use crate::cache::CacheKey;
use crate::codecs::*;
use crate::config::Config;
use crate::query_router::Scope;
use domain_core::bits::*;
use futures::future::Either;
use futures::stream::Stream;
use futures::sync::{mpsc, oneshot};
use log::*;
use parking_lot::RwLock;
use socket2::{Domain, Socket, Type};
use std::collections::HashMap;
use std::fmt::Write;
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::slice::Iter;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{tcp, TcpStream, UdpSocket};
use tokio::prelude::*;
use tokio::reactor::Handle;

/// Default connection concurrency (number of outstanding requests for single connection)
const DEFAULT_CONNECTION_CONCURRENCY: usize = 1000;
/// Default timeout for message exchange
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(2500);
/// Default keepalive interval for idle connections
const DEFAULT_KEEPALIVE: Duration = Duration::from_millis(10_000);

/// Origin trait provides and interface to return a selection addresses for conductor.
/// The implementations of the trait define the order and size of the slice
/// for each request.
pub trait Origin: Send + Sync {
    /// Returns a selection of addresses for next request.
    fn get(&self) -> &[SocketAddr];

    /// Returns a selection of addresses for given scope.
    fn get_scoped(&self, _scope: &Scope) -> &[SocketAddr] {
        self.get()
    }

    /// Convenience function to return an iterator over addresses.
    fn iter(&self) -> Iter<SocketAddr> {
        self.get().iter()
    }
}

/// Future result of the [`Exchanger`].
type ExchangeFuture = Box<Future<Item = (), Error = IoError> + Send>;

/// Exchanger trait provides an interface for performing message exchanges.
trait Exchanger: Send + Sync {
    fn exchange(&self, scope: Scope, query: Message, origin: Arc<Origin>) -> ExchangeFuture;
}

/// Structure for conductor bookkeeping, it tracks pending queries and open connections.
#[derive(Clone, Default)]
struct Timetable {
    pending: Arc<PendingQueries>,
    connections: Arc<EstablishedConnections>,
}

impl Timetable {
    /// Returns an open connection for an address from the given list (if exists).
    fn find_open_connection(&self, addresses: &[SocketAddr]) -> Option<ConnectionSender> {
        let connections = self.connections.read();
        for addr in addresses {
            if let Some(sink) = connections.get(addr) {
                return Some(sink.clone());
            }
        }

        None
    }

    /// Add an open connection to the timetable.
    fn add_open_connection(&self, address: SocketAddr, sink: ConnectionSender) {
        self.connections.write().insert(address, sink);
    }

    /// Removes an open connection for given address from the timetable.
    fn remove_open_connection(&self, address: &SocketAddr) -> Option<ConnectionSender> {
        self.connections.write().remove(address)
    }
}

/// Structure tracks pending queries represented by [`CacheKey`] to a queue of waiting futures.
/// The primary purpose is coalescing of outbound queries over the same circuit.
#[derive(Default)]
struct PendingQueries {
    max_clients_waiting: usize,
    inner: RwLock<HashMap<CacheKey, Vec<ResponseSender>>>,
}

impl PendingQueries {
    /// Create a map of pending queries with limited number of clients waiting for a query.
    pub fn new(max_clients_waiting: usize) -> Self {
        let mut item = Self::default();
        item.max_clients_waiting = max_clients_waiting;
        item
    }

    /// Register a query identified by `key` as pending, and add `sink` to the queue of waiting futures.
    pub fn start(&self, key: &CacheKey, sink: ResponseSender) -> bool {
        let mut locked = self.inner.write();
        match locked.get_mut(&key) {
            Some(v) => {
                // If the queue is longer than the maximum of clients waiting, recycle an oldest waiting client
                // The oldest waiting client is at the position 1 (the client executing the query is on position 0)
                if v.len() >= self.max_clients_waiting {
                    v.remove(1);
                }
                v.push(sink);
                false
            }
            None => {
                locked.insert(key.clone(), vec![sink]);
                true
            }
        }
    }

    /// Send the message to the queue of futures waiting for completion, and clear the message from the wait list.
    pub fn finish(&self, resp: &Message, peer_addr: &SocketAddr) -> usize {
        let key = CacheKey::from(resp);
        let mut locked = self.inner.write();
        match locked.remove(&key) {
            Some(sinks) => {
                let len = sinks.len();
                for sink in sinks {
                    drop(sink.send((resp.clone(), *peer_addr)));
                }
                len
            }
            None => {
                info!("unexpected response for '{}'", key);
                0
            }
        }
    }

    /// Clear a pending query that could not be resolved into a response.
    pub fn clear(&self, key: &CacheKey) -> bool {
        let mut locked = self.inner.write();
        locked.remove(&key).is_some()
    }
}

/// MPSC sink to an established connection.
type ResponseSender = oneshot::Sender<(Message, SocketAddr)>;
type ConnectionSender = mpsc::Sender<(Message, ResponseSender)>;

/// Maps addresses of established connections to their message queues (sinks).
type EstablishedConnections = RwLock<HashMap<SocketAddr, ConnectionSender>>;

/// The conductor schedules outgoing queries identified by message, and an origin.
/// It doesn't implement any specific outgoing connection protocol, and is used to provide
/// basic facilities for specialized conductor implementations.
#[derive(Clone)]
pub struct Conductor {
    timetable: Timetable,
    exchanger: Arc<Exchanger>,
}

impl Conductor {
    /// Create a new constructor instance with default configuration values.
    pub fn new() -> Arc<Self> {
        Arc::new(Builder::default().build())
    }

    /// Resolve a query with given origin, and wait for response.
    pub fn resolve(
        &self,
        scope: Scope,
        query: Message,
        origin: Arc<Origin>,
    ) -> impl Future<Item = (Message, SocketAddr), Error = IoError> {
        let varz = scope.context.varz.clone();

        // Create a waitable future for the query result
        let (tx, rx) = oneshot::channel();
        let wait_response = rx
            .map_err(|_| IoError::new(ErrorKind::UnexpectedEof, "cannot receive a query response"))
            .into_future();

        // If the query is already being solved, register a waitable future
        let key = CacheKey::from(&query);
        let pending = self.timetable.pending.clone();

        if self.timetable.pending.start(&key, tx) {
            debug!("started new query '{}'", key);
            let start_timer = varz.upstream_rtt.start_timer();
            Either::A(
                self.exchanger
                    .exchange(scope, query, origin)
                    .and_then(|_| wait_response)
                    // Clear the pending query on exchange errors
                    .then(move |res| {
                        drop(start_timer);
                        match res {
                            Ok((msg, from)) => {
                                varz.upstream_response_sizes.observe(msg.len() as f64);
                                varz.upstream_received.inc();
                                Ok((msg, from))
                            },
                            Err(e) => {
                                varz.upstream_timeout.inc();
                                pending.clear(&key);
                                Err(e)
                            }
                        }
                    }),
            )
        } else {
            debug!("enqueued query '{}'", key);
            Either::B(wait_response)
        }
    }

    pub fn process_list(&self, f: &mut String) {
        let pending_guard = self.timetable.pending.inner.write();
        for (key, ticket_list) in &*pending_guard {
            writeln!(f, "{}\t{} waiting", key, ticket_list.len()).unwrap();
        }
    }
}

/// Exchanger that supports TCP for message exchanges.
/// If the configuration enables it, it reuses connections.
#[derive(Clone)]
struct TcpExchanger {
    timetable: Timetable,
    connection_reuse: bool,
    connection_concurrency: usize,
}

impl Exchanger for TcpExchanger {
    fn exchange(&self, scope: Scope, query: Message, origin: Arc<Origin>) -> ExchangeFuture {
        let selection = origin.get_scoped(&scope);

        // Clone inner variables because Futures 0.1 only support borrows with 'static
        let exchanger = self.clone();
        let query_clone = query.clone();
        let varz = scope.context.varz.clone();
        let try_selection = stream::iter_ok::<_, IoError>(selection.to_vec())
            .and_then(move |addr| {
                varz.upstream_sent.inc();
                // Attempt to do a message exchange
                exchange_with_tcp(&addr, query_clone.clone()).then(move |res| match res {
                    Ok((message, stream)) => Ok(Some((message, stream))),
                    Err(e) => {
                        info!("error while talking to {}: {}", addr, e);
                        Ok(None)
                    }
                })
            })
            // Continue iterating if the query didn't resolve to answer
            .skip_while(move |res| future::ok(res.is_none()))
            // Terminate stream after first successful answer
            .take(1)
            // Finish the in-flight query
            .fold(0, move |acc, res| {
                if let Some((message, mut stream)) = res {
                    let peer_addr = stream
                        .get_ref()
                        .peer_addr()
                        .expect("tcp connection must have a peer address");
                    // Save connection if connection reuse is enabled
                    if exchanger.connection_reuse {
                        // Save connection in pending queue
                        tokio::spawn(keep_open_connection(
                            exchanger.timetable.clone(),
                            stream,
                            exchanger.connection_concurrency,
                        ));
                    // Close connection as early as possible if not
                    } else if let Err(e) = stream.close() {
                        warn!("error when closing connection {:?}", e);
                    }

                    exchanger.timetable.pending.finish(&message, &peer_addr);
                }
                Ok::<_, IoError>(acc + 1)
            })
            // Return an error if no upstream is available
            .and_then(move |num_results| {
                if num_results > 0 {
                    Ok(())
                } else {
                    Err(ErrorKind::NotFound.into())
                }
            });

        // First try to find an open connection that can be reused.
        // If there's no open connection, or it doesn't produce a response
        // within a reasonable time, then continue.
        let num_choices = selection.len();
        match self.timetable.find_open_connection(selection) {
            Some(sink) => {
                let varz = scope.context.varz.clone();
                varz.upstream_sent.inc();

                let pending = self.timetable.pending.clone();
                Box::new(
                    exchange_with_open_connection(sink, query.clone(), num_choices)
                        .and_then(move |(message, peer_addr)| {
                            pending.finish(&message, &peer_addr);
                            varz.upstream_reused.inc();
                            Ok(())
                        })
                        .or_else(move |_| try_selection)
                )
            }
            None => Box::new(try_selection),
        }
    }
}

/// Exchanger that supports UDP for message exchanges.
struct UdpExchanger {
    timetable: Timetable,
}

impl Exchanger for UdpExchanger {
    fn exchange(&self, scope: Scope, query: Message, origin: Arc<Origin>) -> ExchangeFuture {
        let pending = self.timetable.pending.clone();
        let selection = origin.get_scoped(&scope);
        let varz = scope.context.varz.clone();
        Box::new(
            // Iterate through all addresses in selection
            stream::iter_ok::<_, IoError>(selection.to_vec())
                .and_then(move |addr| {
                    // Attempt to do a message exchange
                    varz.upstream_sent.inc();
                    // TODO: implement the variant with reusing a pool of bound sockets
                    exchange_with_udp(addr, query.clone()).then(move |res| match res {
                        Ok((message, peer_addr)) => Ok(Some((message, peer_addr))),
                        Err(e) => {
                            info!("error while talking to {}: {}", addr, e);
                            Ok(None)
                        }
                    })
                })
                // Continue iterating if the query didn't resolve to answer
                .skip_while(move |res| future::ok(res.is_none()))
                // Terminate stream after first successful answer
                .take(1)
                // Finish the in-flight query
                .fold(0, move |acc, res| {
                    if let Some((message, peer_addr)) = res {
                        pending.finish(&message, &peer_addr);
                    }
                    Ok::<_, IoError>(acc + 1)
                })
                // Return an error if no upstream is available
                .and_then(move |num_results| {
                    if num_results > 0 {
                        Ok(())
                    } else {
                        Err(ErrorKind::NotFound.into())
                    }
                }),
        )
    }
}

/// Dummy exchanger that mirrors the query back
struct NoopExchanger {
    timetable: Timetable,
}

impl Exchanger for NoopExchanger {
    fn exchange(&self, scope: Scope, query: Message, origin: Arc<Origin>) -> ExchangeFuture {
        let selection = origin.get_scoped(&scope);
        if let Some(addr) = selection.first() {
            self.timetable.pending.finish(&query, addr);
            Box::new(future::ok(()))
        } else {
            Box::new(future::err(ErrorKind::NotFound.into()))
        }
    }
}

/// Builder interface for creating a Conductor instance
pub struct Builder {
    enable_tcp: bool,
    enable_udp: bool,
    connection_reuse: bool,
    connection_concurrency: usize,
    max_active_queries: usize,
    max_clients_waiting_for_query: usize,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            enable_tcp: true,
            enable_udp: true,
            connection_reuse: true,
            connection_concurrency: DEFAULT_CONNECTION_CONCURRENCY,
            max_active_queries: 0,
            max_clients_waiting_for_query: 0,
        }
    }
}

impl Builder {
    /// Build conductor with support for UDP.
    #[allow(dead_code)]
    pub fn with_udp(mut self, value: bool) -> Self {
        self.enable_udp = value;
        self
    }

    /// Build conductor with support for TCP.
    #[allow(dead_code)]
    pub fn with_tcp(mut self, value: bool) -> Self {
        self.enable_tcp = value;
        if !value {
            self.connection_reuse = false;
        }
        self
    }

    /// Build conductor with support for reusing TCP connections.
    /// This implies support for TCP.
    #[allow(dead_code)]
    pub fn with_connection_reuse(mut self, value: bool) -> Self {
        self.connection_reuse = value;
        if value {
            self.enable_tcp = value;
        }
        self
    }

    /// Use defined queue size (default is [`DEFAULT_CONNECTION_CONCURRENCY`]).
    #[allow(dead_code)]
    pub fn with_connection_concurrency(mut self, value: usize) -> Self {
        self.connection_concurrency = value;
        self
    }

    /// Set maximum number of inflight queries (default is 0 = unlimited).
    pub fn with_max_active_queries(mut self, value: usize) -> Self {
        self.max_active_queries = value;
        self
    }

    /// Set maximum number of clients waiting for a response to the same query (default is 0 = unlimited).
    pub fn with_max_clients_waiting_for_query(mut self, value: usize) -> Self {
        self.max_clients_waiting_for_query = value;
        self
    }

    /// Convert the Builder into the Recursor with defined configuration.
    pub fn build(self) -> Conductor {
        let timetable = Timetable {
            pending: Arc::new(PendingQueries::new(self.max_clients_waiting_for_query)),
            connections: Arc::new(EstablishedConnections::default()),
        };

        let exchanger: Arc<Exchanger> = if self.enable_tcp {
            Arc::new(TcpExchanger {
                timetable: timetable.clone(),
                connection_reuse: self.connection_reuse,
                connection_concurrency: self.connection_concurrency,
            })
        } else if self.enable_udp {
            Arc::new(UdpExchanger {
                timetable: timetable.clone(),
            })
        } else {
            Arc::new(NoopExchanger {
                timetable: timetable.clone(),
            })
        };

        Conductor {
            timetable,
            exchanger,
        }
    }
}

/// Build from configuration pattern
impl From<&Arc<Config>> for Conductor {
    fn from(config: &Arc<Config>) -> Self {
        Builder::default()
            .with_max_active_queries(config.max_active_queries)
            .with_max_clients_waiting_for_query(config.max_clients_waiting_for_query)
            .build()
    }
}

/// Returns a future that manages an open connection in the background.
/// It registers the open connection in the provided structure, and keeps the
/// connection open for [`DEFAULT_KEEPALIVE`] duration. After that it closes the
/// connection, and unregisters it from the structure.
///
/// The `concurrency` limits the number of in-flight queries for the connection.
fn keep_open_connection(
    timetable: Timetable,
    stream: FramedStream,
    concurrency: usize,
) -> impl Future<Item = (), Error = ()> {
    // Save connection in pending queue
    let peer_addr = stream
        .get_ref()
        .peer_addr()
        .expect("tcp connection must have a peer address");

    let (sender, receiver) = mpsc::channel(concurrency);
    timetable.add_open_connection(peer_addr, sender);

    // Create a token bucket with channel to limit concurrency of the connection
    // In order to start new queries, there must be a token in the channel.
    // When a query is completed, it returns tokens into the channel.
    let (token_sender, token_reader) = mpsc::channel(concurrency);
    let replenish_tokens = token_sender
        .clone()
        .send_all(stream::repeat::<(), mpsc::SendError<_>>(()).take(concurrency as u64))
        .then(move |_| Ok(()));

    // Spawn background message writer
    let pending = Arc::new(PendingQueries::default());
    let (sink, stream) = stream.split();
    let sender_future = {
        let pending = pending.clone();
        receiver
            .zip(token_reader)
            .map(move |((msg, sink), _)| {
                let key = CacheKey::from(&msg);
                debug!("open connection, forwarding message '{}'", key);
                pending.start(&key, sink);
                msg.as_bytes().clone()
            })
            .map_err(move |_| ErrorKind::BrokenPipe.into())
            .fold(sink, move |sink, msg| sink.send(msg))
            .then(move |_: Result<_, IoError>| Ok::<_, ()>(()))
    };

    // Spawn background message reader
    let receiver_future = {
        stream
            .timeout(DEFAULT_KEEPALIVE / 2)
            .map_err(move |_e| ErrorKind::TimedOut.into())
            .for_each(move |resp| {
                // Parse response and attempt to close pending queries
                let tokens = if let Ok(msg) = Message::from_bytes(resp.into()) {
                    debug!(
                        "open connection, received response '{}'",
                        CacheKey::from(&msg)
                    );

                    pending.finish(&msg, &peer_addr)
                } else {
                    debug!("open connection, received invalid response");
                    0
                };

                // Return tokens to token bucket when closing in-flight queries
                token_sender
                    .clone()
                    .send_all(stream::repeat::<_, mpsc::SendError<_>>(()).take(tokens as u64))
                    .then(move |_| Ok::<_, IoError>(()))
            })
            .then(move |_| {
                info!("open connection, closing for {}", peer_addr);
                timetable.remove_open_connection(&peer_addr);
                Ok(())
            })
    };

    info!("open connection, created for {}", peer_addr);
    replenish_tokens
        .join(sender_future)
        .join(receiver_future)
        .map(|_| ())
}

/// Returns a future that tries to perform a message exchange over an established connection.
fn exchange_with_open_connection(
    sink: ConnectionSender,
    query: Message,
    num_choices: usize,
) -> impl Future<Item = (Message, SocketAddr), Error = IoError> {
    let (tx, rx) = oneshot::channel();
    sink.send((query, tx))
        .map_err(move |e| {
            info!("failed to send over existing connection: {}", e);
            IoError::new(
                ErrorKind::BrokenPipe,
                "cannot send to background connection",
            )
        })
        .and_then(move |_| {
            // If the conductor has more address choices, wait for shorter time
            // to allow retry over a new connection to another address.
            let timeout = match num_choices {
                1 => DEFAULT_TIMEOUT,
                _ => DEFAULT_TIMEOUT / 2,
            };
            rx.into_future().timeout(timeout).map_err(move |e| {
                warn!(
                    "waited for {:#?}, but did not receive response: {}",
                    timeout, e
                );
                IoError::new(ErrorKind::TimedOut, "timed out whilst waiting for response")
            })
        })
}

/// Returns a future that creates a TCP connection.
/// It attempts to reuse sockets in CLOSE_WAIT state.
fn create_tcp_connection(addr: &SocketAddr) -> tcp::ConnectFuture {
    let sock = {
        let domain = if addr.is_ipv4() {
            Domain::ipv4()
        } else {
            Domain::ipv6()
        };
        Socket::new(domain, Type::stream(), None)
    };

    match sock {
        Ok(sock) => {
            // Attempt to reuse sockets in CLOSE_WAIT state
            drop(sock.set_reuse_address(true));
            // Convert to connected TcpStream
            TcpStream::connect_std(sock.into_tcp_stream(), addr, &Handle::default())
        }
        Err(_) => {
            // Fall back to default connect
            TcpStream::connect(addr)
        }
    }
}

/// Returns a future that tries to perform a message exchange over a new TCP connection.
fn exchange_with_tcp(
    addr: &SocketAddr,
    query: Message,
) -> impl Future<Item = (Message, FramedStream), Error = IoError> {
    create_tcp_connection(addr)
        .timeout(DEFAULT_TIMEOUT)
        .map_err(move |_e| IoError::new(ErrorKind::TimedOut, "timed out whilst connecting"))
        .map(tcp_framed_transport)
        .and_then(move |stream| {
            stream
                .send(query.as_slice().into())
                .and_then(move |stream| {
                    stream
                        .into_future()
                        .timeout(DEFAULT_TIMEOUT)
                        .map_err(move |_e| {
                            IoError::new(ErrorKind::UnexpectedEof, "no response within timeout")
                        })
                })
        })
        .and_then(move |(response, stream)| match response {
            Some(response) => match Message::from_bytes(response.into()) {
                Ok(message) => Ok((message, stream)),
                Err(_e) => Err(IoError::new(ErrorKind::InvalidData, "invalid response")),
            },
            None => Err(IoError::new(
                ErrorKind::UnexpectedEof,
                "connection closed whilst waiting for response",
            )),
        })
}

/// Returns a future that tries to perform a message exchange over UDP.
fn exchange_with_udp(
    addr: SocketAddr,
    query: Message,
) -> impl Future<Item = (Message, SocketAddr), Error = IoError> {
    let socket = UdpSocket::bind(&"0.0.0.0:0".parse().unwrap()).expect("bound socket");
    udp_framed_transport(socket)
        .send((query.as_bytes().clone(), addr))
        .and_then(move |stream| {
            stream
                // Filter only messages from requested target
                .filter_map(move |(response, from)| {
                    if from == addr {
                        Some(response)
                    } else {
                        info!("skipping unsolicited response from {}", from);
                        None
                    }
                })
                .into_future()
                .timeout(DEFAULT_TIMEOUT)
                .map_err(move |_e| {
                    IoError::new(ErrorKind::TimedOut, "timed out whilst waiting for response")
                })
                // Parse the response into message and unblock waiting futures
                .and_then(move |(response, _stream)| match response {
                    Some(response) => match Message::from_bytes(response.into()) {
                        Ok(message) => Ok((message, addr)),
                        Err(_e) => Err(IoError::new(
                            ErrorKind::InvalidData,
                            "received invalid message",
                        )),
                    },
                    None => Err(IoError::new(
                        ErrorKind::UnexpectedEof,
                        "socket closed whilst waiting for a response",
                    )),
                })
        })
}

#[cfg(test)]
mod test {
    use super::{Builder, Conductor};
    use crate::query_router::Scope;
    use crate::test_utils::{test_context, test_echo_server, TestOrigin, DOMAINS};
    use domain_core::bits::*;
    use domain_core::iana::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use test::{black_box, Bencher};
    use tokio::prelude::*;
    use tokio::runtime::current_thread::Runtime;

    const MAX_TEST_DURATION: Duration = Duration::from_millis(60_000);

    fn bench_batched(b: &mut Bencher, conductor: Arc<Conductor>) {
        let context = test_context();
        let (echo_server, addr) = test_echo_server(MAX_TEST_DURATION);
        let peer_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        let origin: Arc<TestOrigin> = Arc::new(addr.into());

        // Sample a few unique messages to test connection reuse
        let messages = DOMAINS
            .iter()
            .take(10)
            .map(|dname| {
                let mut mb = MessageBuilder::with_capacity(512);
                mb.push(Question::new(dname, Rtype::Any, Class::Ch))
                    .expect("pushed question");
                mb.freeze()
            })
            .collect::<Vec<Message>>();

        // Create a test set
        let scope = Scope::new(context, messages[0].as_bytes().clone(), peer_addr).unwrap();
        let test_set = (0..1000).map(move |i| {
            let msg = messages[i % messages.len()].clone();
            conductor
                .resolve(scope.clone(), msg, origin.clone())
                .then(move |res| {
                    // Print errors when in --nocapture
                    if let Err(e) = res {
                        eprintln!("resolve error: {:?}", e);
                    }
                    // Compiler can't infer the type for E here
                    Ok::<_, ()>(())
                })
        });

        // Run mock responder
        let mut runtime = Runtime::new().expect("runtime");
        runtime.spawn(echo_server);

        let mut bench_closure = || {
            let fut = future::join_all(test_set.clone());
            black_box(runtime.block_on(fut).expect("spawn and wait"));
        };

        // Warmup and test
        bench_closure();
        b.iter(bench_closure);
    }

    #[bench]
    fn batched_1k(b: &mut Bencher) {
        let conductor = Builder::default().build();
        bench_batched(b, Arc::new(conductor))
    }

    #[bench]
    fn batched_udp_1k(b: &mut Bencher) {
        let conductor = Builder::default().with_tcp(false).build();
        bench_batched(b, Arc::new(conductor))
    }

    #[bench]
    fn batched_noreuse_1k(b: &mut Bencher) {
        let conductor = Builder::default().with_connection_reuse(false).build();
        bench_batched(b, Arc::new(conductor))
    }

    #[bench]
    fn batched_noop_1k(b: &mut Bencher) {
        let conductor = Builder::default().with_udp(false).with_tcp(false).build();
        bench_batched(b, Arc::new(conductor))
    }
}
