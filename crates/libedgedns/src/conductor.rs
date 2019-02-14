use crate::cache::CacheKey;
use crate::codecs::*;
use crate::config::{Config, ServerType};
use crate::query_router::Scope;
use crate::UPSTREAM_TOTAL_TIMEOUT_MS;
use domain_core::bits::*;
use futures::future::Either;
use futures::stream::Stream;
use futures::sync::{mpsc, oneshot};
use log::*;
use parking_lot::RwLock;
use socket2::{Domain, Socket, Type};
use std::cmp;
use std::collections::{HashMap, VecDeque};
use std::fmt::Write;
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::slice::Iter;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{tcp, TcpStream, UdpSocket};
use tokio::prelude::*;
use tokio::reactor::Handle;
use clockpro_cache::*;

/// Default connection concurrency (number of outstanding requests for single connection)
const DEFAULT_CONNECTION_CONCURRENCY: usize = 1000;
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
            // TODO: make ExchangeFuture a type and implement cleanup on Drop
            .timeout(Duration::from_millis(UPSTREAM_TOTAL_TIMEOUT_MS))
            .map_err(|_| {
                IoError::new(
                    ErrorKind::TimedOut,
                    "timed out whilst waiting for upstreams",
                )
            })
            .into_future();

        // If the query is already being solved, register a waitable future
        let key = CacheKey::from(&query);
        let pending = self.timetable.pending.clone();

        // First query creates a queue for other same queries
        let queue_len = self.timetable.pending.start(&key, tx);
        if queue_len == 1 {
            debug!("registered query '{}'", key);
            varz.upstream_inflight_queries.inc();
            let start_timer = varz.upstream_rtt.start_timer();
            Either::A(
                self.exchanger
                    .exchange(scope, query, origin)
                    .and_then(|_| wait_response)
                    // Clear the pending query on exchange errors
                    .then(move |res| {
                        drop(start_timer);
                        varz.upstream_inflight_queries.dec();
                        match res {
                            Ok((msg, from)) => {
                                varz.upstream_response_sizes.observe(msg.len() as f64);
                                varz.upstream_received.inc();
                                Ok((msg, from))
                            }
                            Err(e) => {
                                trace!("error in resolve: {:?}", e);
                                varz.upstream_timeout.inc();
                                pending.clear(&key);
                                Err(e)
                            }
                        }
                    }),
            )
        } else {
            debug!("enqueued query '{}' ({} waiting)", key, queue_len);
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

/// Future result of the [`Exchanger`].
type ExchangeFuture = Box<Future<Item = (), Error = IoError> + Send>;

/// Exchanger trait provides an interface for performing message exchanges.
trait Exchanger: Send + Sync {
    fn exchange(&self, scope: Scope, query: Message, origin: Arc<Origin>) -> ExchangeFuture;
}

/// Structure for conductor bookkeeping, it tracks pending queries and open connections.
#[derive(Clone)]
struct Timetable {
    pending: Arc<PendingQueries>,
    connections: Arc<EstablishedConnections>,
}

impl Timetable {
    /// Returns an open connection for an address from the given list (if exists).
    fn find_open_connection(&self, addresses: &[SocketAddr]) -> Option<ConnectionTracker> {
        let mut connections = self.connections.write();
        for addr in addresses {
            if let Some(c) = connections.get(addr) {
                return Some(c.clone());
            }
        }

        None
    }

    /// Update counters and RTT for an open connection.
    fn update_open_connection(&self, address: &SocketAddr, rtt: Duration) {
        if let Some(ref mut c) = self.connections.write().get_mut(address) {
            c.update(rtt);
        }
    }

    /// Add an open connection to the timetable.
    fn add_open_connection(
        &self,
        address: SocketAddr,
        sink: ConnectionSender,
        expected_rtt: Duration,
    ) -> bool {
        // Check if there's an already open connection
        let mut connections = self.connections.write();
        match connections.get_mut(&address) {
            Some(ref mut c) => {
                c.update(expected_rtt);
                false
            }
            None => {
                // Insert a new connection tracker if not exists
                connections.insert(address, ConnectionTracker::new(sink, expected_rtt))
            }
        }
    }

    /// Removes an open connection for given address from the timetable.
    fn remove_open_connection(&self, address: &SocketAddr) -> Option<ConnectionTracker> {
        self.connections.write().remove(address)
    }
}

/// Structure tracks pending queries represented by [`CacheKey`] to a queue of waiting futures.
/// The primary purpose is coalescing of outbound queries over the same circuit.
#[derive(Default)]
struct PendingQueries {
    max_clients_waiting: usize,
    inner: RwLock<HashMap<CacheKey, VecDeque<ResponseSender>>>,
}

impl PendingQueries {
    /// Create a map of pending queries with limited number of clients waiting for a query.
    pub fn new(max_clients_waiting: usize) -> Self {
        let mut item = Self::default();
        item.max_clients_waiting = max_clients_waiting;
        item
    }

    /// Register a query identified by `key` as pending, and add `sink` to the queue of waiting futures.
    pub fn start(&self, key: &CacheKey, sink: ResponseSender) -> usize {
        let mut locked = self.inner.write();
        match locked.get_mut(&key) {
            Some(v) => {
                // If the queue is longer than the maximum of clients waiting, recycle an oldest waiting client
                // The oldest waiting client is at the position 1 (the client executing the query is on position 0)
                if self.max_clients_waiting > 0 && v.len() >= self.max_clients_waiting {
                    v.pop_front();
                }
                v.push_back(sink);
                v.len()
            }
            None => {
                let mut v = VecDeque::with_capacity(1);
                v.push_back(sink);
                locked.insert(key.clone(), v);
                1
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
type ConnectionReceiver = mpsc::Receiver<(Message, ResponseSender)>;

/// Maps addresses of established connections to their message queues (sinks).
type EstablishedConnections = RwLock<ClockProCache<SocketAddr, ConnectionTracker>>;

/// Established connection tracker.
#[derive(Clone)]
struct ConnectionTracker {
    sender: ConnectionSender,
    messages: u64,
    total_rtt: u64,
}

impl ConnectionTracker {
    fn new(sender: ConnectionSender, rtt: Duration) -> Self {
        Self {
            sender,
            messages: 1,
            total_rtt: Self::round_to_millis(rtt),
        }
    }

    /// Çalculate mean RTT from observed messages.
    fn mean_rtt(&self) -> Duration {
        Duration::from_millis(self.total_rtt / self.messages)
    }

    /// Update connection tracker message count and
    fn update(&mut self, rtt: Duration) {
        self.messages += 1;
        self.total_rtt += Self::round_to_millis(rtt);
    }

    /// Round duration to milliseconds and cap at 30 seconds.
    fn round_to_millis(d: Duration) -> u64 {
        cmp::min(d.as_secs(), 30) * 1000 + u64::from(d.subsec_millis())
    }
}

/// Exchanger that supports TCP for message exchanges.
/// If the configuration enables it, it reuses connections.
#[derive(Clone)]
struct TcpExchanger {
    timetable: Timetable,
    connection_reuse: bool,
    connection_reuse_fallback: bool,
    connection_concurrency: usize,
}

impl Exchanger for TcpExchanger {
    fn exchange(&self, scope: Scope, query: Message, origin: Arc<Origin>) -> ExchangeFuture {
        let selection = origin.get_scoped(&scope);
        let num_choices = selection.len();

        // Clone inner variables because Futures 0.1 only support borrows with 'static
        let exchanger = self.clone();
        let query_clone = query.clone();
        let varz = scope.context.varz.clone();
        let try_selection = stream::iter_ok::<_, IoError>(selection.to_vec())
            .and_then(move |addr| {
                varz.upstream_sent.inc();
                // Attempt to do a message exchange
                let duration = Instant::now();
                exchange_with_tcp(&addr, query_clone.clone())
                .timeout(Duration::from_millis(UPSTREAM_TOTAL_TIMEOUT_MS / num_choices as u64))
                .then(move |res| match res {
                    Ok((message, stream)) => Ok(Some((message, stream, addr, duration.elapsed()))),
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
                if let Some((message, mut stream, peer_addr, elapsed)) = res {
                    // Save connection if connection reuse is enabled
                    if exchanger.connection_reuse {
                        // Save connection in pending queue
                        let (sender, receiver) = mpsc::channel(exchanger.connection_concurrency);
                        if exchanger
                            .timetable
                            .add_open_connection(peer_addr, sender, elapsed)
                        {
                            tokio::spawn(keep_open_connection(
                                exchanger.timetable.clone(),
                                stream,
                                peer_addr,
                                exchanger.connection_concurrency,
                                receiver,
                            ));
                        }
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
        match self.timetable.find_open_connection(selection) {
            Some(sink) => {
                // Update metrics for reused connection attempt
                let varz = scope.context.varz.clone();
                varz.upstream_sent.inc();
                // Try to do message exchange
                let started = Instant::now();
                let timetable = self.timetable.clone();
                let fast_fallback = self.connection_reuse_fallback;
                Box::new(
                    exchange_with_open_connection(sink, query.clone(), fast_fallback)
                        .and_then(move |(message, peer_addr)| {
                            timetable.update_open_connection(&peer_addr, started.elapsed());
                            timetable.pending.finish(&message, &peer_addr);
                            varz.upstream_reused.inc();
                            Ok(())
                        })
                        .or_else(move |e| {
                            debug!("tcp error when reusing connection: {:?}", e);
                            try_selection
                        }),
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
        let num_choices = selection.len();
        let varz = scope.context.varz.clone();
        let query_clone = query.clone();
        Box::new(
            // Iterate through all addresses in selection
            stream::iter_ok::<_, IoError>(selection.to_vec())
                .and_then(move |addr| {
                    // Attempt to do a message exchange
                    varz.upstream_sent.inc();
                    // TODO: implement the variant with reusing a pool of bound sockets
                    exchange_with_udp(addr, query.clone())
                    .timeout(Duration::from_millis(UPSTREAM_TOTAL_TIMEOUT_MS / num_choices as u64))
                    .then(move |res| match res {
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
                        // Retry with TCP on truncation, otherwise finish
                        if message.header().tc() {
                            let pending = pending.clone();
                            return Either::A(
                                exchange_with_tcp(&peer_addr, query_clone.clone()).and_then(
                                    move |(message, _stream)| {
                                        pending.finish(&message, &peer_addr);
                                        future::ok(acc + 1)
                                    },
                                ),
                            );
                        } else {
                            pending.finish(&message, &peer_addr);
                        }
                    }
                    Either::B(future::ok::<_, IoError>(acc + 1))
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
    connection_reuse_fallback: bool,
    connection_concurrency: usize,
    max_active_queries: usize,
    max_clients_waiting_for_query: usize,
    max_keepalive_connections: usize,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            enable_tcp: true,
            enable_udp: true,
            connection_reuse: true,
            connection_reuse_fallback: false,
            connection_concurrency: DEFAULT_CONNECTION_CONCURRENCY,
            max_active_queries: 0,
            max_clients_waiting_for_query: 0,
            max_keepalive_connections: DEFAULT_CONNECTION_CONCURRENCY,
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

    /// Test connection reuse on first message over reused connection.
    /// This fails over quickly when the upstream doesn't appear to support connection reuse,
    /// but it could lower the reuse rate when the upstream RTT is unpredictable (recursive).
    pub fn with_connection_reuse_fallback(mut self, value: bool) -> Self {
        self.connection_reuse_fallback = value;
        self
    }

    /// Use defined queue size (default is [`DEFAULT_CONNECTION_CONCURRENCY`]).
    #[allow(dead_code)]
    pub fn with_connection_concurrency(mut self, value: usize) -> Self {
        self.connection_concurrency = value;
        self
    }

    /// Set maximum number of upstream connections (default is 1000).
    /// When set to 0, it disables connection reuse as no upstream connection could be kept open.
    pub fn with_max_keepalive_connections(mut self, value: usize) -> Self {
        self.max_keepalive_connections = value;
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
            connections: Arc::new(EstablishedConnections::new(ClockProCache::new(self.max_keepalive_connections).expect("connection cache"))),
        };

        let exchanger: Arc<Exchanger> = if self.enable_tcp {
            Arc::new(TcpExchanger {
                timetable: timetable.clone(),
                connection_reuse: self.connection_reuse,
                connection_reuse_fallback: self.connection_reuse_fallback,
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
            .with_max_keepalive_connections(config.max_upstream_connections)
            .with_connection_reuse_fallback(config.server_type == ServerType::Recursive)
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
    peer_addr: SocketAddr,
    concurrency: usize,
    receiver: ConnectionReceiver,
) -> impl Future<Item = (), Error = ()> {
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
                debug!("reused connection, forwarding message '{}'", key);
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
                        "reused connection, received response '{}'",
                        CacheKey::from(&msg)
                    );

                    pending.finish(&msg, &peer_addr)
                } else {
                    debug!("reused connection, received invalid response");
                    0
                };

                // Return tokens to token bucket when closing in-flight queries
                token_sender
                    .clone()
                    .send_all(stream::repeat::<_, mpsc::SendError<_>>(()).take(tokens as u64))
                    .then(move |_| Ok::<_, IoError>(()))
            })
            .then(move |_| {
                info!("reused connection, closing for {}", peer_addr);
                timetable.remove_open_connection(&peer_addr);
                Ok(())
            })
    };

    info!("keepalive connection for {}", peer_addr);
    replenish_tokens
        .join(sender_future)
        .join(receiver_future)
        .map(|_| ())
}

/// Returns a future that tries to perform a message exchange over an established connection.
fn exchange_with_open_connection(
    connection: ConnectionTracker,
    query: Message,
    fast_fallback: bool,
) -> impl Future<Item = (Message, SocketAddr), Error = IoError> {
    let (tx, rx) = oneshot::channel();
    let (rtt, messages, sender) = (
        connection.mean_rtt(),
        connection.messages,
        connection.sender,
    );
    sender
        .send((query, tx))
        .map_err(move |e| {
            info!("failed to send over existing connection: {}", e);
            IoError::new(
                ErrorKind::BrokenPipe,
                "cannot send to background connection",
            )
        })
        .and_then(move |_| {
            // First connection reuse doesn't know whether upstream supports it,
            // so the timeout is chosen more conservatively (double RTT).
            let timeout = if fast_fallback && messages <= 100 {
                // Estimate an upper bound for connection timeout 20% or +100ms of mean RTT
                cmp::min((120 * rtt) / 100, rtt + Duration::from_millis(100))
            } else {
                Duration::from_millis(UPSTREAM_TOTAL_TIMEOUT_MS / 2)
            };
            rx.into_future().timeout(timeout).map_err(move |_| {
                IoError::new(ErrorKind::TimedOut, format!("timed out ({:?})", timeout))
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
        .map(move |stream| {
            // Disable Nagle and convert to framed transport
            drop(stream.set_nodelay(true));
            tcp_framed_transport(stream)
        })
        .and_then(move |stream| {
            stream
                .send(query.as_slice().into())
                .and_then(move |stream| {
                    stream
                        .into_future()
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
    let local_addr = match addr.is_ipv6() {
        true => "[::]:0".parse().unwrap(),
        false => "0.0.0.0:0".parse().unwrap(),
    };
    let socket = UdpSocket::bind(&local_addr).expect("bound socket");
    udp_framed_transport(socket)
        .send((query.as_bytes().clone(), addr))
        .and_then(move |stream| {
            stream
                // Filter only messages from requested target
                .filter_map(move |(response, from)| {
                    if from.ip() == addr.ip() {
                        Some(response)
                    } else {
                        info!(
                            "skipping unsolicited response from {} (expected: {})",
                            from, addr
                        );
                        None
                    }
                })
                .into_future()
                .map_err(move |_| ErrorKind::UnexpectedEof.into())
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
        let conductor = Builder::default().with_max_keepalive_connections(0).build();
        bench_batched(b, Arc::new(conductor))
    }

    #[bench]
    fn batched_noop_1k(b: &mut Bencher) {
        let conductor = Builder::default().with_udp(false).with_tcp(false).build();
        bench_batched(b, Arc::new(conductor))
    }
}
