use crate::codecs::*;
use crate::config::Listener;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::query_router::{QueryRouter, Scope};
use bytes::{Bytes, BytesMut};
use futures::sync::mpsc;
use log::*;
use parking_lot::Mutex;
use socket2::{Domain, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::io::{Error as IoError, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use stream_cancel::{StreamExt, Tripwire};
use tokio::await;
use tokio::net::{TcpListener, UdpSocket};
use tokio::prelude::*;
use tokio::reactor::Handle;
use tokio_tls::TlsAcceptor;

/// Default queue size for concurrent processing.
const CONCURRENT_QUEUE_SIZE: usize = 1024;
/// Initial buffer size for answers to cover minimal answers.
const INITIAL_BUF_SIZE: usize = 256;
/// Default read buffer capacity.
const DEFAULT_BUF_CAPACITY: usize = 64 * 1024;

/// Maps a queue of questablished connections per client address.
/// A connection is represented by an atomic boolean that represents an open connection.
type EstablishedConnections =
    Mutex<HashMap<IpAddr, VecDeque<(u16, mpsc::Sender<(Bytes, SocketAddr)>)>>>;

/// Server provides an interface to bound to sockets and serve client DNS requests.
pub struct Server {
    context: Arc<Context>,
    connections: Arc<EstablishedConnections>,
}

impl Server {
    pub fn new(context: Arc<Context>) -> Self {
        Self {
            connections: Arc::new(EstablishedConnections::default()),
            context,
        }
    }

    /// Process clients from a listener.
    pub async fn listener_accept(
        context: Arc<Context>,
        router: Arc<QueryRouter>,
        connections: Arc<EstablishedConnections>,
        listener: TcpListener,
        tls_acceptor: Option<tokio_tls::TlsAcceptor>,
        local_endpoint: Arc<Listener>,
        cancel: Tripwire,
    ) {
        let mut incoming = listener.incoming().take_until(cancel.clone());
        while let Some(item) = await!(incoming.next()) {
            // Check if the next client can be accepted
            let stream = match item {
                Ok(stream) => stream,
                Err(e) => {
                    warn!("can't accept stream client, err {:?}", e);
                    continue;
                }
            };

            let peer_addr = stream.peer_addr().expect("tcp peer has address");
            trace!("stream client {} connected", peer_addr);

            // Perform the optional TLS handshake
            let stream = match tls_acceptor {
                Some(ref tls_acceptor) => match await!(tls_acceptor.clone().accept(stream)) {
                    Ok(stream) => FramedStream::from(stream),
                    Err(e) => {
                        warn!("TLS handshake failed, err {:?}", e);
                        continue;
                    }
                },
                None => FramedStream::from(stream),
            };

            Self::stream_start_client(
                &context,
                router.clone(),
                connections.clone(),
                stream,
                peer_addr,
                local_endpoint.clone(),
                cancel.clone(),
            );
        }
    }

    /// Process stream sequentially (message by message).
    async fn stream_process_sequential(
        router: Arc<QueryRouter>,
        stream: FramedStream,
        local_endpoint: Arc<Listener>,
        cancel: Tripwire,
    ) {
        let mut buf = BytesMut::with_capacity(DEFAULT_BUF_CAPACITY);
        let local_addr = stream.local_addr().expect("bound stream");
        let (mut sink, stream) = stream.split();
        let mut stream = stream.take_until(cancel);
        while let Some(Ok((msg, addr))) = await!(stream.next()) {
            match await!(resolve_message(
                &router,
                msg.into(),
                addr,
                buf,
                Protocol::Udp,
                local_addr,
                &local_endpoint,
            )) {
                Ok((msg, from)) => {
                    buf = msg;
                    // Send the response back
                    match await!(sink.send((buf.take().freeze(), from))) {
                        Ok(_sink) => {
                            sink = _sink;
                        }
                        Err(e) => {
                            warn!("failed to send an answer back: {}", e);
                            break;
                        }
                    }
                    // Try to reclaim unused memory from the buffer
                    if buf.capacity() < INITIAL_BUF_SIZE {
                        buf.reserve(DEFAULT_BUF_CAPACITY);
                    }
                }
                Err(e) => {
                    warn!("failed to generate an answer: {}", e);
                    buf = BytesMut::with_capacity(DEFAULT_BUF_CAPACITY);
                }
            }
        }
    }

    /// Process stream concuurrently (each message is resolved in parallel).
    async fn stream_process_concurrent(
        router: Arc<QueryRouter>,
        stream: FramedStream,
        sender: mpsc::Sender<(Bytes, SocketAddr)>,
        receiver: mpsc::Receiver<(Bytes, SocketAddr)>,
        local_endpoint: Arc<Listener>,
        cancel: Tripwire,
    ) {
        let protocol = stream.protocol();
        let local_addr = stream.local_addr().expect("bound stream");
        let (sink, stream) = stream.split();

        // Demultiplex responses back to the TCP stream
        tokio::spawn(
            receiver
                .map_err(move |_| IoError::new(ErrorKind::BrokenPipe, "broken pipe"))
                .forward(sink)
                .then(move |res| {
                    match res {
                        // Close the socket as soon as possible
                        Ok((_, mut sink)) => {
                            drop(sink.close());
                        }
                        Err(e) => {
                            trace!("stream sink error: {:?}", e);
                        }
                    }
                    Ok::<_, ()>(())
                }),
        );

        // Process incoming messages
        let mut stream = stream.take_until(cancel);
        while let Some(item) = await!(stream.next()) {
            match item {
                Ok((msg, peer_addr)) => {
                    // Process message asynchronously
                    let router = router.clone();
                    let sender = sender.clone();
                    let local_endpoint = local_endpoint.clone();
                    tokio::spawn_async(
                        async move {
                            let buf = BytesMut::with_capacity(INITIAL_BUF_SIZE);
                            match await!(resolve_message(
                                &router,
                                msg.into(),
                                peer_addr,
                                buf,
                                protocol,
                                local_addr,
                                &local_endpoint,
                            )) {
                                Ok((response, peer_addr)) => {
                                    match await!(sender.send((response.into(), peer_addr))) {
                                        Ok(_) => {}
                                        Err(e) => {
                                            info!("stream failed to send response: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    info!("stream failed to generate answer: {}", e);
                                }
                            };
                        },
                    )
                }
                Err(e) => {
                    debug!("stream error: {:?}", e);
                    return;
                }
            };
        }
    }

    /// Process an accepted stream from listener.
    fn stream_start_client(
        context: &Arc<Context>,
        router: Arc<QueryRouter>,
        connections: Arc<EstablishedConnections>,
        stream: FramedStream,
        peer_addr: SocketAddr,
        local_endpoint: Arc<Listener>,
        cancel: Tripwire,
    ) {
        // Reuse TCP slots for each client identified by an IP address
        // This is governed by the maximum TCP client count from the configuration.
        // Each client gets a TCP slot allowance calculated as a portion of total TCP client count.
        // If the TCP slot allowance for client is reached, the client's oldest open connection is recycled.
        let (tx, rx) = {
            let mut connections = connections.lock();

            // If the TCP client count is at maximum capacity, close an arbitrary client
            if connections.len() >= context.config.max_tcp_clients {
                // Full table must have at least one key
                let key = *connections.keys().next().unwrap();
                debug!("stream client {}: forcing {} to close", peer_addr, key);
                if let Some(mut queue) = connections.remove(&key) {
                    while let Some((_, mut stream)) = queue.pop_front() {
                        drop(stream.close());
                    }
                }
            }

            let max_per_client = context.config.max_tcp_clients / (connections.len() + 1);
            let queue = connections.entry(peer_addr.ip()).or_default();

            // Close connections exceeding the allowed count
            while queue.len() >= max_per_client {
                if let Some((_, mut stream)) = queue.pop_front() {
                    debug!("stream client {}: closing previous connection", peer_addr);
                    drop(stream.close());
                }
            }

            // Register new connection (port => message demultiplexer)
            let (tx, rx) = mpsc::channel(1);
            queue.push_back((peer_addr.port(), tx.clone()));
            (tx, rx)
        };

        tokio::spawn_async(
            async move {
                trace!("stream client {} processing", peer_addr);
                await!(Self::stream_process_concurrent(
                    router, stream, tx, rx, local_endpoint, cancel,
                ));

                // Client disconnected, remove the associated connection and close the
                // inner queue to prevent sending responses back from messages in flight
                let mut connections_guard = connections.lock();
                if let Some(queue) = connections_guard.get_mut(&peer_addr.ip()) {
                    for index in 0..queue.len() {
                        let port = queue[index].0;
                        if peer_addr.port() == port {
                            debug!("clearing port {} from queue {}", port, peer_addr.ip());
                            drop(queue.remove(index));
                            break;
                        }
                    }

                    if queue.is_empty() {
                        debug!("clearing queue for {}", peer_addr.ip());
                        connections_guard.remove(&peer_addr.ip());
                    }
                }
            },
        );;
    }

    /// Spawn listeners and stream processors from the configuration.
    pub fn spawn(&self, query_router: Arc<QueryRouter>, cancel: Tripwire) -> Result<()> {
        for (name, local_endpoint) in self.context.config.listen.iter() {
            let addr = match local_endpoint.address {
                Some(x) => x,
                None => continue,
            };

            self.spawn_listener(addr, query_router.clone(), local_endpoint.clone(), cancel.clone())
            .map_err(|e| Error::from(format!("failed to listen on {}: {}", addr, e)))?;

            info!("listener '{}' bound to {}", name, addr);
        }

        Ok(())
    }

    /// Spawn DNS listener and stream processors for given address on UDP and TCP.
    pub fn spawn_listener(
        &self,
        addr: SocketAddr,
        router: Arc<QueryRouter>,
        local_endpoint: Arc<Listener>,
        cancel: Tripwire,
    ) -> Result<()> {
        // Spawn TLS listener and stream processors for given address.
        if let Some(ref tls) = local_endpoint.tls {
            let acceptor = TlsAcceptor::from(tls.clone());
            let socket = TcpListener::bind(&addr)?;
            let connections = self.connections.clone();
            tokio::spawn_async(Self::listener_accept(
                self.context.clone(),
                router.clone(),
                connections,
                socket,
                Some(acceptor),
                local_endpoint,
                cancel.clone(),
            ));

            return Ok(());
        }

        // Spawn a single concurrent handler with higher overhead, and the rest of fast-lane handlers.
        // This serves two purposes:
        //  * The concurrent handler can process many concurrent requests, but requires a channel
        //    to serialize transmission back to the UDP socket.
        //  * The non-concurrent handler can process a single request at a time, but can clear more
        //    requests per second during heavy load.
        let socket = create_udp_socket(addr)?;
        let stream = FramedStream::from(udp_socket_from(socket.try_clone()?)?);
        let (tx, rx) = mpsc::channel(CONCURRENT_QUEUE_SIZE);
        tokio::spawn_async(Self::stream_process_concurrent(
            router.clone(),
            stream,
            tx,
            rx,
            local_endpoint.clone(),
            cancel.clone(),
        ));

        let stream = FramedStream::from(udp_socket_from(socket)?);
        tokio::spawn_async(Self::stream_process_sequential(
            router.clone(),
            stream,
            local_endpoint.clone(),
            cancel.clone(),
        ));

        // Spawn TCP acceptors
        let socket = TcpListener::bind(&addr)?;
        let connections = self.connections.clone();
        tokio::spawn_async(Self::listener_accept(
            self.context.clone(),
            router.clone(),
            connections,
            socket,
            None,
            local_endpoint,
            cancel.clone(),
        ));

        Ok(())
    }
}

async fn resolve_message<'a>(
    router: &'a Arc<QueryRouter>,
    msg: Bytes,
    from: SocketAddr,
    response_buf: BytesMut,
    protocol: Protocol,
    local_address: SocketAddr,
    local_endpoint: &'a Arc<Listener>,
) -> Result<(BytesMut, SocketAddr)> {
    // Create a new request scope
    let result = match Scope::new(msg, from) {
        Ok(mut scope) => {
            scope.set_protocol(protocol);
            scope.set_local_addr(local_address, local_endpoint.internal);
            await!(router.resolve(scope, response_buf))
        }
        Err(e) => Err(e),
    };
    // Generate a response
    match result {
        Ok(answer) => Ok((answer, from)),
        Err(e) => Err(e),
    }
}

fn udp_socket_from(socket: Socket) -> Result<UdpSocket> {
    match UdpSocket::from_std(socket.into_udp_socket(), &Handle::default()) {
        Ok(socket) => Ok(socket),
        Err(e) => Err(e.into()),
    }
}

fn create_udp_socket(addr: SocketAddr) -> Result<Socket> {
    let socket = {
        let domain = if addr.is_ipv4() {
            Domain::ipv4()
        } else {
            Domain::ipv6()
        };
        Socket::new(domain, Type::dgram(), None)?
    };
    socket.bind(&addr.into())?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    Ok(socket)
}
