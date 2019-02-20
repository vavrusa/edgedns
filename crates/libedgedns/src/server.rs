use crate::codecs::*;
use crate::context::Context;
use crate::error::Result;
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
use tokio::codec::BytesCodec;
use tokio::net::{TcpListener, TcpStream, UdpFramed, UdpSocket};
use tokio::prelude::*;
use tokio::reactor::Handle;

/// Initial buffer size for answers to cover minimal answers.
const INITIAL_BUF_SIZE: usize = 256;

/// Enum of used server protocols.
#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    Udp,
    Tcp,
    Tls,
    Https,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Udp
    }
}

/// Server serving DNS requests.
pub struct Server {
    context: Arc<Context>,
    connections: Arc<EstablishedConnections>,
    query_router: Arc<QueryRouter>,
    concurrency_limit: usize,
}

impl Server {
    pub fn new(context: Arc<Context>, concurrency_limit: usize) -> Self {
        Self {
            query_router: Arc::new(QueryRouter::new(context.clone())),
            connections: Arc::new(EstablishedConnections::default()),
            context,
            concurrency_limit,
        }
    }

    pub async fn run_udp(
        router: Arc<QueryRouter>,
        socket: UdpSocket,
        tripwire: Tripwire,
    ) {
        let (mut sink, stream) = UdpFramed::new(socket, BytesCodec::new()).split();
        let mut stream = stream.take_until(tripwire);
        while let Some(Ok((msg, addr))) = await!(stream.next()) {
            match await!(resolve_message(
                &router,
                msg.into(),
                addr,
                Protocol::Udp
            )) {
                Ok(res) => match await!(sink.send(res)) {
                    Ok(res) => {
                        sink = res;
                    }
                    Err(e) => {
                        warn!("failed to send an answer back: {}", e);
                        break;
                    }
                },
                Err(e) => {
                    warn!("failed to generate an answer: {}", e);
                }
            }
        }

        info!("udp server done");
    }

    pub async fn run_udp_concurrent(
        context: Arc<Context>,
        router: Arc<QueryRouter>,
        socket: UdpSocket,
        tripwire: Tripwire,
    ) {
        let (sink, stream) = UdpFramed::new(socket, BytesCodec::new()).split();
        let mut stream = stream.take_until(tripwire);

        // Create a channel for serializing messages from fan-out workers
        // The channel buffer size is set reasonably low to provide a backpressure,
        // so that if the executor is busy resolving queries, it shouldn't queue too many new ones.
        let (sender, receiver) = mpsc::channel(context.config.udp_acceptor_threads);
        tokio::spawn(
            receiver
                .map_err(move |_| ErrorKind::BrokenPipe.into())
                .forward(sink)
                .then(move |res: Result<_>| {
                    if let Err(e) = res {
                        error!("concurrent udp receiver: {:?}", e);
                    }
                    Ok::<_, ()>(())
                }),
        );

        // Receive incoming messages and process asynchronously
        while let Some(Ok((msg, addr))) = await!(stream.next()) {
            let router = router.clone();
            let sender = sender.clone();
            tokio::spawn_async(
                async move {
                    match await!(resolve_message(
                        &router,
                        msg.into(),
                        addr,
                        Protocol::Udp
                    )) {
                        Ok(res) => {
                            drop(await!(sender.send(res)));
                        }
                        Err(e) => {
                            warn!("failed to generate an answer: {}", e);
                        }
                    }
                },
            );
        }

        info!("udp server done");
    }

    /// Process clients from a TCP listener.
    pub async fn run_tcp(
        context: Arc<Context>,
        router: Arc<QueryRouter>,
        connections: Arc<EstablishedConnections>,
        listener: TcpListener,
        tripwire: Tripwire,
    ) {
        let mut incoming = listener.incoming().take_until(tripwire);
        while let Some(item) = await!(incoming.next()) {
            // Check if the next client can be accepted
            let stream = match item {
                Ok(stream) => stream,
                Err(e) => {
                    warn!("can't accept tcp client, err {:?}", e);
                    continue;
                }
            };

            let peer_addr = stream.peer_addr().expect("tcp peer has address");
            trace!("tcp client {} connected", peer_addr);

            // Reuse TCP slots for each client identified by an IP address
            // This is governed by the maximum TCP client count from the configuration.
            // Each client gets a TCP slot allowance calculated as a portion of total TCP client count.
            // If the TCP slot allowance for client is reached, the client's oldest open connection is recycled.
            let (sender, receiver) = {
                let mut connections = connections.lock();

                // If the TCP client count is at maximum capacity, close an arbitrary client
                if connections.len() >= context.config.max_tcp_clients {
                    let key = *connections
                        .keys()
                        .next()
                        .expect("full table must have a key");
                    debug!("tcp client {}: forcing {} to close", peer_addr, key);
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
                        debug!("tcp client {}: closing previous connection", peer_addr);
                        drop(stream.close());
                    }
                }

                // Register new connection (port => message demultiplexer)
                let (sender, receiver) = mpsc::channel(1);
                queue.push_back((peer_addr.port(), sender.clone()));
                (sender, receiver)
            };

            trace!("tcp client {} processing", peer_addr);
            tokio::spawn_async(process_stream(
                router.clone(),
                connections.clone(),
                peer_addr,
                stream,
                sender,
                receiver,
            ));
        }

        info!("tcp server done");
    }

    pub fn spawn(&self, tripwire: Tripwire) -> Result<()> {
        let socket_addr = self.context.config.listen_addr.parse::<SocketAddr>()?;
        let socket = create_udp_socket(socket_addr)?;

        // Start the query router
        let query_router = self.query_router.clone();
        let tripwire_clone = tripwire.clone();
        tokio::spawn_async(
            async move {
                await!(query_router.start(tripwire_clone));
            },
        );

        // Spawn a single concurrent handler with higher overhead, and the rest of fast-lane handlers.
        // This serves two purposes:
        //  * The concurrent handler can process many concurrent requests, but requires a channel
        //    to serialize transmission back to the UDP socket.
        //  * The non-concurrent handler can process a single request at a time, but can clear more
        //    requests per second during heavy load.
        let acceptors = self.context.config.udp_acceptor_threads;
        for i in 0..acceptors {
            let socket = clone_udp_socket(&socket)?;
            let router = self.query_router.clone();
            let tripwire = tripwire.clone();
            if i == acceptors - 1 {
                let context = self.context.clone();
                tokio::spawn_async(Self::run_udp_concurrent(context, router, socket, tripwire));
            } else {
                tokio::spawn_async(Self::run_udp(router, socket, tripwire));
            }
        }

        // Spawn TCP acceptors
        let socket = TcpListener::bind(&socket_addr)?;
        let context = self.context.clone();
        let router = self.query_router.clone();
        let connections = self.connections.clone();
        tokio::spawn_async(Self::run_tcp(
            context,
            router,
            connections,
            socket,
            tripwire.clone(),
        ));

        info!("server bound to {}", socket_addr);
        Ok(())
    }
}

/// Maps a queue of questablished connections per client address.
/// A connection is represented by an atomic boolean that represents an open connection.
type EstablishedConnections = Mutex<HashMap<IpAddr, VecDeque<(u16, mpsc::Sender<Bytes>)>>>;

async fn process_stream(
    router: Arc<QueryRouter>,
    connections: Arc<EstablishedConnections>,
    peer_addr: SocketAddr,
    stream: TcpStream,
    sender: mpsc::Sender<Bytes>,
    receiver: mpsc::Receiver<Bytes>,
) {
    let (sink, mut stream) = tcp_framed_transport(stream).split();

    // Demultiplex responses back to the TCP stream
    tokio::spawn(
        receiver
            .map_err(move |_| IoError::new(ErrorKind::BrokenPipe, "broken pipe"))
            .forward(sink)
            .then(move |res| {
                match res {
                    Ok((_, mut sink)) => {
                        debug!("tcp stream disconnected: {}", peer_addr);
                        drop(sink.close());
                    }
                    Err(e) => {
                        trace!("tcp stream error: {:?}", e);
                    }
                }
                Ok::<_, ()>(())
            }),
    );

    // Process incoming messages
    while let Some(item) = await!(stream.next()) {
        match item {
            Ok(msg) => {
                // Process message asynchronously
                tokio::spawn_async(process_message(
                    router.clone(),
                    sender.clone(),
                    msg.into(),
                    peer_addr,
                    Protocol::Tcp,
                ));
            }
            Err(e) => {
                debug!("tcp stream: {:?}", e);
                return;
            }
        };
    }

    // Client disconnected, remove the associated connection and close the
    // inner queue to prevent sending responses back from messages in flight
    let mut connections_guard = connections.lock();
    if let Some(queue) = connections_guard.get_mut(&peer_addr.ip()) {
        for index in 0..queue.len() {
            let port = queue[index].0;
            if peer_addr.port() == port {
                debug!("tcp clearing port {} from queue {}", port, peer_addr.ip());
                drop(queue.remove(index));
                break;
            }
        }

        if queue.is_empty() {
            debug!("tcp clearing queue for {}", peer_addr.ip());
            connections_guard.remove(&peer_addr.ip());
        }
    }
}

async fn process_message(
    router: Arc<QueryRouter>,
    sender: mpsc::Sender<Bytes>,
    msg: Bytes,
    peer_addr: SocketAddr,
    protocol: Protocol,
) {
    match await!(resolve_message(&router, msg, peer_addr, protocol)) {
        Ok((response, _)) => match await!(sender.send(response)) {
            Ok(_) => {
                debug!("sent back response to {}/{:?}", peer_addr, protocol);
            }
            Err(e) => {
                info!("failed to send an answer back: {}", e);
            }
        },
        Err(e) => {
            info!("failed to generate an answer: {}", e);
        }
    };
}

pub async fn resolve_message<'a>(
    router: &'a Arc<QueryRouter>,
    msg: Bytes,
    from: SocketAddr,
    protocol: Protocol,
) -> Result<(Bytes, SocketAddr)> {
    let buf = BytesMut::with_capacity(INITIAL_BUF_SIZE);
    // Create a new request scope
    let result = match Scope::new(msg, from) {
        Ok(mut scope) => {
            scope.with_protocol(protocol);
            await!(router.resolve(scope, buf))
        }
        Err(e) => Err(e),
    };
    // Generate a response
    match result {
        Ok(answer) => Ok((answer.into(), from)),
        Err(e) => Err(e),
    }
}

fn clone_udp_socket(socket: &Socket) -> Result<UdpSocket> {
    let cloned = socket.try_clone()?;
    match UdpSocket::from_std(cloned.into_udp_socket(), &Handle::default()) {
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
