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
use std::io::ErrorKind;
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::sync::Arc;
use tokio::await;
use tokio::codec::BytesCodec;
use tokio::net::{TcpListener, TcpStream, UdpFramed, UdpSocket};
use tokio::prelude::*;
use tokio::reactor::Handle;

/// Server serving requests from a UDP socket.
pub struct UdpServer {
    context: Arc<Context>,
    query_router: QueryRouter,
    concurrency_limit: usize,
}

impl UdpServer {
    pub fn new(context: Arc<Context>, concurrency_limit: usize) -> Self {
        Self {
            query_router: QueryRouter::new(context.clone()),
            context,
            concurrency_limit,
        }
    }

    pub async fn run(context: Arc<Context>, router: QueryRouter, socket: UdpSocket) {
        let (mut sink, mut stream) = UdpFramed::new(socket, BytesCodec::new()).split();
        while let Some(Ok((msg, addr))) = await!(stream.next()) {
            match await!(resolve_message(&context, &router, msg.into(), addr)) {
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
    }

    pub async fn run_concurrent(context: Arc<Context>, router: QueryRouter, socket: UdpSocket) {
        let (sink, mut stream) = UdpFramed::new(socket, BytesCodec::new()).split();

        // Create a channel for serializing messages from fan-out workers
        // The channel buffer size is set reasonably low to provide a backpressure,
        // so that if the executor is busy resolving queries, it shouldn't queue too many new ones.
        let (mut sender, receiver) = mpsc::channel(context.config.udp_acceptor_threads);

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

        while let Some(Ok((msg, addr))) = await!(stream.next()) {
            match await!(resolve_message(&context, &router, msg.into(), addr)) {
                Ok(res) => match await!(sender.send(res)) {
                    Ok(res) => {
                        sender = res;
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
    }

    pub fn spawn(&self) -> Result<()> {
        let socket_addr = self.context.config.listen_addr.parse::<SocketAddr>()?;
        let socket = create_udp_socket(socket_addr)?;

        // Spawn a single concurrent handler with higher overhead, and the rest of fast-lane handlers.
        // This serves two purposes:
        //  * The concurrent handler can process many concurrent requests, but requires a channel
        //    to serialize transmission back to the UDP socket.
        //  * The non-concurrent handler can process a single request at a time, but can clear more
        //    requests per second during heavy load.
        let acceptors = self.context.config.udp_acceptor_threads;
        for i in 0..acceptors {
            let socket = clone_udp_socket(&socket)?;
            let context = self.context.clone();
            let router = self.query_router.clone();
            if i == acceptors - 1 {
                tokio::spawn_async(UdpServer::run_concurrent(context, router, socket));
            } else {
                tokio::spawn_async(UdpServer::run(context, router, socket));
            }
        }

        info!("udp bound to {}", socket_addr);
        Ok(())
    }
}

pub struct TcpServer {
    context: Arc<Context>,
    query_router: QueryRouter,
    connections: Arc<EstablishedConnections>,
    concurrency_limit: usize,
}

impl TcpServer {
    pub fn new(context: Arc<Context>, concurrency_limit: usize) -> Self {
        Self {
            query_router: QueryRouter::new(context.clone()),
            context,
            connections: Arc::new(EstablishedConnections::default()),
            concurrency_limit,
        }
    }

    pub fn spawn(&self) -> Result<()> {
        let socket_addr = self.context.config.listen_addr.parse::<SocketAddr>()?;
        let socket = TcpListener::bind(&socket_addr)?;
        let context = self.context.clone();
        let router = self.query_router.clone();
        let connections = self.connections.clone();
        tokio::spawn_async(process_tcp_clients(context, router, connections, socket));

        info!("tcp bound to {}", socket_addr);
        Ok(())
    }
}

/// Maps a queue of questablished connections per client address.
/// A connection is represented by an atomic boolean that represents an open connection.
type EstablishedConnections = Mutex<HashMap<IpAddr, VecDeque<TcpStream>>>;

/// Process clients from a TCP listener.
async fn process_tcp_clients(
    context: Arc<Context>,
    router: QueryRouter,
    connections: Arc<EstablishedConnections>,
    listener: TcpListener,
) {
    let mut incoming = listener.incoming();
    while let Some(Ok(stream)) = await!(incoming.next()) {
        let peer_addr = stream.peer_addr().expect("tcp peer has address");

        // Reuse TCP slots for each client identified by an IP address
        // This is governed by the maximum TCP client count from the configuration.
        // Each client gets a TCP slot allowance calculated as a portion of total TCP client count.
        // If the TCP slot allowance for client is reached, the client's oldest open connection is recycled.
        let queue_len = {
            let mut connections = connections.lock();

            // If the TCP client count is at maximum capacity, close an arbitrary client
            if connections.len() >= context.config.max_tcp_clients {
                if let Some((key, queue)) = connections.iter().next() {
                    debug!("tcp client {}: forcing {} to close", peer_addr, key);
                    for stream in queue {
                        drop(stream.shutdown(Shutdown::Both));
                    }
                    let key = *key;
                    connections.remove(&key);
                }
            }

            let max_per_client = context.config.max_tcp_clients / (connections.len() + 2);
            let queue = connections.entry(peer_addr.ip()).or_default();

            // Close connections exceeding the allowed count
            while queue.len() >= max_per_client {
                if let Some(stream) = queue.pop_front() {
                    debug!("tcp client {}: closing previous connection", peer_addr);
                    drop(stream.shutdown(Shutdown::Both));
                }
            }

            // Register new connection
            if let Ok(stream) = stream.try_clone() {
                queue.push_back(stream);
            }

            queue.len()
        };

        debug!(
            "tcp client {} connected, queue length: {}",
            peer_addr, queue_len
        );
        tokio::spawn_async(process_stream(
            context.clone(),
            router.clone(),
            connections.clone(),
            peer_addr,
            stream,
        ));
    }
}

async fn process_stream(
    context: Arc<Context>,
    router: QueryRouter,
    connections: Arc<EstablishedConnections>,
    peer_addr: SocketAddr,
    stream: TcpStream,
) {
    let (sink, mut stream) = tcp_framed_transport(stream).split();

    // TODO: configurable max_inflight_per_connection
    let (sender, receiver) = mpsc::channel(0);

    // Demultiplex responses back to the TCP stream
    tokio::spawn(
        receiver
            .map_err(move |_| ErrorKind::BrokenPipe.into())
            .forward(sink)
            .then(move |res: Result<_>| {
                match res {
                    Ok((_, mut sink)) => {
                        debug!("tcp stream done: {}", peer_addr);
                        drop(sink.close());
                    }
                    Err(e) => {
                        info!("tcp stream error: {:?}", e);
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
                    context.clone(),
                    router.clone(),
                    sender.clone(),
                    msg.into(),
                    peer_addr,
                ));
            }
            Err(e) => {
                debug!("tcp stream: {:?}", e);
                return;
            }
        };
    }

    let mut connections_guard = connections.lock();
    if let Some(queue) = connections_guard.get_mut(&peer_addr.ip()) {
        for index in 0..queue.len() {
            let port = queue[index]
                .peer_addr()
                .expect("tcp stream has peer address")
                .port();
            if peer_addr.port() == port {
                debug!("tcp clearing port {} from queue {}", port, peer_addr.ip());
                queue.remove(index);
                break;
            }
        }

        if queue.is_empty() {
            debug!("tcp clearing queue for {}", peer_addr.ip());
            connections_guard.remove(&peer_addr.ip());
        }
    }

    debug!("tcp disconnected {}", peer_addr)
}

async fn process_message(
    context: Arc<Context>,
    router: QueryRouter,
    sender: mpsc::Sender<Bytes>,
    msg: Bytes,
    peer_addr: SocketAddr,
) {
    match await!(resolve_message(&context, &router, msg, peer_addr)) {
        Ok((response, _)) => match await!(sender.send(response)) {
            Ok(_) => {
                debug!("tcp sent back response to {}", peer_addr);
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
    context: &'a Arc<Context>,
    router: &'a QueryRouter,
    msg: Bytes,
    from: SocketAddr,
) -> Result<(Bytes, SocketAddr)> {
    let buf = BytesMut::with_capacity(1452);
    // Create a new request scope
    let result = match Scope::new(context.clone(), msg, from) {
        Ok(scope) => await!(router.resolve(scope, buf)),
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
