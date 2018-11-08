// Utilities for a test module
#![allow(dead_code)]
use crate::cache::Cache;
use crate::conductor::{Conductor, Origin};
use crate::config::Config;
use crate::context::Context;
use crate::varz::Varz;
use bytes::Bytes;
use domain_core::bits::*;
use futures::sync::oneshot;
use futures::Future;
use lazy_static::*;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io;
use tokio::codec::BytesCodec;
use tokio::net::{UdpFramed, UdpSocket, TcpListener};
use tokio::prelude::*;
use tokio::reactor::Handle;
use tokio::runtime::Runtime;
use socket2::{Socket, Domain, Type, SockAddr};

/// File with a list of test domains
const DOMAINS_STR: &str = include_str!("domains.csv");

// Static variables
lazy_static! {
    pub static ref VARZ: Varz = Varz::default();
    pub static ref MSG: Message = Message::from_bytes(Bytes::from_static(&[0u8; 12])).unwrap();
    pub static ref DOMAINS: Vec<Dname> = DOMAINS_STR
        .lines()
        .filter_map(|line| if let Ok(dname) = Dname::from_str(line) {
            Some(dname)
        } else {
            None
        }).collect();
}

/// Create a default test context
pub fn test_context() -> Arc<Context> {
    let mut config = Config::default();
    config.cache_size = 10;

    let config = Arc::new(config);

    let conductor = Conductor::new();
    let cache = Cache::new(&config, VARZ.clone());
    Context::new(config.clone(), conductor, cache, VARZ.clone())
}

/// Spawn a future on runtime and wait for completion
pub fn spawn_and_wait<R, E, F>(runtime: &mut Runtime, f: F) -> Result<R, E>
where
    R: Send + 'static,
    E: Send + 'static,
    F: Future<Item = R, Error = E> + Send + 'static,
{
    let (tx, rx) = oneshot::channel();
    runtime.spawn(f.then(|r| tx.send(r).map_err(|_| panic!("Cannot send result"))));
    rx.wait().expect("Cannot wait")
}

/// Create an echo UDP server and return its address and future
pub fn echo_udp_server(timeout: Duration) -> (impl Future<Item = (), Error = ()>, SocketAddr) {
    let listener = {
        let sock = Socket::new(Domain::ipv4(), Type::stream(), None).unwrap();
        // sock.set_reuse_address(true).unwrap();
        sock.bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into()).unwrap();
        sock.listen(1_000_000).unwrap();
        TcpListener::from_std(sock.into_tcp_listener(), &Handle::default()).unwrap()
    };
    let local_addr = listener.local_addr().unwrap();
    let sock = UdpSocket::bind(&local_addr).unwrap();

    // Create futures
    let (sink, stream) = UdpFramed::new(sock, BytesCodec::new()).split();
    let fut_udp = sink
        .send_all(stream.map(|(msg, addr)| (msg.into(), addr)))
        .timeout(timeout)
        .and_then(|_| Ok(()))
        .map_err(|e| eprintln!("{}", e));

    let fut_tcp = listener.incoming()
        .map_err(|e| eprintln!("failed to accept socket; error = {:?}", e))
        .for_each(|socket| {
            let (reader, writer) = socket.split();
            tokio::spawn(
                io::copy(reader, writer)
                    .map_err(|err| eprintln!("I/O error {:?}", err))
                    .then(|_| Ok(()))
            );
            Ok(())
        });

    (fut_udp.join(fut_tcp).then(|_| Ok(())), local_addr)
}

/// Test origin returning a predefined address
pub struct TestOrigin {
    addrs: Vec<SocketAddr>,
}

impl From<SocketAddr> for TestOrigin {
    fn from(addr: SocketAddr) -> Self {
        TestOrigin {
            addrs: [addr].to_vec(),
        }
    }
}

impl Origin for TestOrigin {
    fn get(&self) -> &[SocketAddr] {
        &self.addrs
    }
}
