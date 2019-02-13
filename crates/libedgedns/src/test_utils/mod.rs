// Utilities for a test module
#![allow(dead_code)]
use crate::cache::Cache;
use crate::codecs::*;
use crate::conductor::{Conductor, Origin};
use crate::config::{Config, ServerType};
use crate::context::Context;
use crate::varz::Varz;
use bytes::Bytes;
use domain_core::bits::*;
use futures::Future;
use lazy_static::*;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::codec::BytesCodec;
use tokio::net::{TcpListener, UdpFramed, UdpSocket};
use tokio::prelude::*;

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
        })
        .collect();
}

/// Create a default test context
pub fn test_context() -> Arc<Context> {
    let mut config = Config::default();
    config.cache_size = 10;
    config.server_type = ServerType::Recursive;
    config.upstream_max_failure_duration = Duration::from_millis(2500);

    let config = Arc::new(config);
    let conductor = Arc::new(Conductor::from(&config));
    let cache = Cache::from(&config);
    Context::new(config, conductor, cache, VARZ.clone())
}

/// Create an echo server (UDP and TCP) and return the listener address, and the server future
pub fn test_echo_server(timeout: Duration) -> (impl Future<Item = (), Error = ()>, SocketAddr) {
    let listener =
        TcpListener::bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap()).expect("tcp listener");
    let local_addr = listener.local_addr().unwrap();
    let sock = UdpSocket::bind(&local_addr).expect("udp listener");

    // Create futures
    let (sink, stream) = UdpFramed::new(sock, BytesCodec::new()).split();
    let fut_udp = sink
        .send_all(stream.map(|(msg, addr)| (msg.into(), addr)))
        .timeout(timeout)
        .and_then(|_| Ok(()))
        .map_err(|e| eprintln!("{}", e));

    let fut_tcp = listener
        .incoming()
        .map_err(|e| eprintln!("failed to accept socket; error = {:?}", e))
        .for_each(|socket| {
            let (sink, stream) = tcp_framed_transport(socket).split();
            tokio::spawn(
                stream
                    .map(move |msg| msg.into())
                    .forward(sink)
                    .map_err(|err| eprintln!("I/O error: {:?}", err))
                    .and_then(move |(stream, sink)| {
                        // Reunite split stream and close it
                        if let Ok(mut stream) = sink.reunite(stream.into_inner()) {
                            drop(stream.close());
                        }

                        Ok(())
                    }),
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
