// Utilities for a test module
#![allow(dead_code)]
use crate::codecs::*;
use crate::conductor::Origin;
use crate::config::{Config, ServerType};
use crate::context::Context;
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
use std::env;
use std::path::PathBuf;

/// File with a list of test domains
const DOMAINS_STR: &str = include_str!("domains.csv");

/// Test sandbox apps
pub const TEST_APP: &[u8] = include_bytes!("test_app/target/wasm32-unknown-unknown/release/test_app.wasm");

// Static variables
lazy_static! {
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
    Context::new(config)
}

/// Create an echo server (UDP and TCP) and return the listener address, and the server future
pub fn test_echo_server(timeout: Duration) -> (impl Future<Item = (), Error = ()>, SocketAddr) {
    let listener =
        TcpListener::bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap()).expect("tcp listener");
    let local_addr = listener.local_addr().unwrap();
    let sock = UdpSocket::bind(&local_addr).expect("udp listener");

    // Create futures
    let (sink, stream) = UdpFramed::new(sock, BytesCodec::new()).split();
    let echo_udp = sink
        .send_all(stream.map(|(msg, addr)| (msg.into(), addr)))
        .timeout(timeout)
        .and_then(|_| Ok(()))
        .map_err(|e| eprintln!("{}", e));

    let echo_tcp = listener
        .incoming()
        .map_err(|e| eprintln!("failed to accept socket; error = {:?}", e))
        .for_each(|socket| {
            let (sink, stream) = FramedStream::from(socket).split();
            tokio::spawn(
                stream
                    .map(move |(msg, addr)| (msg.into(), addr))
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

    (echo_udp.join(echo_tcp).then(|_| Ok(())), local_addr)
}

/// Returns test root path.
/// See https://github.com/rust-lang/cargo/issues/3368
pub fn test_root_path() -> PathBuf {
     let mut path = env::current_exe().unwrap();
     path.pop(); // chop off exe name
     path.pop(); // chop off 'debug'

     // If `cargo test` is run manually then our path looks like
     // `target/debug/foo`, in which case our `path` is already pointing at
     // `target`. If, however, `cargo test --target $target` is used then the
     // output is `target/$target/debug/foo`, so our path is pointing at
     // `target/$target`. Here we conditionally pop the `$target` name.
     if path.file_name().and_then(|s| s.to_str()) != Some("target") {
         path.pop();
     }

     path
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
