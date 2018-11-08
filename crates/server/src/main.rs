#![feature(pin, await_macro, async_await, futures_api)]
#[cfg(feature = "jemalloc")]
use jemallocator;
#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

use clap::{App, Arg};
use coarsetime::Instant;
use env_logger;
use libedgedns::{Cache, Conductor, Config, Context, Scope, Varz};
use log::*;
use std::io::Result;
use tokio::await;
use tokio::prelude::*;
use tokio::reactor::Handle;
use tokio::timer::Interval;

use bytes::BytesMut;
use socket2::{Domain, Socket, Type};
use std::net;
use std::sync::Arc;
use std::time::Duration;
use tokio::codec::BytesCodec;
use tokio::net::{UdpFramed, UdpSocket};

#[cfg(feature = "webservice")]
mod webservice;

const PKG_NAME: &str = env!("CARGO_PKG_NAME");
const PKG_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const CLOCK_RESOLUTION: u64 = 100;

fn udp_worker_run(context: Arc<Context>, socket: UdpSocket) -> Result<()> {
    tokio::spawn_async(
        async move {
            let answer = BytesMut::with_capacity(1452);
            let (mut sink, mut stream) = UdpFramed::new(socket, BytesCodec::new()).split();
            while let Some(Ok((msg, addr))) = await!(stream.next()) {
                // Clear a buffer for answer
                let mut answer = answer.clone();
                answer.reserve(1452);
                // Create a new request scope
                let result = match Scope::new(msg.into(), addr) {
                    Ok(r) => await!(r.resolve(context.clone(), answer)),
                    Err(e) => Err(e),
                };
                // Generate a response
                if let Ok(answer) = result {
                    match await!(sink.send((answer.into(), addr))) {
                        Ok(res) => {
                            sink = res;
                        }
                        Err(_) => {
                            break;
                        }
                    }
                }
            }
        },
    );

    Ok(())
}

fn main() {
    env_logger::init();

    let matches = App::new(PKG_NAME)
        .version(PKG_VERSION)
        .author(PKG_AUTHORS)
        .about(PKG_DESCRIPTION)
        .arg(
            Arg::with_name("config_file")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Path to the edgedns.toml config file")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    let config_file = match matches.value_of("config_file") {
        None => "edgedns.toml",
        Some(config_file) => config_file,
    };

    let config = match Config::from_path(config_file) {
        Err(err) => {
            error!(
                "The configuration couldn't be loaded -- [{}]: [{}]",
                config_file, err
            );
            return;
        }
        Ok(config) => Arc::new(config),
    };

    let varz = Varz::default();

    tokio::run_async(
        async move {
            // Update coarsetime internal timestamp regularly
            tokio::spawn(
                Interval::new_interval(Duration::from_millis(CLOCK_RESOLUTION))
                    .for_each(move |_| {
                        Instant::update();
                        Ok(())
                    })
                    .map_err(|e| eprintln!("failed to update time: {}", e)),
            );

            let conductor = Conductor::new();
            let cache = Cache::new(&config, varz.clone());
            let context = Context::new(config.clone(), conductor, cache, varz);
            let socket_addr = config.listen_addr.parse::<net::SocketAddr>().unwrap();
            let socket = Socket::new(Domain::ipv4(), Type::dgram(), None).unwrap();
            socket.bind(&socket_addr.into()).unwrap();
            socket.set_reuse_address(true).unwrap();
            socket.set_reuse_port(true).unwrap();

            info!("Bound to: {:?}/udp", socket_addr);
            for _ in 0..config.udp_acceptor_threads {
                let local_context = context.clone();
                let socket = UdpSocket::from_std(
                    socket.try_clone().unwrap().into_udp_socket(),
                    &Handle::default(),
                )
                .unwrap();
                udp_worker_run(local_context, socket).unwrap();
            }

            #[cfg(feature = "webservice")]
            webservice::WebService::spawn(context.clone());
        },
    );
}
