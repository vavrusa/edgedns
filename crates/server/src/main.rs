#![feature(await_macro, async_await, futures_api)]
#[cfg(feature = "jemalloc")]
use jemallocator;
#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

use clap::{App, Arg};
use coarsetime::Instant;
use env_logger;
use libedgedns::{sandbox::Sandbox, Config, Context, Listener, QueryRouter, Server};
use listenfd::ListenFd;
use log::*;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use stream_cancel::{StreamExt, Tripwire};
use tokio::net::{TcpListener, UdpSocket};
use tokio::prelude::*;
use tokio::reactor::Handle;
use tokio::timer::Interval;
use tokio_signal;

#[cfg(feature = "webservice")]
mod webservice;

const PKG_NAME: &str = env!("CARGO_PKG_NAME");
const PKG_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const CLOCK_RESOLUTION: u64 = 250;

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
                .takes_value(true),
        )
        .get_matches();

    let config_file = match matches.value_of("config_file") {
        None => "edgedns.toml",
        Some(config_file) => config_file,
    };

    let config = match Config::from_path(config_file) {
        Err(err) => {
            panic!("configuration {} couldn't be loaded: {}", config_file, err);
        }
        Ok(config) => config,
    };

    tokio::run_async(
        async move {
            let context = Context::new(config);

            // Graceful shutdown trigger
            let (trigger, cancel) = Tripwire::new();

            // Update coarsetime internal timestamp regularly
            tokio::spawn(
                Interval::new_interval(Duration::from_millis(CLOCK_RESOLUTION))
                    .take_until(cancel.clone())
                    .for_each(move |_| {
                        Instant::update();
                        Ok(())
                    })
                    .map_err(|e| eprintln!("failed to update time: {}", e)),
            );

            // Start the app sandbox
            let sandbox = Sandbox::from(&context.config);
            sandbox.start(context.clone(), cancel.clone());

            // Create the query router
            let query_router = Arc::new(QueryRouter::new(context.clone()).with_sandbox(sandbox));
            QueryRouter::spawn(query_router.clone(), cancel.clone());

            // Start server
            let server = Server::new(context.clone());

            // Lease sockets from the supervisor (supports systemd protocol)
            let mut listenfd = ListenFd::from_env();
            let mut bound = HashMap::new();
            for i in 0..listenfd.len() {
                let router = query_router.clone();
                match take_listener(
                    &mut listenfd,
                    i,
                    context.clone(),
                    &server,
                    router,
                    cancel.clone(),
                ) {
                    Ok(addr) => {
                        bound.insert(addr, true);
                    }
                    Err(e) => panic!("failed to take listener: {}", e),
                }
            }

            // Bind to configured sockets
            for endpoint in context.config.listen.iter() {
                // Skip sockets already bound from supervisor
                if bound.contains_key(&endpoint.address) {
                    continue;
                }
                match server.spawn(query_router.clone(), endpoint.clone(), cancel.clone()) {
                    Ok(_) => {
                        info!("listener bound to {}", endpoint.address);
                    }
                    Err(e) => {
                        panic!("failed to bind to {}: {}", endpoint.address, e);
                    }
                }
            }

            // Start the optional webservice
            if !bound.contains_key(&context.config.webservice_listen_addr) {
                #[cfg(feature = "webservice")]
                match webservice::WebService::spawn(context.clone(), query_router, cancel.clone()) {
                    Err(e) => panic!("failed to spawn webservice: {}", e),
                    Ok(_) => {}
                }
            }

            // Wait for termination signal
            let ctrl_c = tokio_signal::ctrl_c()
                .flatten_stream()
                .into_future()
                .then(move |_| {
                    info!("shutdown initiated");
                    drop(trigger);
                    Ok(())
                });
            tokio::spawn(ctrl_c);
        },
    );
}

/// Convert a fd leased from the supervisor into listener.
fn take_listener(
    listenfd: &mut ListenFd,
    index: usize,
    context: Arc<Context>,
    server: &Server,
    router: Arc<QueryRouter>,
    cancel: Tripwire,
) -> Result<SocketAddr> {
    let config = &context.config;
    // Try to convert passed fd into a TCP listener
    if let Ok(Some(socket)) = listenfd.take_tcp_listener(index) {
        // Use listener configuration from the config or create new
        let local_addr = socket.local_addr().expect("bound socket");
        let endpoint = match config.listen.iter().find(|x| x.address == local_addr) {
            Some(endpoint) => endpoint.clone(),
            None => {
                // Check if the listener matches the webservice
                if local_addr == config.webservice_listen_addr {
                    #[cfg(feature = "webservice")]
                    match webservice::WebService::spawn_listener(context.clone(), router.clone(), socket, cancel) {
                        Err(e) => {
                            warn!("failed to spawn webservice: {}", e);
                            return Err(Error::new(ErrorKind::Other, e.to_string()));
                        }
                        Ok(_) => {
                            info!("webservice leased {}/tcp", local_addr);
                            return Ok(local_addr)
                        },
                    }
                }

                Arc::new(Listener::new(local_addr))
            }
        };

        info!("listener leased {}/tcp", local_addr);
        let socket = TcpListener::from_std(socket, &Handle::default())?;
        server.spawn_stream_tcp(router, socket, endpoint, cancel);
        return Ok(local_addr);
    }

    // Try to convert passed fd into a UDP listener
    if let Ok(Some(socket)) = listenfd.take_udp_socket(index) {
        // Use listener configuration from the config or create new
        let socket = UdpSocket::from_std(socket, &Handle::default())?;
        let local_addr = socket.local_addr().expect("bound socket");
        let endpoint = match config.listen.iter().find(|x| x.address == local_addr) {
            Some(endpoint) => endpoint.clone(),
            None => Arc::new(Listener::new(local_addr)),
        };

        info!("listener leased {}/udp", local_addr);
        server.spawn_stream_udp(router, socket, endpoint, cancel);
        return Ok(local_addr);
    }

    // Unsupported socket passed, ignore
    warn!(
        "supervisor passed an unknown socket {:?}",
        listenfd.take_raw_fd(0)
    );
    Err(ErrorKind::Other.into())
}
