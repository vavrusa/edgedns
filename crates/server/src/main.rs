#![feature(await_macro, async_await, futures_api)]
#[cfg(feature = "jemalloc")]
use jemallocator;
#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

use clap::{App, Arg};
use coarsetime::Instant;
use env_logger;
use libedgedns::{Config, Context, QueryRouter, Server};
use log::*;
use std::sync::Arc;
use std::time::Duration;
use stream_cancel::{StreamExt, Tripwire};
use tokio::prelude::*;
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
            error!(
                "The configuration couldn't be loaded -- [{}]: [{}]",
                config_file, err
            );
            return;
        }
        Ok(config) => config,
    };

    tokio::run_async(
        async move {
            let context = Context::new(config);

            // Graceful shutdown trigger
            let (trigger, tripwire) = Tripwire::new();

            // Update coarsetime internal timestamp regularly
            tokio::spawn(
                Interval::new_interval(Duration::from_millis(CLOCK_RESOLUTION))
                    .take_until(tripwire.clone())
                    .for_each(move |_| {
                        Instant::update();
                        Ok(())
                    })
                    .map_err(|e| eprintln!("failed to update time: {}", e)),
            );

            // Create the query router
            let query_router = Arc::new(QueryRouter::new(context.clone()));
            QueryRouter::spawn(query_router.clone(), tripwire.clone());

            // Start server
            let server = Server::new(context.clone());
            if let Err(e) = server.spawn(query_router, tripwire.clone()) {
                panic!("failed to start: {}", e);
            }

            // Start the optional webservice
            #[cfg(feature = "webservice")]
            webservice::WebService::spawn(context.clone(), tripwire.clone());

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
