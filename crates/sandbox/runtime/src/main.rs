#![feature(await_macro, async_await, futures_api)]

use bytes::BytesMut;
use clap::{App, Arg};
use domain_core::bits::*;
use env_logger;
use guest;
use libedgedns::{sandbox, Config, Context, FramedStream, Scope};
use log::*;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use stream_cancel::Tripwire;
use tokio::await;
use tokio::net::UdpSocket;
use tokio::prelude::*;

const PKG_NAME: &str = env!("CARGO_PKG_NAME");
const PKG_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

fn main() {
    env_logger::init();

    let matches = App::new(PKG_NAME)
        .version(PKG_VERSION)
        .author(PKG_AUTHORS)
        .about(PKG_DESCRIPTION)
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("FILE")
                .help("Path to the *.wasm file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen")
                .short("l")
                .long("listen")
                .value_name("ADDRESS")
                .help("Listen on given address for queries (example: 127.0.0.1:1053)")
                .takes_value(true),
        )
        .get_matches();

    let wasm_file = Path::new(matches.value_of("file").unwrap_or("example.wasm"));

    // Graceful shutdown trigger
    let (trigger, tripwire) = Tripwire::new();
    let context = runtime_context(
        wasm_file.parent().unwrap(),
        wasm_file.file_stem().unwrap().to_str().unwrap(),
    );

    tokio::run_async(
        async move {
            // Start the module loader
            let loader = Arc::new(sandbox::FSLoader::new(context.clone()));
            sandbox::FSLoader::spawn(loader.clone(), tripwire.clone());

            // Listen and process incoming messages
            if let Some(address) = matches.value_of("listen") {
                info!("processing messages from {}", address);
                let socket = UdpSocket::bind(&address.parse::<SocketAddr>().unwrap()).unwrap();

                let (mut sink, mut stream) = FramedStream::from(socket).split();
                while let Some(Ok((msg, from))) = await!(stream.next()) {
                    let scope = Scope::new(msg.clone().into(), from).expect("scope");
                    trace!("processing {} bytes from {}", msg.len(), from);

                    // Create a response builder
                    let answer = {
                        let mut message = MessageBuilder::from_buf(BytesMut::with_capacity(512));
                        let header = message.header_mut();
                        *header = *scope.query.header();
                        header.set_id(scope.query.header().id());
                        header.set_qr(true);
                        message.push(scope.question.clone()).unwrap();
                        message.finish()
                    };

                    // Process message
                    let (answer, action) =
                        await!(loader.run_hook(guest::Phase::PreCache, &scope, answer));
                    trace!("processed hook: {:?}", action);

                    sink = await!(sink.send((answer.into(), from))).unwrap();
                }
            }
        },
    );

    drop(trigger);
}

fn runtime_context(path: &Path, name: &str) -> Arc<Context> {
    let mut config = Config::default();
    config.apps_location = Some(path.to_str().unwrap().to_owned());
    config.apps_reload_interval = Some(Duration::from_millis(500));
    Context::new(config)
}
