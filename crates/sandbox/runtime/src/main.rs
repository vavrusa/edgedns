#![feature(await_macro, async_await, futures_api)]

use toml;
use bytes::BytesMut;
use clap::{App, Arg};
use domain_core::bits::*;
use env_logger;
use guest_types as guest;
use libedgedns::{Config, Context, FramedStream, ClientRequest, sandbox::Sandbox};
use log::*;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
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
            let sandbox = Sandbox::from(&context.config);
            sandbox.start(context.clone(), tripwire.clone());

            // Listen and process incoming messages
            if let Some(address) = matches.value_of("listen") {
                info!("processing messages from {}", address);
                let local_addr = address.parse::<SocketAddr>().unwrap();
                let socket = UdpSocket::bind(&local_addr).unwrap();

                let (mut sink, mut stream) = FramedStream::from(socket).split();
                while let Some(Ok((msg, from))) = await!(stream.next()) {
                    let mut scope = ClientRequest::new(msg.clone().into(), from).expect("scope");
                    scope.set_local_addr(local_addr.clone(), false);
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
                        await!(sandbox.resolve(guest::Phase::PreCache, &scope, answer));
                    trace!("processed phase: {:?}", action);

                    sink = await!(sink.send((answer.into(), from))).unwrap();
                }
            }
        },
    );

    drop(trigger);
}

fn runtime_context(path: &Path, name: &str) -> Arc<Context> {
    let mut config = Config::default();
    config.apps_location = path.to_str().unwrap().parse().ok();
    config.apps_config.insert(name.to_owned(), toml::value::Value::Table(toml::value::Table::new()));
    Context::new(config)
}
