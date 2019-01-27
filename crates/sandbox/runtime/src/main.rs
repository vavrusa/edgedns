#![feature(await_macro, async_await, futures_api)]
#[cfg(feature = "jemalloc")]
use jemallocator;
#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

use bytes::BytesMut;
use clap::{App, Arg};
use cranelift_codegen::settings;
use cranelift_codegen::settings::Configurable;
use domain_core::bits::*;
use env_logger;
use futures::future::Either;
use libedgedns::{Cache, Conductor, Config, Context, Scope, Varz};
use log::*;
use parking_lot::{Mutex, RwLock};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use tokio::codec::BytesCodec;
use tokio::net::{UdpFramed, UdpSocket};
use tokio::prelude::*;
use tokio::runtime::Runtime;
use tokio::timer::Interval;
use wasmtime_jit::{Compiler, Namespace, InstanceIndex};
use libedgedns_sandbox::SharedState;

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
        .arg(
            Arg::with_name("verify")
                .short("v")
                .long("verify")
                .help("Enable WASM compiler verifier."),
        )
        .arg(
            Arg::with_name("opt_level")
                .short("o")
                .long("opt-level")
                .value_name("SETTINGS")
                .help("Select optimization level")
                .possible_values(&["default", "best", "fastest"])
                .takes_value(true),
        )
        .arg(
            Arg::with_name("disable")
                .short("x")
                .long("disable")
                .help("Disable message processing hooks."),
        )
        .get_matches();

    let wasm_file = matches.value_of("file").unwrap_or("main.wasm");

    let mut flag_builder = settings::builder();
    if matches.is_present("verify") {
        flag_builder.enable("enable_verifier").unwrap();
    }
    flag_builder
        .set(
            "opt_level",
            matches.value_of("opt_level").unwrap_or("default"),
        )
        .unwrap();

    let isa_builder = cranelift_native::builder().unwrap_or_else(|_| {
        panic!("host machine is not a supported target");
    });
    let isa = isa_builder.finish(settings::Flags::new(flag_builder));
    let context = runtime_context();
    let shared_state = SharedState::new(context.clone(), Compiler::new(isa), Namespace::new());
    let current_index : Arc<RwLock<Option<InstanceIndex>>> = Arc::new(RwLock::new(None));

    // Run start function
    trace!("runtime start");
    let file_reloader = file_reloader(wasm_file.to_string(), shared_state.clone(), current_index.clone());

    // Listen and process incoming messages
    if let Some(address) = matches.value_of("listen") {
        let current_index = current_index.clone();
        let hook_disabled = matches.is_present("disable");

        info!("processing messages from {}", address);
        let socket = UdpSocket::bind(&address.parse::<SocketAddr>().unwrap()).unwrap();
        let (sink, stream) = UdpFramed::new(socket, BytesCodec::new()).split();
        let fut = stream
            .and_then(move |(msg, from)| {
                let shared_state = shared_state.clone();
                let index = *current_index.read();
                let scope = Scope::new(context.clone(), msg.clone().into(), from).expect("scope");
                trace!("processing {} bytes from {}, instance: {:?}", msg.len(), from, index);

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
                if hook_disabled || index.is_none() {
                    Either::A(future::ok((answer.into(), from)))
                } else {
                    Either::B(
                        shared_state
                            .invoke_hook(index.unwrap(), scope, answer.clone())
                            .then(move |res| {
                                trace!("processed hook: {:?}", res);
                                if let Ok((answer, _action)) = res {
                                    Ok((answer.into(), from))
                                } else {
                                    Ok((answer.into(), from))
                                }
                            }),
                    )
                }
            })
            .forward(sink)
            .and_then(move |_| Ok(()))
            .map_err(move |e| error!("when processing: {}", e));

        // Spawn both concurrently
        let mut rt = Runtime::new().unwrap();
        rt.spawn(file_reloader);
        rt.spawn(fut);
        rt.shutdown_on_idle()
            .wait().unwrap();
    } else {
        tokio::run(file_reloader);
    }
}

fn file_reloader(wasm_file: String, shared_state: SharedState, current_index: Arc<RwLock<Option<InstanceIndex>>>) -> impl Future<Item = (), Error = ()> {
    let last_modified = Mutex::new(None);
    Interval::new_interval(Duration::from_millis(500))
            .map_err(|_| io::ErrorKind::Other.into())
            .filter_map(move |_| {
                let metadata = std::fs::metadata(&wasm_file).unwrap();
                let time = metadata.modified().unwrap();
                let mut lock_guard = last_modified.lock();
                if lock_guard.is_none() || lock_guard.unwrap() != time {
                    info!("reloading {}", wasm_file);
                    *lock_guard = Some(time);
                    Some(wasm_file.clone())
                } else {
                    None
                }
            })
            .and_then(move |wasm_file| {
                let global_exports = Rc::new(RefCell::new(HashMap::new()));
                let data = read_to_end(wasm_file.clone().into()).unwrap();
                let shared_state = shared_state.clone();
                match shared_state.load(data, global_exports) {
                    Ok(index) => {
                        let scheduled = shared_state.invoke_start(index);
                        *current_index.write() = Some(index);
                        future::Either::A(scheduled)
                    },
                    Err(e) => {
                        error!("failed to reload {}: {:?}", wasm_file, e);
                        future::Either::B(future::ok(()))
                    },
                }
            })
            .for_each(move |_| Ok(()))
            .map_err(move |e| error!("when processing: {}", e))
}

fn runtime_context() -> Arc<Context> {
    let config = Arc::new(Config::default());
    let varz = Varz::default();
    let conductor = Conductor::new();
    let cache = Cache::new(&config, varz.clone());
    Context::new(config.clone(), conductor, cache, varz.clone())
}

fn read_to_end(path: PathBuf) -> Result<Vec<u8>, io::Error> {
    let mut buf: Vec<u8> = Vec::new();
    let mut file = std::fs::File::open(path)?;
    file.read_to_end(&mut buf)?;
    Ok(buf)
}
