//! Import all the required crates, instanciate the main components and start
//! the service.
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(feature = "clippy", allow(identity_op, ptr_arg, collapsible_if, let_and_return))]
#![allow(dead_code, unused_imports, unused_variables)]
#![feature(await_macro, async_await, futures_api)]

#[cfg(feature = "jemalloc")]
use jemallocator;
#[cfg(feature = "jemalloc")]
#[global_allocator] static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[macro_use]
extern crate tokio;

mod c_abi;
mod cache;
// mod cli_listener;
mod client_query;
mod config;
mod errors;
mod ext_udp_listener;
mod globals;
mod hooks;
mod log_dnstap;
mod net_helpers;
mod query_router;
mod resolver_queries_handler;
mod resolver;
// mod tcp_acceptor;
// mod tcp_arbitrator;
mod udp_acceptor;
mod udp_stream;
mod upstream_server;
mod varz;
pub mod dns;

#[cfg(feature = "webservice")]
mod webservice;

use xfailure::xbail;
use log::{debug, info, warn};
use crate::cache::Cache;
// use crate::cli_listener::CLIListener;
pub use crate::config::Config;
use crate::hooks::Hooks;
use crate::log_dnstap::LogDNSTap;
use crate::net_helpers::*;
use parking_lot::RwLock;
use privdrop::PrivDrop;
use crate::resolver::*;
use crate::resolver_queries_handler::PendingQueries;
use std::io;
use std::net;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
// use crate::tcp_acceptor::*;
// use crate::tcp_arbitrator::TcpArbitrator;
use crate::udp_acceptor::*;
use tokio::prelude::*;
use tokio::runtime::{Runtime, Builder};
use crate::varz::*;
use prost_derive::*;

#[cfg(feature = "webservice")]
use crate::webservice::*;

const CLOCK_RESOLUTION: u64 = 100;
const DNS_MAX_SIZE: usize = 65_535;
const DNS_MAX_TCP_SIZE: usize = 65_535;
const DNS_MAX_UDP_SIZE: usize = 4096;
const DNS_QUERY_MAX_SIZE: usize = 283;
const DNS_QUERY_MIN_SIZE: usize = 17;
const DNS_RESPONSE_MIN_SIZE: usize = 17;
const DNS_UDP_NOEDNS0_MAX_SIZE: u16 = 512;
const HEALTH_CHECK_MS: u64 = 10 * 1000;
const MAX_EVENTS_PER_BATCH: usize = 1024;
const MAX_TCP_CLIENTS: usize = 1_000;
const MAX_TCP_HASH_DISTANCE: usize = 10;
const MAX_TCP_IDLE_MS: u64 = 10 * 1000;
const FAILURE_TTL: u32 = 30;
const TCP_BACKLOG: usize = 1024;
const UDP_BUFFER_SIZE: usize = 1024 * 1024;
const UPSTREAM_TOTAL_TIMEOUT_MS: u64 = 5 * 1000;
const UPSTREAM_QUERY_MIN_TIMEOUT_MS: u64 = 1 * 1000;
const UPSTREAM_QUERY_MAX_TIMEOUT_MS: u64 = UPSTREAM_TOTAL_TIMEOUT_MS * 3 / 4;
const UPSTREAM_QUERY_MAX_DEVIATION_COEFFICIENT: f64 = 4.0;
const UPSTREAM_PROBES_DELAY_MS: u64 = 1 * 1000;
const DEFAULT_GRACE_SEC: u64 = 86400;

#[cfg(feature = "webservice")]
const WEBSERVICE_THREADS: usize = 1;

pub struct EdgeDNSContext {
    pub config: Config,
    pub listen_addr: String,
    // pub tcp_listener: net::TcpListener,
    pub cache: Cache,
    pub varz: Varz,
    pub hooks_arc: Arc<RwLock<Hooks>>,
    // pub tcp_arbitrator: TcpArbitrator,
    pub dnstap_sender: Option<log_dnstap::Sender>,
    pub pending_queries: PendingQueries,
}

pub struct EdgeDNS;

impl EdgeDNS {
    #[cfg(feature = "webservice")]
    fn webservice_start(
        edgedns_context: &EdgeDNSContext,
        service_ready_tx: mpsc::SyncSender<u8>,
        rt: &mut Runtime,
    ) {
        WebService::spawn(edgedns_context, service_ready_tx, rt)
    }

    #[cfg(not(feature = "webservice"))]
    fn webservice_start(
        _edgedns_context: &EdgeDNSContext,
        _service_ready_tx: mpsc::SyncSender<u8>,
        _rt: &mut Runtime,
    ) {
        panic!("Support for metrics was not compiled in");
    }

    fn privileges_drop(config: &Config) {
        let mut changed = false;
        let mut pd = PrivDrop::default();
        if let Some(ref user) = config.user {
            pd = pd.user(user).unwrap();
            changed = true;
        }
        if let Some(ref group) = config.group {
            pd = pd.group(group).unwrap();
            changed = true;
        }
        if let Some(ref chroot_dir) = config.chroot_dir {
            pd = pd.chroot(chroot_dir);
            changed = true;
        }
        if changed {
            pd.apply().unwrap_or_else(|e| {
                panic!("Failed to drop privileges: {}", e)
            });
        }
    }

    pub fn new(config: &Config) -> EdgeDNS {
        let ct = coarsetime::Updater::new(CLOCK_RESOLUTION)
            .start()
            .expect("Unable to spawn the internal timer");
        let varz = varz::new();
        let hooks_basedir = config.hooks_basedir.as_ref().map(|x| x.as_str());
        let hooks_arc = Arc::new(RwLock::new(Hooks::new(hooks_basedir)));
        let cache = Cache::new(config.clone());
        // let tcp_listener =
        //     socket_tcp_bound(&config.listen_addr).expect("Unable to create a TCP client socket");
        let (log_dnstap, dnstap_sender) = if config.dnstap_enabled {
            let log_dnstap = LogDNSTap::new(config);
            let dnstap_sender = log_dnstap.sender();
            (Some(log_dnstap), Some(dnstap_sender))
        } else {
            (None, None)
        };
        let pending_queries = PendingQueries::default();
        // let tcp_arbitrator = TcpArbitrator::with_capacity(config.max_tcp_clients);
        let edgedns_context = EdgeDNSContext {
            config: config.clone(),
            listen_addr: config.listen_addr.to_owned(),
            // tcp_listener,
            cache,
            varz,
            hooks_arc,
            // tcp_arbitrator,
            dnstap_sender,
            pending_queries,
        };

        // build Runtime
        // let mut rt = Builder::new()
        //     .core_threads(config.udp_acceptor_threads + config.tcp_acceptor_threads + 1)
        //     .build()
        //     .unwrap();

        tokio::run_async( async move {

            let globals = Arc::new(await!(ResolverCore::spawn(&edgedns_context)).expect("Unable to spawn the resolver"));
            info!("Resolver ready");

            let (service_ready_tx, service_ready_rx) = mpsc::sync_channel::<u8>(1);
            
            await!(UdpAcceptorCore::spawn(
                globals.clone(),
                &edgedns_context,
                globals.resolver_tx.clone(),
                service_ready_tx.clone(),
            ));

            info!("UDP listeners ready");
        });

        // for _ in 0..config.tcp_acceptor_threads {
        //     let tcp_listener = TcpAcceptorCore::spawn(
        //         globals.clone(),
        //         &edgedns_context,
        //         globals.resolver_tx.clone(),
        //         service_ready_tx.clone(),
        //         &mut rt,
        //     ).expect("Unable to spawn a TCP listener");
        //     service_ready_rx.recv().unwrap();
        // }
        // info!("TCP listeners ready {:?}", config.tcp_acceptor_threads);

        // if config.webservice_enabled {
        //     Self::webservice_start(&edgedns_context, service_ready_tx.clone(), &mut rt);
        //     service_ready_rx.recv().unwrap();
        // }
        // if let (&Some(ref _hooks_basedir), &Some(ref hooks_socket_path)) =
        //     (&config.hooks_basedir, &config.hooks_socket_path)
        // {
        //     let cli_listener = CLIListener::new(
        //         hooks_socket_path.to_string(),
        //         Arc::clone(&edgedns_context.hooks_arc),
        //     );
        //     cli_listener.spawn(&mut rt);
        // };

        Self::privileges_drop(&config.clone());
        
        log_dnstap.map(|mut x| x.start());
        info!("EdgeDNS is ready to process requests");
        
        // Wait until the runtime becomes idle and shut it down.
        // rt.shutdown_on_idle()
        //     .wait().unwrap();

        ct.stop().unwrap();
        EdgeDNS
    }
}
