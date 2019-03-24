//! Import all the required crates, instanciate the main components and start
//! the service.
#![recursion_limit = "128"]
#![feature(await_macro, async_await, futures_api, test, non_exhaustive)]
extern crate test;

mod cache;
mod codecs;
mod conductor;
mod config;
mod context;
pub mod error;
pub mod forwarder;
mod query_router;
pub mod recursor;
pub mod sandbox;
mod server;
mod test_utils;
mod tracing;
mod varz;

pub use crate::cache::*;
pub use crate::conductor::Conductor;
pub use crate::config::{Config, Listener};
pub use crate::context::*;
pub use crate::query_router::*;
pub use crate::server::*;
pub use crate::varz::Varz;
pub use crate::codecs::FramedStream;

pub const DNS_MAX_SIZE: usize = 65_535;
pub const DNS_MAX_TCP_SIZE: usize = 65_535;
pub const DNS_MAX_UDP_SIZE: usize = 4096;
pub const DNS_QUERY_MAX_SIZE: usize = 283;
pub const DNS_QUERY_MIN_SIZE: usize = 17;
pub const DNS_RESPONSE_MIN_SIZE: usize = 17;
pub const DNS_UDP_NOEDNS0_MAX_SIZE: u16 = 512;
pub const HEALTH_CHECK_MS: u64 = 10 * 1000;
pub const MAX_TCP_CLIENTS: usize = 1_000;
pub const MAX_TCP_HASH_DISTANCE: usize = 10;
pub const MAX_TCP_IDLE_MS: u64 = 10 * 1000;
pub const FAILURE_TTL: u32 = 30;
pub const TCP_BACKLOG: usize = 1024;
pub const UDP_BUFFER_SIZE: usize = 1024 * 1024;
pub const UPSTREAM_TOTAL_TIMEOUT_MS: u64 = 5 * 1000;
pub const UPSTREAM_QUERY_MIN_TIMEOUT_MS: u64 = 1000;
pub const UPSTREAM_QUERY_MAX_TIMEOUT_MS: u64 = UPSTREAM_TOTAL_TIMEOUT_MS * 3 / 4;
pub const UPSTREAM_QUERY_MAX_DEVIATION_COEFFICIENT: f64 = 4.0;
pub const UPSTREAM_PROBES_DELAY_MS: u64 = 1000;
pub const DEFAULT_GRACE_SEC: u64 = 86400;
