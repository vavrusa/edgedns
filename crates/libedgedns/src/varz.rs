//! Metrics
//!
//! Varz are updated by pretty much all components, using only two
//! operations: set() and inc().

use coarsetime::Instant;
use prometheus::*;
use std::sync::Arc;

pub struct StartInstant(pub Instant);

pub struct Inner {
    pub start_instant: StartInstant,
    pub uptime: Gauge,
    pub cache_frequent_len: Gauge,
    pub cache_recent_len: Gauge,
    pub cache_test_len: Gauge,
    pub cache_inserted: Gauge,
    pub cache_evicted: Gauge,
    pub client_queries: Gauge,
    pub client_queries_udp: Counter,
    pub client_queries_tcp: Counter,
    pub client_queries_cached: Counter,
    pub client_queries_expired: Counter,
    pub client_queries_offline: Counter,
    pub client_queries_errors: Counter,
    pub inflight_queries: Gauge,
    pub upstream_errors: Counter,
    pub upstream_sent: Counter,
    pub upstream_received: Counter,
    pub upstream_timeout: Counter,
    pub upstream_reused: Counter,
    pub upstream_rtt: Histogram,
    pub upstream_response_sizes: Histogram,
}

pub type Varz = Arc<Inner>;

impl Inner {
    pub fn new() -> Inner {
        Inner {
            start_instant: StartInstant::default(),
            uptime: register_gauge!(opts!(
                "edgedns_uptime",
                "Uptime",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            cache_frequent_len: register_gauge!(opts!(
                "edgedns_cache_frequent_len",
                "Number of entries in the cached set of \
                 frequent items",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            cache_recent_len: register_gauge!(opts!(
                "edgedns_cache_recent_len",
                "Number of entries in the cached set of \
                 recent items",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            cache_test_len: register_gauge!(opts!(
                "edgedns_cache_test_len",
                "Number of entries in the cached set of \
                 staged items",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            cache_inserted: register_gauge!(opts!(
                "edgedns_cache_inserted",
                "Number of entries added to the cache",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            cache_evicted: register_gauge!(opts!(
                "edgedns_cache_evicted",
                "Number of entries evicted from the cache",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries: register_gauge!(opts!(
                "edgedns_client_queries",
                "Number of client queries received",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_udp: register_counter!(opts!(
                "edgedns_client_queries_udp",
                "Number of client queries received \
                 using UDP",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_tcp: register_counter!(opts!(
                "edgedns_client_queries_tcp",
                "Number of client queries received \
                 using TCP",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_cached: register_counter!(opts!(
                "edgedns_client_queries_cached",
                "Number of client queries sent from \
                 the cache",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_expired: register_counter!(opts!(
                "edgedns_client_queries_expired",
                "Number of expired client queries",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_offline: register_counter!(opts!(
                "edgedns_client_queries_offline",
                "Number of client queries answered \
                 while upstream resolvers are \
                 unresponsive",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_errors: register_counter!(opts!(
                "edgedns_client_queries_errors",
                "Number of bogus client queries",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            inflight_queries: register_gauge!(opts!(
                "edgedns_inflight_queries",
                "Number of queries currently waiting for a response",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            upstream_errors: register_counter!(opts!(
                "edgedns_upstream_errors",
                "Number of bogus upstream servers responses",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            upstream_sent: register_counter!(opts!(
                "edgedns_upstream_sent",
                "Number of upstream servers queries sent",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            upstream_received: register_counter!(opts!(
                "edgedns_upstream_received",
                "Number of upstream servers responses received",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            upstream_timeout: register_counter!(opts!(
                "edgedns_upstream_timeout",
                "Number of upstream servers responses \
                 having timed out",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            upstream_reused: register_counter!(opts!(
                "edgedns_upstream_reused",
                "Number queries reusing the same connection",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            upstream_rtt: register_histogram!(histogram_opts!(
                "edgedns_upstream_rtt",
                "Upstream response RTT in seconds",
                vec![0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1., 1.5, 2., 4., 5., 10.]
            ))
            .unwrap(),
            upstream_response_sizes: register_histogram!(histogram_opts!(
                "edgedns_upstream_response_sizes",
                "Upstream response size in bytes",
                vec![64.0, 128.0, 192.0, 256.0, 512.0, 1024.0, 2048.0]
            ))
            .unwrap(),
        }
    }

    /// Update server uptime metric.
    pub fn update_uptime(&self) {
        let StartInstant(start_instant) = self.start_instant;
        let uptime = start_instant.elapsed().as_secs();
        self.uptime.set(uptime as f64);
    }
}

impl Default for Inner {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for StartInstant {
    fn default() -> StartInstant {
        StartInstant(Instant::now())
    }
}
