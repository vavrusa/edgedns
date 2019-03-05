use crate::cache::CacheKey;
use crate::codecs::*;
use crate::config::Config;
use crate::query_router::Scope;
use crate::tracing;
use crate::varz;
use clockpro_cache::*;
use domain_core::bits::*;
use futures::future::Either;
use futures::stream::Stream;
use futures::sync::{mpsc, oneshot};
use lazy_static::lazy_static;
use log::*;
use native_tls;
use parking_lot::RwLock;
use socket2::{Domain, Socket, Type};
use std::cmp;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write;
use std::io::{Error as IoError, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Add;
use std::slice::Iter;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{tcp, TcpStream, UdpSocket};
use tokio::prelude::*;
use tokio::reactor::Handle;
use tokio::timer::Delay;
use tokio_tls;

/// IANA reserved port for DNS over TLS.
const DNS_OVER_TLS_PORT: u16 = 853;
/// Extra allowed time for each try to account for variability;
const DEFAULT_EXCHANGE_EXTRA: Duration = Duration::from_millis(50);
/// Default retry interval for a single message exchange
const DEFAULT_EXCHANGE_RETRY: Duration = Duration::from_millis(250);
/// Default connection concurrency (number of outstanding requests for single connection)
const DEFAULT_CONNECTION_CONCURRENCY: usize = 1000;
/// Default number of tracked connections.
const DEFAULT_CONNECTIONS_TRACKED: usize = 100_000;
/// Default keepalive interval for idle connections
const DEFAULT_KEEPALIVE: Duration = Duration::from_millis(10_000);

lazy_static! {
    static ref UNBOUND_IPV4: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    static ref UNBOUND_IPV6: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
}

/// Origin trait provides and interface to return a selection addresses for conductor.
/// The implementations of the trait define the order and size of the slice
/// for each request.
pub trait Origin: Send + Sync {
    /// Returns an optional origin name.
    fn name(&self) -> &str {
        "origin"
    }

    /// Returns a selection of addresses for next request.
    fn get(&self) -> &[SocketAddr];

    /// Returns a selection of addresses for given scope.
    fn get_scoped(&self, _scope: &Scope, _timetable: &Timetable) -> Vec<SocketAddr> {
        self.get().to_vec()
    }

    /// Convenience function to return an iterator over addresses.
    fn iter(&self) -> Iter<SocketAddr> {
        self.get().iter()
    }

    /// Convenience function to return next selected address.
    fn choose(&self, _scope: &Scope) -> Option<&SocketAddr> {
        self.get().first()
    }
}

/// The conductor schedules outgoing queries identified by message, and an origin.
/// It doesn't implement any specific outgoing connection protocol, and is used to provide
/// basic facilities for specialized conductor implementations.
#[derive(Clone)]
pub struct Conductor {
    timetable: Timetable,
    exchanger: Arc<Exchanger>,
}

impl Conductor {
    /// Create a new constructor instance with default configuration values.
    pub fn new() -> Arc<Self> {
        Arc::new(Builder::default().build())
    }

    /// Resolve a query with given origin, and wait for response.
    pub fn resolve(
        &self,
        scope: &Scope,
        query: Message,
        origin: Arc<Origin>,
    ) -> impl Future<Item = (Message, SocketAddr), Error = IoError> {
        // If the query is already being solved, register a waitable future
        let key = CacheKey::from(&query);

        // Retry until a query is either started or enqueued
        loop {
            // First query creates a queue for other same queries
            if let Some(pending) = self.timetable.start_query(scope, &key) {
                debug!("starting query '{}'", key);
                return Either::A(
                    self.exchanger
                        .exchange(scope, query, origin, &pending)
                        // Clear the pending query on exchange errors
                        .and_then(move |(msg, from)| {
                            pending.finish(&msg, &from);
                            Ok((msg, from))
                        }),
                );
            } else {
                // Create a waitable future for the query result
                trace!("enqueueing query '{}'", key);
                let (tx, rx) = oneshot::channel();
                let wait_response = rx
                    .map_err(|_| {
                        IoError::new(ErrorKind::UnexpectedEof, "cannot receive a query response")
                    })
                    .into_future();

                if !self.timetable.enqueue_query(&key, tx) {
                    continue;
                }

                // Enqueue to an already pending query
                return Either::B(wait_response);
            }
        }
    }

    /// Format a table of pending queries.
    pub fn pending_queries(&self, f: &mut String) {
        let pending_guard = self.timetable.pending.inner.write();
        for (key, ticket_list) in &*pending_guard {
            writeln!(f, "{}\t{} waiting", key, ticket_list.len()).unwrap();
        }
    }
}

/// Future result of the [`Exchanger`].
type ExchangeFuture = Box<Future<Item = (Message, SocketAddr), Error = IoError> + Send>;

/// Exchanger trait provides an interface for performing message exchanges.
trait Exchanger: Send + Sync {
    fn exchange(
        &self,
        scope: &Scope,
        query: Message,
        origin: Arc<Origin>,
        pending: &PendingQuery,
    ) -> ExchangeFuture;
}

/// Structure for conductor bookkeeping, it tracks pending queries and open connections.
#[derive(Clone)]
pub struct Timetable {
    pending: Arc<PendingQueries>,
    connections: Option<Arc<EstablishedConnections>>,
    metrics: Arc<ConnectionMetrics>,
}

impl Timetable {
    /// Register a query identified by `key` as pending, and add `sink` to the queue of waiting futures.
    /// Note: The function returns a handle that closes when the pending query when it goes out of scope.
    fn start_query(&self, scope: &Scope, key: &CacheKey) -> Option<PendingQuery> {
        if self.pending.start(&key) {
            Some(PendingQuery::new(key.clone(), self.pending.clone(), scope))
        } else {
            None
        }
    }

    /// Enqueue waiting query for an already start query.
    fn enqueue_query(&self, key: &CacheKey, sink: ResponseSender) -> bool {
        self.pending.enqueue(key, sink)
    }

    /// Update counters and RTT for an open connection.
    fn update_rtt(&self, address: &SocketAddr, rtt: Duration) {
        self.metrics.update_rtt(address, rtt);
    }

    /// Return connection metrics for given address.
    pub fn get_metrics(&self, address: &SocketAddr) -> Option<ConnectionTracker> {
        match self.metrics.inner.write().get(address) {
            Some(c) => Some(c.clone()),
            None => None,
        }
    }

    /// Returns an open connection for an address from the given list (if exists).
    pub fn contains_open_connection(&self, address: &SocketAddr) -> bool {
        match self.connections {
            Some(ref connections) => connections.write().get(address).is_some(),
            None => false,
        }
    }

    /// Returns an open connection reference if exists.
    fn get_open_connection(&self, address: &SocketAddr) -> Option<ConnectionSender> {
        match self.connections {
            Some(ref connections) => connections.write().get(address).cloned(),
            None => None,
        }
    }

    /// Add an open connection to the timetable.
    fn add_open_connection(&self, address: SocketAddr, sink: ConnectionSender) -> bool {
        if let Some(ref connections) = self.connections {
            // Check if there's an already open connection
            let mut connections = connections.write();
            if connections.get_mut(&address).is_none() {
                // Insert a new connection tracker if not exists
                return connections.insert(address, sink);
            }
        }

        // There's an already open connection for this endpoint
        false
    }

    /// Removes an open connection for given address from the timetable.
    fn remove_open_connection(&self, address: &SocketAddr) -> Option<ConnectionSender> {
        match self.connections {
            Some(ref connections) => connections.write().remove(address),
            None => None,
        }
    }
}

/// Reference for a single pending query.
/// It clears itself from context on drop.
struct PendingQuery {
    context: Arc<PendingQueries>,
    key: Option<CacheKey>,
    _timer: prometheus::HistogramTimer,
    trace_span: Option<tracing::Span>,
}

impl PendingQuery {
    fn new(key: CacheKey, context: Arc<PendingQueries>, scope: &Scope) -> Self {
        let varz = varz::current();
        varz.upstream_inflight_queries.inc();
        let _timer = varz.upstream_rtt.start_timer();
        let trace_span = match scope.trace_span {
            Some(ref span) => Some(
                span.new_child()
                    .with_name("upstream-query")
                    .with_tag("dns.query", &format!("{}", key)),
            ),
            None => None,
        };

        Self {
            context,
            key: Some(key),
            _timer,
            trace_span,
        }
    }

    // Finish enqueued queries waiting for this response.
    fn finish(mut self, resp: &Message, peer_addr: &SocketAddr) {
        if let Some(key) = self.key.take() {
            trace!("finishing pending query '{}'", key);
            self.context.finish(&key, resp, peer_addr);
            let varz = varz::current();
            varz.upstream_response_sizes.observe(resp.len() as f64);
            varz.upstream_received.inc();
        }
        drop(self);
    }
}

impl Drop for PendingQuery {
    fn drop(&mut self) {
        let varz = varz::current();
        varz.upstream_inflight_queries.dec();
        if let Some(key) = self.key.take() {
            trace!("closing pending query '{}' without response", key);
            varz.upstream_timeout.inc();
            self.context.clear(&key);
        }
    }
}

/// Structure tracks pending queries represented by [`CacheKey`] to a queue of waiting futures.
/// The primary purpose is coalescing of outbound queries over the same circuit.
#[derive(Default)]
struct PendingQueries {
    max_clients_waiting: usize,
    inner: RwLock<HashMap<CacheKey, VecDeque<ResponseSender>>>,
}

impl PendingQueries {
    /// Create a map of pending queries with limited number of clients waiting for a query.
    pub fn new(max_clients_waiting: usize) -> Self {
        let mut item = Self::default();
        item.max_clients_waiting = max_clients_waiting;
        item
    }

    /// Register a query identified by `key` as pending, and add `sink` to the queue of waiting futures.
    pub fn start(&self, key: &CacheKey) -> bool {
        let mut locked = self.inner.write();
        match locked.entry(key.clone()) {
            Occupied(_) => false,
            Vacant(entry) => {
                entry.insert(VecDeque::new());
                true
            }
        }
    }

    /// Enqueue a query in a queue of same queries waiting for response.
    pub fn enqueue(&self, key: &CacheKey, sink: ResponseSender) -> bool {
        let mut locked = self.inner.write();
        match locked.get_mut(&key) {
            Some(v) => {
                // If the queue is longer than the maximum of clients waiting, recycle an oldest waiting client
                // The oldest waiting client is at the position 1 (the client executing the query is on position 0)
                if self.max_clients_waiting > 0 && v.len() >= self.max_clients_waiting {
                    v.pop_front();
                }
                v.push_back(sink);
                true
            }
            // Pending query closed before enqueuing, caller must retry
            None => false,
        }
    }

    /// Send the message to the queue of futures waiting for completion, and clear the message from the wait list.
    pub fn finish(&self, key: &CacheKey, resp: &Message, peer_addr: &SocketAddr) -> usize {
        let mut locked = self.inner.write();
        match locked.remove(&key) {
            Some(sinks) => {
                let len = sinks.len();
                for sink in sinks {
                    drop(sink.send((resp.clone(), *peer_addr)));
                }
                len
            }
            None => {
                info!("unexpected response for '{}'", key);
                0
            }
        }
    }

    /// Clear a pending query that could not be resolved into a response.
    pub fn clear(&self, key: &CacheKey) -> bool {
        let mut locked = self.inner.write();
        locked.remove(&key).is_some()
    }
}

/// MPSC sink to an established connection.
type ResponseSender = oneshot::Sender<(Message, SocketAddr)>;
type ConnectionSender = mpsc::Sender<(Message, ResponseSender)>;
type ConnectionReceiver = mpsc::Receiver<(Message, ResponseSender)>;

/// Maps addresses of established connections to their message queues (sinks).
type EstablishedConnections = RwLock<ClockProCache<SocketAddr, ConnectionSender>>;

/// Metrics for a connection (query stream) to a single upstream address.
#[derive(Clone)]
pub struct ConnectionTracker {
    messages: u64,
    total_rtt: u64,
}

impl ConnectionTracker {
    fn new(rtt: Duration) -> Self {
        Self {
            messages: 1,
            total_rtt: Self::round_to_millis(rtt),
        }
    }

    /// Çalculate mean RTT from observed messages.
    fn mean_rtt(&self) -> Duration {
        Duration::from_millis(self.total_rtt / self.messages)
    }

    /// Update connection tracker message count and
    fn update(&mut self, rtt: Duration) {
        self.messages += 1;
        self.total_rtt += Self::round_to_millis(rtt);
    }

    /// Round duration to milliseconds and cap at 30 seconds.
    fn round_to_millis(d: Duration) -> u64 {
        cmp::min(d.as_secs(), 30) * 1000 + u64::from(d.subsec_millis())
    }
}

/// Infrastructure cache tracks latency and QoS for upstream connections (query streams).
struct ConnectionMetrics {
    inner: RwLock<ClockProCache<SocketAddr, ConnectionTracker>>,
}

impl ConnectionMetrics {
    fn new(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(ClockProCache::new(capacity).expect("created cache")),
        }
    }

    fn update_rtt(&self, address: &SocketAddr, rtt: Duration) {
        trace!("upstream {:?} responded in {:?}", address, rtt);
        let mut inner = self.inner.write();
        match inner.get_mut(address) {
            Some(metrics) => metrics.update(rtt),
            None => {
                inner.insert(*address, ConnectionTracker::new(rtt));
            }
        }
    }
}

/// General purpose that supports opportunistic connection reuse and aggressive retries.
struct AnyExchanger {
    timetable: Timetable,
    connection_reuse: bool,
    connection_concurrency: usize,
}

impl Exchanger for AnyExchanger {
    fn exchange(
        &self,
        scope: &Scope,
        query: Message,
        origin: Arc<Origin>,
        pending: &PendingQuery,
    ) -> ExchangeFuture {
        let selection = origin.get_scoped(scope, &self.timetable);
        let tries = cmp::min(selection.len(), 2);
        let default_expected_rtt = DEFAULT_EXCHANGE_RETRY;
        let mut retries = Retransmitter::new();
        for addr in selection.iter().cycle().take(tries) {
            // Estimate expected RTT + extra time to account for variability
            let expected_rtt = match self.timetable.get_metrics(addr) {
                Some(metrics) => cmp::min(
                    metrics.mean_rtt().add(DEFAULT_EXCHANGE_EXTRA),
                    default_expected_rtt,
                ),
                None => default_expected_rtt,
            };

            // Schedule a try for current address
            let (addr, query, origin) = (addr.to_owned(), query.clone(), origin.clone());
            let timetable = self.timetable.clone();
            let span = pending.trace_span.clone();
            let exchange = future::lazy(move || {
                // Trace the individual subrequest
                let instant = Instant::now();
                // Try to reuse an already open connection
                match timetable.get_open_connection(&addr) {
                    Some(sender) => {
                        trace!("reusing connection to to {:?}", addr);
                        let span = trace_span_new(&span, "reused-exchange", origin.name(), &addr);
                        let try_reuse = exchange_with_open_connection(sender, query.clone())
                            .and_then(move |(message, peer_addr)| {
                                trace_span_close(span, &message);
                                // Update response RTT
                                timetable.update_rtt(&peer_addr, instant.elapsed());
                                varz::current().upstream_reused.inc();
                                Ok((message, peer_addr, None))
                            });

                        Either::A(try_reuse)
                    }
                    None => {
                        let try_send = match addr.port() {
                            DNS_OVER_TLS_PORT => {
                                trace!("sending message to {:?} with TLS", addr);
                                let span =
                                    trace_span_new(&span, "tls-exchange", origin.name(), &addr);
                                Either::A(
                                    exchange_with_tls(addr, query.clone(), addr.ip().to_string())
                                        .then(move |res| {
                                            trace_finish(timetable, span, instant, res)
                                        }),
                                )
                            }
                            _ => {
                                trace!("sending message to {:?} with UDP", addr);
                                let span =
                                    trace_span_new(&span, "udp-exchange", origin.name(), &addr);
                                Either::B(exchange_with_udp(addr, query.clone()).and_then(
                                    move |(message, (addr, query))| {
                                        // Update response RTT
                                        timetable.update_rtt(&addr, instant.elapsed());
                                        // Retry with TCP on truncation, otherwise finish.
                                        if !message.header().tc() {
                                            Either::A(future::ok((message, addr, None)))
                                        } else {
                                            let instant = Instant::now();
                                            let span = span.and_then(|s| {
                                                Some(s.next_span().with_name("tcp-exchange"))
                                            });
                                            Either::B(exchange_with_tcp(addr, query).then(
                                                move |res| {
                                                    trace_finish(timetable, span, instant, res)
                                                },
                                            ))
                                        }
                                    },
                                ))
                            }
                        };

                        Either::B(try_send)
                    }
                }
            });

            retries.schedule(Box::new(exchange), expected_rtt);
        }

        let timetable = self.timetable.clone();
        let enable_connection_reuse = self.connection_reuse;
        let connection_concurrency = self.connection_concurrency;

        Box::new(
            retries
                .into_future()
                .map(move |(message, addr, maybe_stream)| {
                    // Save connection if connection reuse is enabled
                    if let Some(mut stream) = maybe_stream {
                        if enable_connection_reuse {
                            // Save connection in pending queue
                            let (sender, receiver) = mpsc::channel(100);
                            if timetable.add_open_connection(addr, sender) {
                                tokio::spawn(keep_open_connection(
                                    timetable,
                                    stream,
                                    receiver,
                                    addr,
                                    connection_concurrency,
                                ));
                            }
                        // Close connection as early as possible if not
                        } else if let Err(e) = stream.close() {
                            warn!("error when closing connection {:?}", e);
                        }
                    }
                    (message, addr)
                }),
        )
    }
}

/// Dummy exchanger that mirrors the query back
struct NoopExchanger {
    timetable: Timetable,
}

impl Exchanger for NoopExchanger {
    fn exchange(
        &self,
        scope: &Scope,
        query: Message,
        origin: Arc<Origin>,
        _pending: &PendingQuery,
    ) -> ExchangeFuture {
        let selection = origin.get_scoped(scope, &self.timetable);
        if let Some(addr) = selection.first() {
            Box::new(future::ok((query, *addr)))
        } else {
            Box::new(future::err(ErrorKind::NotFound.into()))
        }
    }
}

/// Builder interface for creating a Conductor instance
pub struct Builder {
    enable_tcp: bool,
    enable_udp: bool,
    connection_concurrency: usize,
    max_active_queries: usize,
    max_clients_waiting_for_query: usize,
    max_keepalive_connections: usize,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            enable_tcp: true,
            enable_udp: true,
            connection_concurrency: DEFAULT_CONNECTION_CONCURRENCY,
            max_active_queries: 0,
            max_clients_waiting_for_query: 0,
            max_keepalive_connections: DEFAULT_CONNECTION_CONCURRENCY / 2,
        }
    }
}

impl Builder {
    /// Build conductor with support for UDP.
    #[allow(dead_code)]
    pub fn with_udp(mut self, value: bool) -> Self {
        self.enable_udp = value;
        self
    }

    /// Build conductor with support for TCP.
    #[allow(dead_code)]
    pub fn with_tcp(mut self, value: bool) -> Self {
        self.enable_tcp = value;
        self
    }

    /// Use defined queue size (default is [`DEFAULT_CONNECTION_CONCURRENCY`]).
    #[allow(dead_code)]
    pub fn with_connection_concurrency(mut self, value: usize) -> Self {
        self.connection_concurrency = value;
        self
    }

    /// Set maximum number of upstream connections (default is 500).
    /// When set to 0, it disables connection reuse as no upstream connection could be kept open.
    pub fn with_max_keepalive_connections(mut self, value: usize) -> Self {
        self.max_keepalive_connections = value;
        self
    }

    /// Set maximum number of inflight queries (default is 0 = unlimited).
    pub fn with_max_active_queries(mut self, value: usize) -> Self {
        self.max_active_queries = value;
        self
    }

    /// Set maximum number of clients waiting for a response to the same query (default is 0 = unlimited).
    pub fn with_max_clients_waiting_for_query(mut self, value: usize) -> Self {
        self.max_clients_waiting_for_query = value;
        self
    }

    /// Convert the Builder into the Recursor with defined configuration.
    pub fn build(self) -> Conductor {
        let connection_reuse = self.max_keepalive_connections >= 3;
        let connections = if connection_reuse {
            Some(Arc::new(RwLock::new(
                ClockProCache::new(self.max_keepalive_connections).expect("connection cache"),
            )))
        } else {
            None
        };

        let timetable = Timetable {
            pending: Arc::new(PendingQueries::new(self.max_clients_waiting_for_query)),
            connections,
            metrics: Arc::new(ConnectionMetrics::new(DEFAULT_CONNECTIONS_TRACKED)),
        };

        let exchanger: Arc<Exchanger> = if self.enable_udp || self.enable_tcp {
            Arc::new(AnyExchanger {
                timetable: timetable.clone(),
                connection_reuse,
                connection_concurrency: self.connection_concurrency,
            })
        } else {
            Arc::new(NoopExchanger {
                timetable: timetable.clone(),
            })
        };

        Conductor {
            timetable,
            exchanger,
        }
    }
}

/// Build from configuration pattern
impl From<&Arc<Config>> for Conductor {
    fn from(config: &Arc<Config>) -> Self {
        Builder::default()
            .with_max_active_queries(config.max_active_queries)
            .with_max_clients_waiting_for_query(config.max_clients_waiting_for_query)
            .with_max_keepalive_connections(config.max_upstream_connections)
            .build()
    }
}

/// FIFO queue of waiting queries roughly sorted by the time of insertion.
#[derive(Default, Clone)]
struct PendingQueue {
    inner: Arc<RwLock<VecDeque<(CacheKey, ResponseSender)>>>,
}

impl PendingQueue {
    /// Returns the queue length.
    fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Pushes a new query into the queue.
    fn push(&self, key: CacheKey, sink: ResponseSender) {
        let mut pending = self.inner.write();
        pending.push_back((key, sink));
    }

    /// Removes a query from the queue and returns its sender.
    fn remove(&self, key: &CacheKey) -> Option<(CacheKey, ResponseSender)> {
        let mut pending = self.inner.write();
        // The queries are in a FIFO, so assume the responses are coming in order
        // as well, starting from the oldest one.
        let mut i = 0;
        let mut end = pending.len();
        while i < end {
            let entry = &pending[i];
            // This is the query we're looking for
            if &entry.0 == key {
                return pending.swap_remove_front(i);
            }
            // This is a query older than we're looking for, and canceled, sweep it
            if entry.1.is_canceled() {
                // Swap with an entry from the front of the queue.
                // We've already inspected this entry, so we don't have to move iterator.
                pending.swap_remove_front(i);
                end -= 1;
            }
            // Inspect next entry
            i += 1;
        }

        None
    }
}

/// Any boxed `ExchangeFuture` (either stream or stream-less).
type ExchangeFutureExt =
    Box<dyn Future<Item = (Message, SocketAddr, Option<FramedStream>), Error = IoError> + Send>;

/// Retransmitter has a queue of scheduled tries, and executes them based on the expected RTT.Add
///
/// Each nameserver tries to lookup expected RTT based on past tries,
/// if there's no previous information stored, it will use a fixed delay for the expected RTT.
/// The tries are staged as follows:
///
/// Start                                                   Timeout
/// -> Q1.....Q2..............Q3......Q4....................]
///         ^               ^       ^
///         Q1: Expected RTT|       |
///                         | Q2: Expected RTT
///                                 | Q3: Expected RTT
///           ^
///           Start Q2
///                            ^ Start Q3
///                                   ^ Start Q4
struct Retransmitter {
    timeout: Option<Delay>,
    scheduled: VecDeque<(ExchangeFutureExt, Duration)>,
    pending: Vec<ExchangeFutureExt>,
}

impl Retransmitter {
    /// Create a new retransmitter.
    fn new() -> Self {
        Self {
            timeout: None,
            scheduled: VecDeque::new(),
            pending: Vec::new(),
        }
    }

    /// Schedule an exchange operation with an expected grace period.
    fn schedule(&mut self, retry: ExchangeFutureExt, timeout: Duration) {
        self.scheduled.push_back((retry, timeout));
    }
}

impl Future for Retransmitter {
    type Item = (Message, SocketAddr, Option<FramedStream>);
    type Error = IoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut schedule_next = false;
        loop {
            // Find a first ready or errored retry
            let first_ready = self
                .pending
                .iter_mut()
                .enumerate()
                .filter_map(|(i, f)| match f.poll() {
                    Ok(Async::NotReady) => None,
                    Ok(Async::Ready(item)) => Some((i, Ok(item))),
                    Err(e) => Some((i, Err(e))),
                })
                .next();

            if let Some((id, res)) = first_ready {
                // Finish if some future is ready
                if let Ok(item) = res {
                    return Ok(Async::Ready(item));
                }
                // Schedule next retry if the last (most recent) errored
                if let Err(e) = res {
                    debug!("retransmit {} future error: {:?}", id, e);
                    if id == self.pending.len() - 1 {
                        schedule_next = true;
                    }
                }
                drop(self.pending.remove(id));
            } else {
                // No retry is ready, continue with scheduling
                break;
            }
        }

        // Check if we can start a next scheduled retry
        let schedule_next = schedule_next
            || match self.timeout {
                Some(ref mut t) => t.poll().ok().map(|r| r.is_ready()).unwrap_or(false),
                None => !self.scheduled.is_empty(),
            };

        // Start the next try if necessary
        if schedule_next {
            if let Some((fut, timeout)) = self.scheduled.pop_front() {
                trace!(
                    "retransmit scheduling {}, grace period {:?}",
                    self.pending.len(),
                    timeout
                );
                self.pending.push(fut);
                let instant = Instant::now().add(timeout);
                if let Some(ref mut delay) = self.timeout {
                    delay.reset(instant);
                } else {
                    self.timeout = Some(Delay::new(instant));
                }
                // We pushed a new retry, so we must poll again
                return self.poll();
            } else {
                self.timeout = None;
            }
        }

        Ok(Async::NotReady)
    }
}

/// Create a new trace span for message exchange.
fn trace_span_new(
    parent: &Option<tracing::Span>,
    name: &str,
    service: &str,
    addr: &SocketAddr,
) -> Option<tracing::Span> {
    match parent {
        Some(ref span) => Some(
            span.new_child()
                .with_name(name)
                .with_remote_endpoint(&service, *addr),
        ),
        None => None,
    }
}

/// Close a trace span with response.
fn trace_span_close(mut span: Option<tracing::Span>, msg: &Message) {
    if let Some(ref mut span) = span {
        span.tag("dns.rcode", &format!("{}", msg.header().rcode()));
    }
}

/// Close a trace span with an error.
fn trace_span_close_err(mut span: Option<tracing::Span>, err: &IoError) {
    if let Some(ref mut span) = span {
        span.tag("error", "true");
        span.tag("error.message", &err.to_string());
    }
}

fn trace_finish(
    timetable: Timetable,
    span: Option<tracing::Span>,
    instant: Instant,
    res: Result<(Message, SocketAddr, Option<FramedStream>), IoError>,
) -> Result<(Message, SocketAddr, Option<FramedStream>), IoError> {
    match res {
        Ok((message, addr, maybe_stream)) => {
            trace_span_close(span, &message);
            timetable.update_rtt(&addr, instant.elapsed());
            Ok((message, addr, maybe_stream))
        }
        Err(e) => {
            trace_span_close_err(span, &e);
            Err(e)
        }
    }
}

/// Returns a future that manages an open connection in the background.
/// It registers the open connection in the provided structure, and keeps the
/// connection open for [`DEFAULT_KEEPALIVE`] duration. After that it closes the
/// connection, and unregisters it from the structure.
///
/// The `concurrency` limits the number of in-flight queries for the connection.
fn keep_open_connection(
    timetable: Timetable,
    stream: FramedStream,
    receiver: ConnectionReceiver,
    peer_addr: SocketAddr,
    concurrency: usize,
) -> impl Future<Item = (), Error = ()> {
    // Create a token bucket with channel to limit concurrency of the connection
    // In order to start new queries, there must be a token in the channel.
    // When a query is completed, it returns tokens into the channel.
    let (token_sender, token_reader) = mpsc::channel(concurrency);
    let replenish_tokens = token_sender
        .clone()
        .send_all(stream::repeat::<(), mpsc::SendError<_>>(()).take(concurrency as u64))
        .then(move |_| Ok(()));

    // Process inbound queries and send them into the open connection.
    // Each sent message registers a slot in the queue, so it can be matched with response later.
    let pending = PendingQueue::default();
    let (sink, stream) = stream.split();
    let sender_future = {
        let pending = pending.clone();
        receiver
            .zip(token_reader)
            .filter_map(move |((msg, sink), _)| {
                let key = CacheKey::from(&msg);
                debug!("reused connection, forwarding message '{}'", key);
                // Make sure there's no more  earliest waiting query from the queue
                if pending.len() < concurrency {
                    pending.push(key, sink);
                    Some(msg.as_bytes().clone())
                } else {
                    None
                }
            })
            .map_err(move |_| ErrorKind::BrokenPipe.into())
            .fold(sink, move |sink, msg| sink.send((msg, peer_addr)))
            .then(move |_: Result<_, IoError>| Ok::<_, ()>(()))
    };

    // Spawn background message reader
    let receiver_future = {
        stream
            .timeout(DEFAULT_KEEPALIVE / 2)
            .map_err(move |_e| ErrorKind::TimedOut.into())
            .for_each(move |(resp, peer_addr)| {
                // Parse response and attempt to close pending queries
                let tokens = if let Ok(msg) = Message::from_bytes(resp.into()) {
                    let key = CacheKey::from(&msg);
                    debug!("reused connection, received response '{}'", key);
                    if let Some((_, sink)) = pending.remove(&key) {
                        drop(sink.send((msg, peer_addr)));
                    }
                    1
                } else {
                    debug!("reused connection, received invalid response");
                    0
                };

                // Return tokens to token bucket when closing in-flight queries
                token_sender
                    .clone()
                    .send_all(stream::repeat::<_, mpsc::SendError<_>>(()).take(tokens as u64))
                    .then(move |_| Ok::<_, IoError>(()))
            })
            .then(move |_| {
                info!("reused connection, closing for {}", peer_addr);
                timetable.remove_open_connection(&peer_addr);
                Ok(())
            })
    };

    info!("keepalive connection for {}", peer_addr);
    replenish_tokens
        .join(sender_future)
        .join(receiver_future)
        .map(|_| ())
}

/// Returns a future that tries to perform a message exchange over an established connection.
fn exchange_with_open_connection(
    sender: ConnectionSender,
    query: Message,
) -> impl Future<Item = (Message, SocketAddr), Error = IoError> {
    let (tx, rx) = oneshot::channel();
    sender
        .send((query, tx))
        .map_err(move |e| {
            debug!("failed to send over reused connection: {}", e);
            ErrorKind::BrokenPipe.into()
        })
        .and_then(move |_| {
            rx.into_future().map_err(move |e| {
                debug!("failed to receive from a reused connection: {}", e);
                ErrorKind::BrokenPipe.into()
            })
        })
}

/// Returns a future that creates a TCP connection.
/// It attempts to reuse sockets in CLOSE_WAIT state.
fn create_tcp_connection(addr: &SocketAddr) -> tcp::ConnectFuture {
    let sock = {
        let domain = if addr.is_ipv4() {
            Domain::ipv4()
        } else {
            Domain::ipv6()
        };
        Socket::new(domain, Type::stream(), None)
    };

    match sock {
        Ok(sock) => {
            // Attempt to reuse sockets in CLOSE_WAIT state
            drop(sock.set_reuse_address(true));
            // Convert to connected TcpStream
            TcpStream::connect_std(sock.into_tcp_stream(), addr, &Handle::default())
        }
        Err(_) => {
            // Fall back to default connect
            TcpStream::connect(addr)
        }
    }
}

/// Returns a future that tries to perform a message exchange over a new TCP connection.
fn exchange_with_tcp(
    addr: SocketAddr,
    query: Message,
) -> impl Future<Item = (Message, SocketAddr, Option<FramedStream>), Error = IoError> {
    create_tcp_connection(&addr).and_then(move |stream| {
        // Disable Nagle and convert to framed transport
        drop(stream.set_nodelay(true));
        let stream = FramedStream::from(stream);
        exchange_with_stream(stream, addr, query)
    })
}

/// Returns a future that tries to perform a message exchange over a new TCP connection.
fn exchange_with_tls(
    addr: SocketAddr,
    query: Message,
    domain: String,
) -> impl Future<Item = (Message, SocketAddr, Option<FramedStream>), Error = IoError> {
    let connector = native_tls::TlsConnector::builder().build().unwrap();
    let connector: tokio_tls::TlsConnector = connector.into();
    create_tcp_connection(&addr)
        .and_then(move |stream| {
            trace!("handshake with {:?}, domain: {}", addr, domain);
            connector
                .connect(&domain, stream)
                .map_err(|e| IoError::new(ErrorKind::Other, e))
        })
        .and_then(move |stream| {
            let stream = FramedStream::from(stream);
            exchange_with_stream(stream, addr, query)
        })
}

/// Returns a future that tries to perform a message exchange over a new TCP connection.
fn exchange_with_stream(
    stream: FramedStream,
    addr: SocketAddr,
    query: Message,
) -> impl Future<Item = (Message, SocketAddr, Option<FramedStream>), Error = IoError> {
    stream
        .send((query.as_slice().into(), addr))
        .and_then(move |stream| {
            stream.into_future().map_err(move |_e| {
                IoError::new(ErrorKind::UnexpectedEof, "no response within timeout")
            })
        })
        .and_then(move |(response, stream)| match response {
            Some((response, peer_addr)) => match Message::from_bytes(response.into()) {
                Ok(message) => Ok((message, peer_addr, Some(stream))),
                Err(_e) => Err(IoError::new(ErrorKind::InvalidData, "invalid response")),
            },
            None => Err(IoError::new(
                ErrorKind::UnexpectedEof,
                "connection closed whilst waiting for response",
            )),
        })
}

/// Get an address for socket binding based on the family
fn get_local_addr(ipv6: bool) -> SocketAddr {
    SocketAddr::new(if ipv6 { *UNBOUND_IPV6 } else { *UNBOUND_IPV4 }, 0)
}

/// Returns a future that tries to perform a message exchange over UDP.
fn exchange_with_udp(
    addr: SocketAddr,
    query: Message,
) -> impl Future<Item = (Message, (SocketAddr, Message)), Error = IoError> {
    let local_addr = get_local_addr(addr.is_ipv6());
    let socket = UdpSocket::bind(&local_addr).expect("bound socket");
    FramedStream::from(socket)
        .send((query.as_bytes().clone(), addr))
        .and_then(move |stream| {
            stream
                // Filter only messages from requested target
                .filter_map(move |(response, from)| {
                    if from.ip() == addr.ip() {
                        Some(response)
                    } else {
                        info!(
                            "skipping unsolicited response from {} (expected: {})",
                            from, addr
                        );
                        None
                    }
                })
                .into_future()
                .map_err(move |_| ErrorKind::UnexpectedEof.into())
                // Parse the response into message and unblock waiting futures
                .and_then(move |(response, _stream)| match response {
                    Some(response) => match Message::from_bytes(response.into()) {
                        Ok(message) => Ok((message, (addr, query))),
                        Err(_e) => Err(IoError::new(
                            ErrorKind::InvalidData,
                            "received invalid message",
                        )),
                    },
                    None => Err(IoError::new(
                        ErrorKind::UnexpectedEof,
                        "socket closed whilst waiting for a response",
                    )),
                })
        })
}

#[cfg(test)]
mod test {
    use super::{Builder, Conductor, Retransmitter};
    use crate::query_router::Scope;
    use crate::test_utils::{test_echo_server, TestOrigin, DOMAINS};
    use bytes::Bytes;
    use domain_core::bits::*;
    use domain_core::iana::*;
    use std::net::SocketAddr;
    use std::ops::Add;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use test::{black_box, Bencher};
    use tokio::await;
    use tokio::prelude::*;
    use tokio::runtime::current_thread::Runtime;
    use tokio::timer::Delay;

    #[test]
    fn retransmitter() {
        let now = Instant::now();
        let f0 = Delay::new(now.add(Duration::from_millis(200))).then(|_| {
            let addr = "127.0.0.1:1".parse::<SocketAddr>().unwrap();
            let msg = Message::from_bytes(Bytes::from_static(&[0u8; 12])).unwrap();
            Ok((msg, addr, None))
        });
        let f1 = future::lazy(|| Err(std::io::ErrorKind::UnexpectedEof.into()));
        let f2 = future::lazy(|| {
            let addr = "127.0.0.1:2".parse::<SocketAddr>().unwrap();
            let msg = Message::from_bytes(Bytes::from_static(&[1u8; 12])).unwrap();
            Ok((msg, addr, None))
        });

        let mut retry = Retransmitter::new();
        tokio::run_async(
            async move {
                // Schedule tries with the same grace period
                retry.schedule(Box::new(f0), Duration::from_millis(100));
                retry.schedule(Box::new(f1), Duration::from_millis(100));
                retry.schedule(Box::new(f2), Duration::from_millis(100));

                // Waiting on first delayed future, nothing should be returned
                match retry.poll() {
                    Ok(Async::NotReady) => {}
                    _ => {
                        assert!(false);
                    }
                }

                let _ = await!(Delay::new(now.add(Duration::from_millis(10))));
                match retry.poll() {
                    Ok(Async::NotReady) => {}
                    _ => {
                        assert!(false);
                    }
                }

                // Grace period passes, second + third future should be polled
                // Second future is an error, so the Retransmitter should continue polling
                // and return the third scheduled future.
                let _ = await!(Delay::new(now.add(Duration::from_millis(150))));
                match retry.poll() {
                    Ok(Async::Ready(_)) => {} // Ready
                    _ => {
                        assert!(false);
                    }
                }
            },
        );
    }

    const MAX_TEST_DURATION: Duration = Duration::from_millis(60_000);

    fn bench_batched(b: &mut Bencher, conductor: Arc<Conductor>) {
        let (echo_server, addr) = test_echo_server(MAX_TEST_DURATION);
        let peer_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        let origin: Arc<TestOrigin> = Arc::new(addr.into());

        // Sample a few unique messages to test connection reuse
        let messages = DOMAINS
            .iter()
            .take(10)
            .map(|dname| {
                let mut mb = MessageBuilder::with_capacity(512);
                mb.push(Question::new(dname, Rtype::Any, Class::Ch))
                    .expect("pushed question");
                mb.freeze()
            })
            .collect::<Vec<Message>>();

        // Create a test set
        let test_set = (0..1000).map(move |i| {
            let msg = messages[i % messages.len()].clone();
            let scope = Scope::new(msg.clone().as_bytes().clone(), peer_addr).unwrap();
            conductor
                .resolve(&scope, msg, origin.clone())
                .then(move |res| {
                    // Print errors when in --nocapture
                    if let Err(e) = res {
                        eprintln!("resolve error: {:?}", e);
                    }
                    // Compiler can't infer the type for E here
                    Ok::<_, ()>(())
                })
        });

        // Run mock responder
        let mut runtime = Runtime::new().expect("runtime");
        runtime.spawn(echo_server);

        let mut bench_closure = || {
            let fut = future::join_all(test_set.clone());
            black_box(runtime.block_on(fut).expect("spawn and wait"));
        };

        // Warmup and test
        bench_closure();
        b.iter(bench_closure);
    }

    #[bench]
    fn batched_1k(b: &mut Bencher) {
        let conductor = Builder::default().build();
        bench_batched(b, Arc::new(conductor))
    }

    #[bench]
    fn batched_udp_1k(b: &mut Bencher) {
        let conductor = Builder::default().with_tcp(false).build();
        bench_batched(b, Arc::new(conductor))
    }

    #[bench]
    fn batched_noreuse_1k(b: &mut Bencher) {
        let conductor = Builder::default().with_max_keepalive_connections(0).build();
        bench_batched(b, Arc::new(conductor))
    }

    #[bench]
    fn batched_noop_1k(b: &mut Bencher) {
        let conductor = Builder::default().with_udp(false).with_tcp(false).build();
        bench_batched(b, Arc::new(conductor))
    }
}
