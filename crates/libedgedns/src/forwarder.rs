use crate::conductor::{Origin, Timetable};
use crate::config::Config;
use crate::context::Context;
use crate::query_router::Scope;
use crate::UPSTREAM_TOTAL_TIMEOUT_MS;
use domain_core::bits::Message;
use jumphash::JumpHasher;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use stream_cancel::Tripwire;
use tokio::prelude::*;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum LoadBalancingMode {
    Uniform,
    Consistent,
    MinLoad,
    Fallback,
}

impl Default for LoadBalancingMode {
    fn default() -> LoadBalancingMode {
        LoadBalancingMode::Uniform
    }
}

#[derive(Clone)]
pub struct Forwarder {
    origin: Arc<Origin>,
    pub mode: LoadBalancingMode,
    pub upstream_total_timeout: Duration,
}

impl Forwarder {
    /// Returns forwarder instance builder.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Starts the upstream healthchecks.
    pub async fn start(&self, _context: Arc<Context>, _tripwire: Tripwire) -> Result<(), Error> {
        // TODO: start healthcheck
        Ok(())
    }

    /// Resolve the request with the configured upstreams.
    pub fn resolve(
        &self,
        context: &Arc<Context>,
        scope: &Scope,
    ) -> impl Future<Item = Message, Error = Error> {
        let conductor = context.conductor.clone();
        conductor
            .resolve(scope, scope.query.clone(), self.origin.clone())
            .timeout(self.upstream_total_timeout)
            .map_err(|_| ErrorKind::TimedOut.into())
            .map(move |(message, _from)| message)
    }

    /// Convert forwarder into the used Origin.
    pub fn to_origin(&self) -> Arc<Origin> {
        self.origin.clone()
    }
}

/// Build from configuration pattern
impl From<&Arc<Config>> for Forwarder {
    fn from(config: &Arc<Config>) -> Self {
        Builder {
            upstream_servers: config
                .upstream_servers_str
                .iter()
                .map(|addr| addr.parse::<SocketAddr>().unwrap())
                .collect(),
            lbmode: config.lbmode,
            upstream_total_timeout: Duration::from_millis(UPSTREAM_TOTAL_TIMEOUT_MS),
        }
        .build()
    }
}

#[derive(Clone)]
pub struct Builder {
    upstream_servers: Vec<SocketAddr>,
    lbmode: LoadBalancingMode,
    upstream_total_timeout: Duration,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            upstream_servers: vec![],
            lbmode: LoadBalancingMode::default(),
            upstream_total_timeout: Duration::from_millis(UPSTREAM_TOTAL_TIMEOUT_MS),
        }
    }
}

/// Builder pattern
impl Builder {
    pub fn new() -> Self {
        Default::default()
    }

    /// Set load balancing mode for the forwarder (default is Uniform)
    pub fn with_loadbalancing_mode(mut self, mode: LoadBalancingMode) -> Self {
        self.lbmode = mode;
        self
    }

    /// Set upstream server list
    pub fn with_upstream_servers(mut self, servers: Vec<SocketAddr>) -> Self {
        self.upstream_servers = servers;
        self
    }

    /// Convert the Builder into the Forwarder with defined configuration.
    pub fn build(self) -> Forwarder {
        let origin: Arc<Origin> = match self.lbmode {
            LoadBalancingMode::Uniform => {
                Arc::new(UniformlyDistributedOrigin::new(self.upstream_servers))
            }
            LoadBalancingMode::Consistent => Arc::new(JumpHashOrigin::new(self.upstream_servers)),
            LoadBalancingMode::MinLoad => Arc::new(MinLoadOrigin::new(self.upstream_servers)),
            LoadBalancingMode::Fallback => Arc::new(FallbackOrigin::new(self.upstream_servers)),
        };

        Forwarder {
            origin,
            mode: self.lbmode,
            upstream_total_timeout: self.upstream_total_timeout,
        }
    }
}

/// Origin implementation with upstreams selected in order.
pub struct FallbackOrigin {
    pub addresses: Vec<SocketAddr>,
}

impl FallbackOrigin {
    pub fn new(addresses: Vec<SocketAddr>) -> Self {
        Self { addresses }
    }
}

impl Origin for FallbackOrigin {
    fn get(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

/// Origin implementation with upstream selected with random choice.
pub struct UniformlyDistributedOrigin {
    pub addresses: Vec<SocketAddr>,
}

impl UniformlyDistributedOrigin {
    pub fn new(addresses: Vec<SocketAddr>) -> Self {
        Self { addresses }
    }
}

impl Origin for UniformlyDistributedOrigin {
    fn get(&self) -> &[SocketAddr] {
        &self.addresses
    }

    fn get_scoped(&self, _scope: &Scope, _timetable: &Timetable) -> Vec<SocketAddr> {
        self.addresses.choose_multiple(&mut thread_rng(), 4).cloned().collect()
    }

    fn choose(&self, _scope: &Scope) -> Option<&SocketAddr> {
        self.addresses.choose(&mut thread_rng())
    }
}

/// Origin implementation with consistent hashing based on the query name.
pub struct JumpHashOrigin {
    jumphasher: JumpHasher,
    addresses: Vec<SocketAddr>,
}

impl JumpHashOrigin {
    pub fn new(addresses: Vec<SocketAddr>) -> Self {
        Self {
            jumphasher: JumpHasher::new(),
            addresses,
        }
    }

    /// Returns a slot choice for given scope.
    fn slot(&self, scope: &Scope) -> usize {
        self
            .jumphasher
            .slot(scope.question.qname(), self.addresses.len() as u32) as usize
    }
}

impl Origin for JumpHashOrigin {
    fn get(&self) -> &[SocketAddr] {
        &self.addresses
    }

    fn get_scoped(&self, scope: &Scope, _timetable: &Timetable) -> Vec<SocketAddr> {
        let slot = self.slot(scope);
        (&self.addresses[slot..]).to_vec()
    }

    fn choose(&self, scope: &Scope) -> Option<&SocketAddr> {
        self.addresses.get(self.slot(scope))
    }
}

/// Origin implementation with the power of two choices.
pub struct MinLoadOrigin {
    addresses: Vec<SocketAddr>,
}

impl MinLoadOrigin {
    pub fn new(addresses: Vec<SocketAddr>) -> Self {
        Self { addresses }
    }
}

impl Origin for MinLoadOrigin {
    fn get(&self) -> &[SocketAddr] {
        &self.addresses
    }

    fn get_scoped(&self, scope: &Scope, _timetable: &Timetable) -> Vec<SocketAddr> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use super::{Builder, LoadBalancingMode};
    use crate::query_router::Scope;
    use crate::test_utils::{test_context, test_echo_server};
    use bytes::Bytes;
    use domain_core::bits::*;
    use domain_core::iana::*;
    use std::net::SocketAddr;
    use std::time::Duration;
    use test::{black_box, Bencher};
    use tokio::prelude::*;
    use tokio::runtime::current_thread::Runtime;

    const MAX_TEST_DURATION: Duration = Duration::from_millis(60_000);

    fn bench_batched(b: &mut Bencher, builder: Builder) {
        let context = test_context();
        let peer_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        let (echo_server, addr) = test_echo_server(MAX_TEST_DURATION);
        let msg: Bytes = {
            let mut mb = MessageBuilder::with_capacity(512);
            mb.push(Question::new(
                Dname::from_slice(b"\0").unwrap(),
                Rtype::Any,
                Class::Ch,
            ))
            .expect("pushed question");
            mb.finish().into()
        };

        // Finalize forwarder
        let forwarder = builder.with_upstream_servers(vec![addr]).build();

        // Run mock responder
        let mut runtime = Runtime::new().expect("runtime");
        runtime.spawn(echo_server);

        let mut bench_closure = || {
            let fut = {
                let msg = msg.clone();
                let context = context.clone();
                let forwarder = forwarder.clone();
                let set = (0..1000).map(move |_| {
                    let scope = Scope::new(msg.clone(), peer_addr).unwrap();
                    forwarder
                        .resolve(&context, &scope)
                        .and_then(|_| Ok(()))
                        .map_err(|e| eprintln!("resolver err {}", e))
                });
                future::join_all(set)
            };

            black_box(runtime.block_on(fut).expect("spawn and wait"));
        };

        // Warmup and test
        bench_closure();
        b.iter(bench_closure);
    }

    #[bench]
    fn forward_fallback(b: &mut Bencher) {
        let builder = Builder::default().with_loadbalancing_mode(LoadBalancingMode::Fallback);

        bench_batched(b, builder)
    }

    #[bench]
    fn forward_uniform(b: &mut Bencher) {
        let builder = Builder::default().with_loadbalancing_mode(LoadBalancingMode::Uniform);

        bench_batched(b, builder)
    }

    #[bench]
    fn forward_consistent(b: &mut Bencher) {
        let builder = Builder::default().with_loadbalancing_mode(LoadBalancingMode::Consistent);

        bench_batched(b, builder)
    }
}
