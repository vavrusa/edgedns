use crate::conductor::Origin;
use crate::config::Config;
use crate::query_router::Scope;
use crate::UPSTREAM_TOTAL_TIMEOUT_MS;
use domain_core::bits::Message;
use jumphash::JumpHasher;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::io::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::prelude::*;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum LoadBalancingMode {
    Uniform,
    Consistent,
    // MinLoad,
}

impl Default for LoadBalancingMode {
    fn default() -> LoadBalancingMode {
        LoadBalancingMode::Uniform
    }
}

#[derive(Clone)]
pub struct Forwarder {
    origin: Arc<Origin>,
}

impl Forwarder {
    pub fn resolve(&self, scope: &Scope) -> impl Future<Item = Message, Error = Error> {
        let conductor = scope.context.conductor.clone();
        conductor
            .resolve(scope.clone(), scope.query.clone(), self.origin.clone())
            .map(move |(message, _from)| message)
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
            upstream_max_failure_duration: config.upstream_max_failure_duration,
        }
        .build()
    }
}

#[derive(Clone)]
pub struct Builder {
    upstream_servers: Vec<SocketAddr>,
    lbmode: LoadBalancingMode,
    upstream_max_failure_duration: Duration,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            upstream_servers: vec![],
            lbmode: LoadBalancingMode::default(),
            upstream_max_failure_duration: Duration::from_millis(UPSTREAM_TOTAL_TIMEOUT_MS),
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
        };

        Forwarder { origin }
    }
}

pub struct UniformlyDistributedOrigin {
    pub addresses: Vec<SocketAddr>,
}

impl UniformlyDistributedOrigin {
    pub fn new(mut addresses: Vec<SocketAddr>) -> Self {
        // Shuffle array with uniform distribution
        let mut rng = thread_rng();
        addresses.shuffle(&mut rng);
        Self { addresses }
    }
}

impl Origin for UniformlyDistributedOrigin {
    fn get(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

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
}

impl Origin for JumpHashOrigin {
    fn get(&self) -> &[SocketAddr] {
        &self.addresses
    }

    fn get_scoped(&self, scope: &Scope) -> &[SocketAddr] {
        let slot = self
            .jumphasher
            .slot(scope.question.qname(), self.addresses.len() as u32) as usize;
        &self.addresses[slot..]
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
                    let scope = Scope::new(context.clone(), msg.clone(), peer_addr).unwrap();
                    forwarder
                        .resolve(&scope)
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