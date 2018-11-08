use coarsetime::Duration;
use crate::config::Config;
use tokio::prelude::*;
use crate::context::Context;
use std::sync::Arc;
use domain_core::bits::Message;
use crate::query_router::Scope;
use crate::conductor::Origin;
use jumphash::JumpHasher;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::net::SocketAddr;
use std::io::Error as IoError;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum LoadBalancingMode {
	Uniform,
	Consistent,
	// MinLoad,
}

impl Default for LoadBalancingMode {
	fn default() -> LoadBalancingMode { LoadBalancingMode::Uniform }
}

#[derive(Clone)]
pub struct Forwarder {
	context: Arc<Context>,
	origin: Arc<Origin>,
}

impl Forwarder {
	pub fn resolve(&self, context: Arc<Context>, scope: &Scope) -> impl Future<Item = Message, Error = IoError> {
		let conductor = context.conductor.clone();
		conductor.resolve(scope.clone(), scope.query.clone(), self.origin.clone())
	}
}

#[derive(Clone, Default)]
pub struct Builder {
	upstream_servers: Vec<SocketAddr>,
	lbmode: LoadBalancingMode,
	upstream_max_failure_duration: Duration,
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
	pub fn build(self, context: Arc<Context>) -> Forwarder {
		let origin : Arc<Origin> = match self.lbmode {
			LoadBalancingMode::Uniform => Arc::new(UniformlyDistributedOrigin::new(self.upstream_servers)),
			LoadBalancingMode::Consistent => Arc::new(JumpHashOrigin::new(self.upstream_servers)),
		};

		Forwarder { context, origin }
	}
}

/// Builder from configuration pattern
impl From<&Config> for Builder {
	fn from(config: &Config) -> Self {
		Self {
			upstream_servers: config.upstream_servers_str.iter().map(|addr| {
				addr.parse::<SocketAddr>().unwrap()
			}).collect(),
			lbmode: config.lbmode,
			upstream_max_failure_duration: config.upstream_max_failure_duration,
		}
	}
}

pub struct UniformlyDistributedOrigin {
	pub addresses: Vec<SocketAddr>,
}

impl UniformlyDistributedOrigin {
	pub fn new(mut addresses: Vec<SocketAddr>) -> impl Origin {
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
	pub fn new(addresses: Vec<SocketAddr>) -> impl Origin {
		Self {
			jumphasher: JumpHasher::new(),
			addresses
		}
	}
}

impl Origin for JumpHashOrigin {
	fn get(&self) -> &[SocketAddr] {
		&self.addresses
	}
	fn get_scoped(&self, scope: &Scope) -> &[SocketAddr] {
		self.get()
	}
}

#[cfg(test)]
mod test {
	use super::{Builder, LoadBalancingMode};
	use crate::query_router::Scope;
	use crate::test_utils::{echo_udp_server, spawn_and_wait, test_context};
	use bytes::Bytes;
	use std::sync::Arc;
	use std::time::Duration;
	use std::net::SocketAddr;
	use test::{black_box, Bencher};
	use tokio::runtime::Runtime;
	use tokio::prelude::*;
	use domain_core::bits::*;
	use domain_core::iana::*;

	const MAX_TEST_DURATION: Duration = Duration::from_millis(60_000);

	fn bench_batched(b: &mut Bencher, builder: Builder) {
		let mut runtime = Runtime::new().expect("runtime");

		let context = test_context();
		let peer_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
		let (echo_server, addr) = echo_udp_server(MAX_TEST_DURATION);
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

		let forwarder = builder.with_upstream_servers(vec![addr]).build(context.clone());

		// Run mock responder
		runtime.spawn(echo_server);

		let mut bench_closure = || {
			let fut = {
				let msg = msg.clone();
				let context = context.clone();
				let forwarder = forwarder.clone();
				let set = (0..1000).map(move |_| {
					let scope = Scope::new(msg.clone(), peer_addr).unwrap();
					forwarder
						.resolve(context.clone(), &scope)
						.and_then(|_| Ok(()))
						.map_err(|e| eprintln!("resolver err {}", e))
				});
				future::join_all(set)
			};

			black_box(spawn_and_wait(&mut runtime, fut).expect("spawn and wait"));
		};

		// Warmup and test
		bench_closure();
		b.iter(bench_closure);

		// Wait until the runtime becomes idle and shut it down.
		runtime.shutdown_now().wait().unwrap();
	}

	#[bench]
	fn forward_uniform(b: &mut Bencher) {
		let builder = Builder::default()
			.with_loadbalancing_mode(LoadBalancingMode::Uniform);

		bench_batched(b, builder)
	}
}