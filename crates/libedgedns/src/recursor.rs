use crate::cache::{Cache, CacheKey};
use crate::conductor::Origin;
use crate::config::Config;
use crate::context::Context;
use crate::query_router::Scope;
use crate::{HEALTH_CHECK_MS, UPSTREAM_TOTAL_TIMEOUT_MS};
use bytes::Bytes;
use domain_core::bits::*;
use domain_core::iana::*;
use domain_core::rdata::*;
use hex;
use kres;
use log::*;
use std::io::{ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use stream_cancel::{StreamExt, Tripwire};
use tokio::await;
use tokio::prelude::*;
use tokio::timer::Interval;

#[derive(Clone)]
pub struct Recursor {
    resolver: Arc<kres::Context>,
    cache: Option<Cache>,
}

impl Recursor {
    pub fn new(config: &Config) -> Self {
        Builder::default()
            .with_cache(config.cache_size)
            .with_trust_anchor(Ds::new(
                20326,
                SecAlg::RsaSha256,
                DigestAlg::Sha256,
                hex::decode("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")
                    .unwrap()
                    .into(),
            ))
            .with_verbosity(log_enabled!(Level::Trace))
            .build()
    }

    fn from_builder(builder: &Builder) -> Self {
        let resolver = kres::Context::new();
        let cache = match builder.cache_size {
            0 => None,
            _ => Some(Cache::new(builder.cache_size, 0, 10_800)),
        };

        for ta in &builder.trust_anchors {
            let mut serialized = Vec::with_capacity(ta.compose_len());
            ta.compose(&mut serialized);
            resolver.add_trust_anchor(&serialized).unwrap();
        }

        resolver.set_verbose(builder.verbose);
        Self { resolver, cache }
    }

    pub async fn start(&self, context: Arc<Context>, tripwire: Tripwire) -> Result<()> {
        let healthcheck = Duration::from_millis(HEALTH_CHECK_MS);
        let mut interval = Interval::new(Instant::now(), healthcheck).take_until(tripwire);

        // Construct priming query
        let source = "127.0.0.1:0".parse::<SocketAddr>().expect("local addr");
        let msg: Bytes = {
            let mut b = MessageBuilder::with_capacity(512);
            b.header_mut().set_rd(true);
            b.push(Question::new(Dname::root(), Rtype::Ns, Class::In))
                .expect("pushed question");
            b.finish().into()
        };

        // Poll root servers for healthcheck
        while let Some(_) = await!(interval.next()) {
            let scope = Scope::new(context.clone(), msg.clone(), source).unwrap();
            let start = Instant::now();
            match await!(self.resolve(&scope)) {
                Ok(msg) => {
                    debug!(
                        "polled root servers in {:?}: {}",
                        start.elapsed(),
                        msg.header().rcode()
                    );
                }
                Err(e) => {
                    info!("root servers unreachable: {:?}", e);
                }
            }
        }

        info!("recursor healthcheck stopped");
        Ok(())
    }

    pub async fn resolve<'a>(&'a self, scope: &'a Scope) -> Result<Message> {
        let request = kres::Request::new(self.resolver.clone());
        let mut cache = self.cache.clone();
        let scope = scope.clone();

        // Push it as a question to request
        let mut state = request.consume(scope.query.as_bytes(), scope.peer_addr);

        // Generate an outbound query
        let conductor = scope.context.conductor.clone();
        while state == kres::State::PRODUCE {
            state = match request.produce() {
                Some((buf, addresses)) => {
                    // Save first address in case of an error
                    let first_address = addresses[0];
                    let msg = Message::from_bytes(buf).unwrap();

                    // Check infrastructure cache first
                    let cache_key = CacheKey::from(&msg);
                    let cached_response = match cache {
                        Some(ref mut cache) => {
                            cache.get(&cache_key).and_then(move |e| Some(e.as_message()))
                        }
                        None => None,
                    };

                    // Resolve the query with the origin list
                    let response = match cached_response {
                        Some(msg) => {
                            // Cache response has no source address specified
                            let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
                            Ok((msg, from))
                        }
                        None => {
                            let origin = Arc::new(PreferenceList { addresses });
                            let response = await!(conductor
                                .resolve(scope.clone(), msg, origin)
                                .timeout(Duration::from_millis(UPSTREAM_TOTAL_TIMEOUT_MS / 2)));

                            // Update infrastructure cache
                            if let Some(ref mut cache) = cache {
                                if let Ok((ref msg, ..)) = response {
                                    // Only accept valid responses (not SERVFAIL)
                                    let is_valid = {
                                        let hdr = msg.header();
                                        hdr.qr() && hdr.rcode() != Rcode::ServFail
                                    };
                                    // Only accept NS type responses, or responses that are authoritative
                                    // e.g. not referrals, as it may be a different answer within the same zone cut
                                    let is_infrastructure = match msg.first_question() {
                                        Some(q) => q.qtype() == Rtype::Ns || msg.header().aa(),
                                        None => false,
                                    };
                                    // TODO: avoid inserting final response
                                    if is_valid && is_infrastructure {
                                        cache.insert(cache_key, msg.clone().into());
                                    }
                                }
                            }

                            response
                        }
                    };

                    // Consume the mock answer and expect resolution to be done
                    match response {
                        Ok((msg, from)) => request.consume(msg.as_slice(), from),
                        Err(e) => {
                            info!("error when resolving query with origin: {:?}", e);
                            request.consume(&[], first_address)
                        }
                    }
                }
                None => kres::State::DONE,
            };
        }

        // Get final answer
        let buf = request.finish(state).unwrap();
        match Message::from_bytes(buf) {
            Ok(resp) => Ok(resp),
            Err(_) => Err(ErrorKind::InvalidData.into()),
        }
    }
}

/// Implementation of origin for a list of addresses sorted by preference
struct PreferenceList {
    addresses: Vec<SocketAddr>,
}

impl Origin for PreferenceList {
    fn get(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

/// Builder interface for creating a Resolver instance
#[derive(Default)]
pub struct Builder {
    cache_size: usize,
    trust_anchors: Vec<Ds>,
    verbose: bool,
}

impl Builder {
    /// Build recursor with a defined cache size.
    /// If the cache size is `0`, the cache will be disabled.
    pub fn with_cache(mut self, max_size: usize) -> Self {
        self.cache_size = max_size;
        self
    }

    /// Add a trust anchor (as a DS record) to the recursor.
    /// If the recursor has at least one TA, the DNSSEC validator is enabled.
    pub fn with_trust_anchor(mut self, trust_anchor: Ds) -> Self {
        self.trust_anchors.push(trust_anchor);
        self
    }

    /// Set to true for verbose logs from the recursor.
    pub fn with_verbosity(mut self, toggle: bool) -> Self {
        self.verbose = toggle;
        self
    }

    /// Convert the Builder into the Recursor with defined configuration.
    pub fn build(self) -> Recursor {
        Recursor::from_builder(&self)
    }
}

#[cfg(test)]
mod test {
    use super::Builder;
    use crate::query_router::Scope;
    use crate::test_utils::test_context;
    use bytes::Bytes;
    use domain_core::bits::*;
    use domain_core::iana::*;
    use std::net::SocketAddr;
    use test::{black_box, Bencher};
    use tokio::await;
    use tokio::runtime::current_thread::Runtime;

    #[bench]
    fn resolve_1k_async(b: &mut Bencher) {
        let context = test_context();

        // Build a default recursor
        let rec = Builder::default().build();

        // Create a query that will be immediately solved
        let peer_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
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

        let bench_closure = || {
            let rec = rec.clone();
            let msg = msg.clone();
            let context = context.clone();
            tokio::run_async(
                async move {
                    for _ in 1..1000 {
                        let scope = Scope::new(context.clone(), msg.clone(), peer_addr).unwrap();
                        black_box(await!(rec.resolve(&scope)).expect("result"));
                    }
                },
            );
        };

        // Warmup and test
        bench_closure();
        b.iter(bench_closure);
    }
}
