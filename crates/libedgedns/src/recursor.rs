use crate::conductor::Origin;
use crate::config::Config;
use crate::query_router::Scope;
use domain_core::bits::*;
use domain_core::iana::*;
use domain_core::rdata::*;
use futures::future::Either;
use hex;
use kres;
use log::*;
use std::io::{Error as IoError, ErrorKind, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::await;
use tokio::prelude::*;

#[derive(Clone)]
pub struct Recursor {
    resolver: Arc<kres::Context>,
}

impl Recursor {
    pub fn new(config: &Config) -> Self {
        Builder::default()
            .with_cache(if config.cache_size > 1024 {
                1024 * 1024
            } else {
                0
            })
            .with_trust_anchor(Ds::new(
                20326,
                SecAlg::RsaSha256,
                DigestAlg::Sha256,
                hex::decode("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")
                    .unwrap()
                    .into(),
            ))
            .with_verbosity(log_enabled!(Level::Info))
            .build()
    }

    fn from_builder(builder: &Builder) -> Self {
        let resolver = match builder.cache_size {
            0 => kres::Context::new(),
            _ => kres::Context::with_cache(".", builder.cache_size).unwrap(),
        };

        for ta in &builder.trust_anchors {
            let mut serialized = Vec::with_capacity(ta.compose_len());
            ta.compose(&mut serialized);
            resolver.add_trust_anchor(&serialized).unwrap();
        }

        resolver.set_verbose(builder.verbose);
        Self { resolver }
    }

    pub async fn resolve_async<'a>(&'a self, scope: &'a Scope) -> Result<Message> {
        let request = kres::Request::new(self.resolver.clone());
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
                    // Resolve the query with the origin list
                    let origin = Arc::new(PreferenceList { addresses });
                    let res = await!(conductor
                        .resolve(scope.clone(), Message::from_bytes(buf).unwrap(), origin)
                        .timeout(Duration::from_millis(3000)));

                    // Consume the mock answer and expect resolution to be done
                    match res {
                        Ok((message, from)) => request.consume(message.as_slice(), from),
                        Err(e) => {
                            warn!("error when resolving query with origin: {:?}", e);
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

    pub fn resolve(&self, scope: &Scope) -> impl Future<Item = Message, Error = IoError> {
        let request = kres::Request::new(self.resolver.clone());
        let scope = scope.clone();

        // Push it as a question to request
        let state = request.consume(scope.query.as_bytes(), scope.peer_addr);
        let fut = if state != kres::State::PRODUCE {
            Either::A(future::ok((state, request)))
        } else {
            let conductor = scope.context.conductor.clone();
            Either::B(future::loop_fn(request, move |request| {
                match request.produce() {
                    Some((buf, addresses)) => {
                        // Save first address in case of an error
                        let first_address = addresses[0];
                        // Resolve the query with the origin list
                        let origin = Arc::new(PreferenceList { addresses });
                        Either::A(
                            conductor
                                .resolve(scope.clone(), Message::from_bytes(buf).unwrap(), origin)
                                .timeout(Duration::from_millis(3000))
                                .then(move |res| {
                                    let state = match res {
                                        Ok((message, from)) => {
                                            debug!(
                                                "received response for '{:?}'",
                                                message.first_question()
                                            );
                                            request.consume(message.as_slice(), from)
                                        }
                                        Err(e) => {
                                            info!(
                                                "error when resolving query with origin: {:?}",
                                                e
                                            );
                                            request.consume(&[], first_address)
                                        }
                                    };

                                    Ok((state, request))
                                })
                                .and_then(move |(state, request)| {
                                    if state == kres::State::PRODUCE {
                                        Ok(future::Loop::Continue(request))
                                    } else {
                                        Ok(future::Loop::Break((state, request)))
                                    }
                                }),
                        )
                    }
                    None => Either::B(future::ok(future::Loop::Break((
                        kres::State::DONE,
                        request,
                    )))),
                }
            }))
        };

        // Get final answer
        fut.and_then(move |(state, request)| {
            let buf = request.finish(state).unwrap();
            match Message::from_bytes(buf) {
                Ok(resp) => Ok(resp),
                Err(_) => Err(ErrorKind::InvalidData.into()),
            }
        })
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
                        black_box(await!(rec.resolve_async(&scope)).expect("result"));
                    }
                },
            );
        };

        // Warmup and test
        bench_closure();
        b.iter(bench_closure);
    }

    #[bench]
    fn resolve_1k_future(b: &mut Bencher) {
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

        let mut runtime = Runtime::new().expect("runtime");
        let mut bench_closure = || {
            let rec = rec.clone();
            let msg = msg.clone();
            for _ in 1..1000 {
                let scope = Scope::new(context.clone(), msg.clone(), peer_addr).unwrap();
                black_box(runtime.block_on(rec.resolve(&scope)).expect("result"));
            }
        };

        // Warmup and test
        bench_closure();
        b.iter(bench_closure);
    }
}
