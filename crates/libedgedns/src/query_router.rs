use crate::cache::{CacheEntry, CacheKey};
use crate::codecs::Protocol;
use crate::config::ServerType;
use crate::context::Context;
use crate::error::Result;
use crate::forwarder::Forwarder;
use crate::recursor::Recursor;
use crate::sandbox::FSLoader;
use crate::tracing;
use crate::varz;
use bytes::{Bytes, BytesMut};
use domain_core::bits::*;
use domain_core::iana::{Class, Rcode, Rtype};
use domain_core::rdata::{AllRecordData, Txt};
use guest::{Action, Phase};
use lazy_static::*;
use log::*;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use stream_cancel::Tripwire;
use tokio::await;

lazy_static! {
    static ref DNAME_SERVER: Dname = Dname::from_str("server.").unwrap();
}

/// A request scope is a handle and state for a single client request.
/// It keeps the client query and source information, as well as a reference
/// to the context on which it was created.
///
/// ```rust,no_run
/// #![feature(await_macro, async_await, futures_api)]
/// use tokio::await;
/// use domain_core::bits::{Dname, Question, SectionBuilder, MessageBuilder};
/// use domain_core::iana::{Rtype, Class};
/// use bytes::{Bytes, BytesMut};
/// use libedgedns::{Config, Context, QueryRouter, Scope};
///
/// let context = Context::new(Config::default());
/// let router = QueryRouter::new(context.clone());
/// let query = {
///    let mut mb = MessageBuilder::with_capacity(512);
///    mb.push(Question::new(Dname::root(), Rtype::Ns, Class::In)).unwrap();
///    mb.finish().into()
/// };
///
/// let scope = Scope::new(query, "127.0.0.1:53".parse().unwrap()).expect("scope");
/// tokio::run_async(async move {
///     println!("result: {:?}", await!(router.resolve(scope, BytesMut::new())));
/// });
///
/// ```
pub struct Scope {
    pub query: Message,
    pub question: Question<ParsedDname>,
    pub peer_addr: SocketAddr,
    pub local_addr: Option<SocketAddr>,
    pub is_internal: bool,
    pub protocol: Protocol,
    pub(crate) trace_span: Option<tracing::Span>,
}

impl Clone for Scope {
    fn clone(&self) -> Self {
        Self {
            query: self.query.clone(),
            question: self.question.clone(),
            peer_addr: self.peer_addr,
            local_addr: self.local_addr,
            is_internal: self.is_internal,
            protocol: self.protocol,
            trace_span: None,
        }
    }
}

impl Scope {
    /// Creates a new request scope with starting query.
    pub fn new(query: Bytes, peer_addr: SocketAddr) -> Result<Self> {
        let query = Message::from_bytes(query).unwrap();
        match query.first_question() {
            Some(question) => {
                varz::current().inflight_queries.inc();
                Ok(Self {
                    query,
                    question,
                    peer_addr,
                    local_addr: None,
                    is_internal: false,
                    protocol: Protocol::default(),
                    trace_span: None,
                })
            }
            None => Err(ErrorKind::UnexpectedEof.into()),
        }
    }

    /// Sets trace span for current request.
    fn set_trace_span(&mut self, span: tracing::Span) -> &mut Self {
        self.trace_span.replace(span);
        self
    }

    /// Set transport protocol used in this scope
    pub fn set_protocol(&mut self, protocol: Protocol) -> &mut Self {
        self.protocol = protocol;
        self
    }

    /// Set local address on which the request is served.
    pub fn set_local_addr(&mut self, local_addr: SocketAddr, is_internal: bool) -> &mut Self {
        self.local_addr = Some(local_addr);
        self.is_internal = is_internal;
        self
    }

    /// Get OPT record from client query
    pub fn opt(&self) -> Option<opt::OptRecord> {
        self.query.opt()
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        varz::current().inflight_queries.dec();
    }
}

#[derive(Clone)]
enum QueryRouterVariant {
    Forwarder(Forwarder),
    Recursor(Recursor),
}

pub struct QueryRouter {
    context: Arc<Context>,
    router: QueryRouterVariant,
    sandbox: Arc<FSLoader>,
    tracer: Arc<tracing::Tracer>,
}

impl QueryRouter {
    pub fn new(context: Arc<Context>, sandbox: Arc<FSLoader>) -> Self {
        let config = &context.config;
        let tracer = Arc::new(tracing::Tracer::from_config(config));
        Self {
            router: match config.server_type {
                ServerType::Recursive => QueryRouterVariant::Recursor(Recursor::new(config)),
                ServerType::Authoritative | ServerType::Forwarder => {
                    QueryRouterVariant::Forwarder(Forwarder::from(config))
                }
            },
            context,
            sandbox,
            tracer,
        }
    }

    /// Spawns the query router start in the default executor.
    pub fn spawn(me: Arc<QueryRouter>, tripwire: Tripwire) {
        tokio::spawn_async(
            async move {
                await!(me.start(tripwire));
            },
        );
    }

    /// Starts the query router.
    pub async fn start(&self, tripwire: Tripwire) {
        debug!("starting query router");
        let context = self.context.clone();
        self.tracer.start(tripwire.clone());

        let result = match &self.router {
            QueryRouterVariant::Recursor(recursor) => await!(recursor.start(context, tripwire)),
            QueryRouterVariant::Forwarder(forwarder) => await!(forwarder.start(context, tripwire)),
        };

        if let Err(e) = result {
            warn!("failed to start query router: {:?}", e);
        }
    }

    /// Resolve the DNS request and serialize the answer in provided buffer.
    pub async fn resolve(&self, mut scope: Scope, answer: BytesMut) -> Result<BytesMut> {
        // Update metrics
        let varz = varz::current();
        varz.client_queries.inc();

        // Process special queries
        match scope.question.qclass() {
            // Chaos class
            Class::Ch => return self.resolve_to_chaos(&scope, answer),
            // Internet class, fallthrough
            Class::In => {}
            // Other class, not implemented
            _ => return self.resolve_to_error(&scope, answer, Rcode::NotImp, false),
        };

        // Process query
        match scope.protocol {
            Protocol::Udp => varz.client_queries_udp.inc(),
            Protocol::Tcp => varz.client_queries_tcp.inc(),
            _ => {}
        }

        // Process pre-flight phase
        let (answer, action) = await!(self.sandbox.run_phase(Phase::PreCache, &scope, answer));
        match action {
            Action::Deliver => return Ok(answer),
            Action::Drop => return resolve_to_error(&scope, answer, Rcode::Refused, false),
            Action::Pass => {},
        }

        let mut cache = self.context.cache.clone();
        let cache_key = CacheKey::from(&scope);
        match cache.get(&cache_key) {
            Some(entry) => {
                varz.client_queries_cached.inc();
                self.resolve_from_cache(&scope, entry, answer)
            }
            None => {
                // Set tracing span
                if let Some(span) = self.tracer.new_span(&scope.question) {
                    scope.set_trace_span(span);
                }

                // Route the request to respective handler
                let res = match &self.router {
                    QueryRouterVariant::Recursor(recursor) => {
                        await!(recursor.resolve(&self.context, &scope))
                    }
                    QueryRouterVariant::Forwarder(forwarder) => {
                        await!(forwarder.resolve(&self.context, &scope))
                    }
                };

                // Handle errors during processing
                match res {
                    Ok(message) => {
                        // Disable trace if only failure tracing is configured
                        if self.context.config.tracing_only_failures
                            && message.header().rcode() != Rcode::ServFail
                        {
                            if let Some(ref span) = scope.trace_span {
                                span.discard()
                            }
                        }
                        trace!(
                            "query router resolved '{}': {}",
                            cache_key,
                            message.header().rcode()
                        );
                        cache.insert(cache_key, message.clone().into());
                        self.resolve_from_answer(&scope, message, answer, None)
                    }
                    Err(e) => {
                        debug!("query router failed to resolve '{}': {:?}", cache_key, e);
                        varz.client_queries_errors.inc();
                        self.resolve_to_error(&scope, answer, Rcode::ServFail, false)
                    }
                }
            }
        }
    }

    fn resolve_from_answer(
        &self,
        scope: &Scope,
        source: Message,
        answer: BytesMut,
        elapsed: Option<u32>,
    ) -> Result<BytesMut> {
        // Check server type to alter cached message processing
        let server_type = self.context.config.server_type;

        // Calculate the maximum payload size
        let opt = scope.opt();
        let max_bufsize = match scope.protocol {
            Protocol::Udp => match opt {
                Some(opt) => opt.udp_payload_size() as usize,
                None => 512,
            },
            _ => std::u16::MAX as usize,
        };

        // Build response from cached message
        let mut message = MessageBuilder::from_buf(answer.clone());
        // TODO: Disabled because habbo.com.mx A fails to compress
        // message.enable_compression();
        message.set_limit(max_bufsize);

        // Set header flags for response
        let header = message.header_mut();
        let src_header = source.header();
        header.set_id(scope.query.header().id());
        header.set_qr(true);
        header.set_opcode(src_header.opcode());
        header.set_rcode(src_header.rcode());
        header.set_aa(src_header.aa());
        header.set_ad(src_header.ad());
        header.set_cd(src_header.cd());
        header.set_rd(scope.query.header().rd());
        header.set_ra(server_type == ServerType::Recursive);
        if message.push(scope.question.clone()).is_err() {
            return Err(ErrorKind::UnexpectedEof.into());
        }

        // Copy records from section with decayed TTL
        let result = source.copy_records(message, |parsed| {
            let rr = match parsed {
                Ok(rr) => rr,
                Err(_) => return None,
            };

            // Skip OPT as the server is going attach its own
            if rr.rtype() == Rtype::Opt {
                return None;
            }

            // Skip the unparseable records
            if let Ok(Some(mut rr)) = rr.into_record::<AllRecordData<ParsedDname>>() {
                // Decay TTL if configured
                if elapsed.is_some() && server_type != ServerType::Authoritative {
                    rr.set_ttl(rr.ttl().saturating_sub(elapsed.unwrap()));
                }
                return Some(rr);
            }

            None
        });

        // Finalize message
        match result {
            Ok(message) => {
                // TODO: add OPT before finalizing
                Ok(message.finish())
            }
            Err(e) => {
                // Truncation occured, return error
                debug!(
                    "failed to generate a response: {:?} ({}B, max: {})",
                    e,
                    source.len(),
                    max_bufsize
                );
                self.resolve_to_error(scope, answer, src_header.rcode(), true)
            }
        }
    }

    /// Resolve from cached entry.
    fn resolve_from_cache(
        &self,
        scope: &Scope,
        entry: CacheEntry,
        answer: BytesMut,
    ) -> Result<BytesMut> {
        let cached = entry.as_message();
        let elapsed = entry.elapsed();
        self.resolve_from_answer(scope, cached, answer, Some(elapsed))
    }

    /// Fallback handler to resolve CHAOS zone requests
    fn resolve_to_chaos(&self, scope: &Scope, answer: BytesMut) -> Result<BytesMut> {
        // Fallback handler only implements CH TXT
        if scope.question.qtype() != Rtype::Txt {
            return self.resolve_to_error(scope, answer, Rcode::NotImp, false);
        }

        // Build message response header and question
        let mut message = {
            let mut message = MessageBuilder::from_buf(answer);
            let header = message.header_mut();
            *header = *scope.query.header();
            header.set_id(scope.query.header().id());
            header.set_qr(true);
            if message.push(scope.question.clone()).is_err() {
                return Err(ErrorKind::UnexpectedEof.into());
            }
            message.answer()
        };

        // Return different data based on the query name
        if let Some(qname) = scope.question.qname().as_flat_slice() {
            let config = &self.context.config;
            let owner = scope.question.qname().clone();
            match qname {
                b"\x02id\x06server\x00" => {
                    if let Some(identity) = &config.identity {
                        let rdata = Txt::new(identity.parse().unwrap());
                        drop(message.push((owner, Class::Ch, 0, rdata)));
                    }
                }
                b"\x07version\x06server\x00" => {
                    if let Some(version) = &config.version {
                        let rdata = Txt::new(version.parse().unwrap());
                        drop(message.push((owner, Class::Ch, 0, rdata)));
                    }
                }
                _ => {}
            }
        } else {
            message.header_mut().set_rcode(Rcode::Refused);
        }

        Ok(message.finish())
    }

    /// Fallback handler to resolve errors into error responses
    fn resolve_to_error(
        &self,
        scope: &Scope,
        answer: BytesMut,
        rcode: Rcode,
        truncated: bool,
    ) -> Result<BytesMut> {
        let server_type = self.context.config.server_type;
        let mut message = MessageBuilder::from_buf(answer);
        let header = message.header_mut();
        *header = *scope.query.header();
        header.set_id(scope.query.header().id());
        header.set_qr(true);
        header.set_ra(server_type == ServerType::Recursive);
        header.set_rcode(rcode);
        header.set_tc(truncated);
        if message.push(scope.question.clone()).is_err() {
            return Err(ErrorKind::UnexpectedEof.into());
        }

        Ok(message.finish())
    }

}

#[cfg(test)]
mod test {
    use super::{QueryRouter, Scope};
    use crate::test_utils::{test_context, DOMAINS};
    use bytes::{Bytes, BytesMut};
    use domain_core::bits::*;
    use domain_core::iana::*;
    use std::net::SocketAddr;
    use test::{black_box, Bencher};

    #[bench]
    fn resolve_1k(b: &mut Bencher) {
        let context = test_context();

        // Create ANY queries that will be immediately solved
        let peer_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        let messages: Vec<Bytes> = DOMAINS
            .iter()
            .map(|dname| {
                let mut mb = MessageBuilder::with_capacity(512);
                mb.push(Question::new(dname, Rtype::Any, Class::Ch))
                    .expect("pushed question");
                mb.finish().into()
            })
            .collect();

        let bench_closure = || {
            let messages = messages.clone();
            let buf = BytesMut::with_capacity(512);
            let router = QueryRouter::new(context.clone());
            tokio::run_async(
                async move {
                    for i in 1..1000 {
                        let scope = Scope::new(messages[i - 1].clone(), peer_addr).unwrap();
                        let mut buf = buf.clone();
                        buf.reserve(512);
                        black_box(await!(router.resolve(scope, buf)).expect("result"));
                    }
                },
            );
        };

        // Warmup and test
        bench_closure();
        b.iter(bench_closure);
    }
}
