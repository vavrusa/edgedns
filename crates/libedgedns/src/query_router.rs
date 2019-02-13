use crate::cache::{CacheEntry, CacheKey};
use crate::config::ServerType;
use crate::context::Context;
use crate::error::Result;
use crate::forwarder::Forwarder;
use crate::recursor::Recursor;
use crate::server::Protocol;
use bytes::{Bytes, BytesMut};
use domain_core::bits::*;
use domain_core::iana::{Class, Rcode, Rtype};
use domain_core::rdata::{AllRecordData, Txt};
use lazy_static::*;
use log::*;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use stream_cancel::Tripwire;
use tokio::await;

#[derive(Clone)]
pub struct Scope {
    pub query: Message,
    pub question: Question<ParsedDname>,
    pub peer_addr: SocketAddr,
    pub context: Arc<Context>,
    protocol: Protocol,
}

impl Scope {
    pub fn new(context: Arc<Context>, query: Bytes, peer_addr: SocketAddr) -> Result<Self> {
        let query = Message::from_bytes(query).unwrap();
        match query.first_question() {
            Some(question) => Ok(Self {
                query,
                question,
                peer_addr,
                context,
                protocol: Protocol::default(),
            }),
            None => Err(ErrorKind::UnexpectedEof.into()),
        }
    }

    /// Set transport protocol used in this scope
    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.protocol = protocol;
    }

    /// Get OPT record from client query
    pub fn opt(&self) -> Option<opt::OptRecord> {
        self.query.opt()
    }
}

#[derive(Clone)]
enum QueryRouterVariant {
    Forwarder(Forwarder),
    Recursor(Recursor),
}

#[derive(Clone)]
pub struct QueryRouter {
    context: Arc<Context>,
    router: QueryRouterVariant,
}

impl QueryRouter {
    pub fn new(context: Arc<Context>) -> Self {
        let config = &context.config;

        Self {
            router: match config.server_type {
                ServerType::Recursive => QueryRouterVariant::Recursor(Recursor::new(config)),
                ServerType::Authoritative | ServerType::Forwarder => {
                    QueryRouterVariant::Forwarder(Forwarder::from(config))
                }
            },
            context,
        }
    }

    pub async fn start(&self, tripwire: Tripwire) {
        debug!("starting query router");
        let context = self.context.clone();
        let result = match &self.router {
            QueryRouterVariant::Recursor(recursor) => await!(recursor.start(context, tripwire)),
            QueryRouterVariant::Forwarder(forwarder) => await!(forwarder.start(context, tripwire)),
        };
        if let Err(e) = result {
            warn!("failed to start query router: {:?}", e);
        }
    }

    pub async fn resolve(&self, scope: Scope, answer: BytesMut) -> Result<BytesMut> {
        // Update metrics
        self.context.varz.client_queries.inc();

        // Process special queries
        match scope.question.qclass() {
            // Chaos class
            Class::Ch => return resolve_to_chaos(&scope, answer),
            // Internet class, fallthrough
            Class::In => {}
            // Other class, not implemented
            _ => return resolve_to_error(&scope, answer, Rcode::NotImp, false),
        };

        // Process query
        self.context.varz.inflight_queries.inc();
        match scope.protocol {
            Protocol::Udp => self.context.varz.client_queries_udp.inc(),
            Protocol::Tcp => self.context.varz.client_queries_tcp.inc(),
            _ => {}
        }

        // TODO: Process pre-flight hooks

        let mut cache = self.context.cache.clone();
        let cache_key = CacheKey::from(&scope);
        let answer = match cache.get(&cache_key) {
            Some(entry) => {
                self.context.varz.client_queries_cached.inc();
                resolve_from_cache(&scope, entry, answer)
            }
            None => {
                // Route the request to respective handler
                let res = match &self.router {
                    QueryRouterVariant::Recursor(recursor) => await!(recursor.resolve(&scope)),
                    QueryRouterVariant::Forwarder(forwarder) => await!(forwarder.resolve(&scope)),
                };

                // Handle errors during processing
                match res {
                    Ok(message) => {
                        trace!("storing message in cache: {}B", message.len());
                        cache.insert(cache_key, message.clone().into());
                        resolve_from_answer(&scope, message, answer, None)
                    }
                    Err(e) => {
                        info!("query router failed to resolve '{}': {:?}", cache_key, e);
                        self.context.varz.client_queries_errors.inc();
                        resolve_to_error(&scope, answer, Rcode::ServFail, false)
                    }
                }
            }
        };

        // Update metrics
        self.context.varz.inflight_queries.dec();

        answer
    }
}

lazy_static! {
    static ref DNAME_SERVER: Dname = Dname::from_str("server.").unwrap();
}

fn resolve_from_answer(
    scope: &Scope,
    source: Message,
    answer: BytesMut,
    elapsed: Option<u32>,
) -> Result<BytesMut> {
    // Check server type to alter cached message processing
    let server_type = scope.context.config.server_type;

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
    message.enable_compression();
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
        Err(_) => {
            // Truncation occured, return error
            resolve_to_error(scope, answer, src_header.rcode(), true)
        }
    }
}

/// Resolve from cached entry.
fn resolve_from_cache(scope: &Scope, entry: CacheEntry, answer: BytesMut) -> Result<BytesMut> {
    let cached = entry.as_message();
    let elapsed = entry.elapsed();
    resolve_from_answer(scope, cached, answer, Some(elapsed))
}

/// Fallback handler to resolve CHAOS zone requests
fn resolve_to_chaos(scope: &Scope, answer: BytesMut) -> Result<BytesMut> {
    // Fallback handler only implements CH TXT
    if scope.question.qtype() != Rtype::Txt {
        return resolve_to_error(scope, answer, Rcode::NotImp, false);
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
        let config = &scope.context.config;
        let owner = scope.question.qname().clone();
        match qname.as_ref() {
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
    scope: &Scope,
    answer: BytesMut,
    rcode: Rcode,
    truncated: bool,
) -> Result<BytesMut> {
    // TODO: reuse header and opt building code
    let mut message = MessageBuilder::from_buf(answer);
    let header = message.header_mut();
    *header = *scope.query.header();
    header.set_id(scope.query.header().id());
    header.set_qr(true);
    header.set_rcode(rcode);
    header.set_tc(truncated);
    if message.push(scope.question.clone()).is_err() {
        return Err(ErrorKind::UnexpectedEof.into());
    }

    Ok(message.finish())
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

        let router = QueryRouter::new(context.clone());
        let bench_closure = || {
            let context = context.clone();
            let messages = messages.clone();
            let router = router.clone();
            let buf = BytesMut::with_capacity(512);
            tokio::run_async(
                async move {
                    for i in 1..1000 {
                        let scope = Scope::new(context.clone(), messages[i - 1].clone(), peer_addr)
                            .unwrap();
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
