use crate::conductor::Origin;
use crate::cache::CacheEntry;
use crate::config::ServerType;
use crate::context::Context;
use crate::error::{Result, Error};
use crate::forwarder::Forwarder;
use crate::recursor::Recursor;
use bytes::{BufMut, Bytes, BytesMut};
use domain_core::bits::*;
use domain_core::iana::{Class, Rcode, Rtype};
use domain_core::rdata::Txt;
use lazy_static::*;
use log::*;
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::prelude::*;
use tokio::await;
use futures::Future;

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

    pub async fn resolve(&self, scope: Scope, mut answer: BytesMut) -> Result<BytesMut> {
        // Update metrics
        self.context.varz.client_queries.inc();

        // Process special queries
        match scope.question.qclass() {
            // Chaos class
            Class::Ch => return resolve_to_chaos(&scope, answer),
            // Internet class, fallthrough
            Class::In => {}
            // Other class, not implemented
            _ => return resolve_to_error(&scope, answer, Rcode::NotImp),
        };

        // Process query
        self.context.varz.inflight_queries.inc();

        // Process pre-flight hooks
        // let res = await!(self.resolvers.iter().fold(
        //     Box::new(future::ok(())) as HookFuture,
        //     |acc, task| {
        //         Box::new(acc.and_then(move |_| task.resolve()))
        //     }));
        // let res = await!(stream::iter_ok::<_, IoError>(self.resolvers.iter())
        // //     .map(move |hook| {
        // //         hook.resolve().into_future()
        // //     })
        //     .for_each(move |f| f.resolve().into_future().then(|_| {
        //         Ok(())
        //     }))
        //     // .fold(Action::Pass, move |acc, res| {
        //     //     // eprintln!("acc {:#?} res {:#?}", acc, res);
        //     //     Ok::<_, IoError>(acc)
        //     // })
        //     // .and_then(move |acc| {
        //     //     eprintln!("res {:#?}", acc);
        //     //     Ok(())
        //     // })
            // );
        // eprintln!("hooks res {:#?}", res);
       
        let mut cache = self.context.cache.clone();
        let cache_key = (&scope.question).into();
        let answer = match cache.get(&cache_key) {
            Some(entry) => resolve_from_cache(&scope, entry, answer),
            None => {
                // Route the request to respective handler
                let res = match &self.router {
                    QueryRouterVariant::Recursor(recursor) => await!(recursor.resolve(&scope)),
                    QueryRouterVariant::Forwarder(forwarder) => await!(forwarder.resolve(&scope)),
                };

                // Handle errors during processing
                match res {
                    Ok(message) => {
                        cache.insert(cache_key, message.clone().into());
                        answer.put_slice(message.as_slice());
                        Ok(answer)
                    }
                    Err(e) => {
                        info!("query router failed to resolve '{}': {:?}", cache_key, e);
                        resolve_to_error(&scope, answer, Rcode::ServFail)
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

/// Resolve from cached entry.
fn resolve_from_cache(scope: &Scope, entry: CacheEntry, answer: BytesMut) -> Result<BytesMut> {
    let cached = entry.as_message();
    let elapsed = entry.elapsed();

    // Build response from cached message
    let mut message = MessageBuilder::from_buf(answer);
    message.enable_compression();
    let header = message.header_mut();
    *header = *cached.header();
    header.set_id(scope.query.header().id());
    message.push(scope.question.clone()).unwrap();

    // Copy records from section with decayed TTL
    let result = cached.copy_records(message, |parsed| {
        if let Ok(rr) = parsed {
            if let Ok(Some(mut rr)) = rr.into_record::<UnknownRecordData>() {
                rr.set_ttl(rr.ttl().saturating_sub(elapsed));
                return Some(rr);
            }
        }
        None
    });

    match result {
        Ok(message) => Ok(message.finish()),
        Err(e) => Err(Error::Io(ErrorKind::InvalidData.into())),
    }
}

/// Fallback handler to resolve CHAOS zone requests
fn resolve_to_chaos(scope: &Scope, answer: BytesMut) -> Result<BytesMut> {
    // Fallback handler only implements CH TXT
    if scope.question.qtype() != Rtype::Txt {
        return resolve_to_error(scope, answer, Rcode::NotImp);
    }

    // Build message response header and question
    let mut message = {
        let mut message = MessageBuilder::from_buf(answer);
        let header = message.header_mut();
        *header = *scope.query.header();
        header.set_id(scope.query.header().id());
        header.set_qr(true);
        message.push(scope.question.clone()).unwrap();
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
fn resolve_to_error(scope: &Scope, answer: BytesMut, rcode: Rcode) -> Result<BytesMut> {
    let mut message = MessageBuilder::from_buf(answer);
    let header = message.header_mut();
    *header = *scope.query.header();
    header.set_id(scope.query.header().id());
    header.set_qr(true);
    header.set_rcode(rcode);
    message.push(scope.question.clone()).unwrap();
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
