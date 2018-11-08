use crate::context::Context;
use bytes::{BufMut, Bytes, BytesMut};
use domain_core::bits::*;
use std::io::{ErrorKind, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::await;

#[derive(Clone)]
pub struct Scope {
    pub query: Message,
    pub question: Question<ParsedDname>,
    pub peer_addr: SocketAddr,
}

impl Scope {
    pub fn new(query: Bytes, peer_addr: SocketAddr) -> Result<Self> {
        let query = Message::from_bytes(query).unwrap();
        match query.first_question() {
            Some(question) => Ok(Self {
                query,
                question,
                peer_addr,
            }),
            None => Err(ErrorKind::UnexpectedEof.into()),
        }
    }

    pub async fn resolve(self, context: Arc<Context>, mut answer: BytesMut) -> Result<BytesMut> {
    	// Update metrics
    	context.varz.inflight_queries.inc();
    	context.varz.client_queries.inc();
    	// Process query
        let mut cache = context.cache.clone();
        let cache_key = (&self.question).into();
        match cache.get(&cache_key) {
            Some(entry) => {
                let cached = entry.as_message();

                // Build response from cached message
                let mut message = MessageBuilder::from_buf(answer);
                message.enable_compression();
                let header = message.header_mut();
                *header = *cached.header();
                header.set_id(self.query.header().id());
                message.push(self.question.clone()).unwrap();

                // Copy records from section with decayed TTL
                let mut message = message.stream();
                cached
                    .iter()
                    .filter_map(|(rr, section)| {
                        // Filter invalid records
                        match rr {
                            Ok(rr) => {
                                if let Ok(Some(rr)) = rr.into_record::<UnknownRecordData>() {
                                    Some((rr, section))
                                } else {
                                    None
                                }
                            }
                            Err(_) => None,
                        }
                    })
                    .map(|(mut rr, section)| {
                        // Decay record TTL
                        rr.set_ttl(rr.ttl() - entry.elapsed());
                        (rr, section)
                    })
                    .for_each(|(rr, section)| {
                        // Push to the response
                        drop(message.push(rr, section));
                    });

                // TODO: copy OPT from query

                answer = message.finish();
            }
            None => {
                let resolvers = context.resolvers.clone();
                let recursor = resolvers.read().recursor.clone().unwrap();
                let message = await!(recursor.resolve(&self)).unwrap();
                cache.insert(cache_key, message.clone().into());
                answer.put_slice(message.as_slice());
            }
        };

        // Update metrics
        context.varz.inflight_queries.dec();

        Ok(answer)
    }
}

#[cfg(test)]
mod test {
    use super::Scope;
    use crate::test_utils::{DOMAINS, test_context};
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
        let messages : Vec<Bytes> = DOMAINS.iter().map(|dname| {
        	let mut mb = MessageBuilder::with_capacity(512);
        	mb.push(Question::new(dname, Rtype::Any, Class::Ch)).expect("pushed question");
        	mb.finish().into()
        }).collect();

        let bench_closure = || {
            let context = context.clone();
            let messages = messages.clone();
            let buf = BytesMut::with_capacity(512);
            tokio::run_async(async move {
                for i in 1..1000 {
                	let req = Scope::new(messages[i - 1].clone(), peer_addr).unwrap();
                	let mut buf = buf.clone();
                	buf.reserve(512);
                    black_box(await!(req.resolve(context.clone(), buf)).expect("result"));

                }
            });
        };

        // Warmup and test
        bench_closure();
        b.iter(bench_closure);
    }
}
