use super::{DNS_UDP_NOEDNS0_MAX_SIZE, DNS_MAX_TCP_SIZE, DNS_MAX_UDP_SIZE, DNS_RESPONSE_MIN_SIZE,
            UPSTREAM_TOTAL_TIMEOUT_MS};
use byteorder::{BigEndian, ByteOrder};
use crate::cache::*;
use crate::client_query::*;
use crate::dns;
use crate::dns::*;
use dnssector::*;
use crate::errors::*;
use failure;
use futures::{future, Future};
use futures::Async;
use futures::Sink;
use futures::prelude::*;
use futures::sync::mpsc::Sender;
use futures::sync::oneshot;
use futures::task;
use crate::globals::*;
use crate::hooks;
use crate::hooks::*;
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;
use std::time;
use std::error::Error;
use tokio::prelude::*;
use tokio::timer::Timeout;
use crate::upstream_server::*;
use log::debug;
use xfailure::xbail;
use bytes::{BytesMut, BufMut};

pub struct Answer {
    packet: Arc<Vec<u8>>,
    ttl: Option<u32>,
    special: bool,
}

impl From<Arc<Vec<u8>>> for Answer {
    fn from(packet: Arc<Vec<u8>>) -> Answer {
        Answer {
            packet: packet,
            ttl: None,
            special: false,
        }
    }
}

impl From<Vec<u8>> for Answer {
    fn from(packet: Vec<u8>) -> Answer {
        Answer {
            packet: Arc::new(packet),
            ttl: None,
            special: false,
        }
    }
}

impl From<(Vec<u8>, u32)> for Answer {
    fn from(packet_ttl: (Vec<u8>, u32)) -> Answer {
        Answer {
            packet: Arc::new(packet_ttl.0),
            ttl: Some(packet_ttl.1),
            special: false,
        }
    }
}

pub enum PacketOrFuture {
    Packet(Vec<u8>),
    Future(Box<Future<Item = Vec<u8>, Error = failure::Error> + Send>),
    PacketAndFuture((Vec<u8>, Box<Future<Item = Vec<u8>, Error = failure::Error> + Send>)),
}

pub enum AnswerOrFuture {
    Answer(Answer),
    Future(Box<Future<Item = (Answer, Option<SessionState>), Error = failure::Error> + Send>),
    AnswerAndFuture(
        (
            Answer,
            Box<Future<Item = (Answer, Option<SessionState>), Error = failure::Error> + Send>,
        ),
    ),
}

pub struct QueryRouter {
    globals: Arc<Globals>,
    session_state: Option<SessionState>,
}

impl QueryRouter {
    fn rewrite_according_to_original_query(
        &self,
        parsed_packet: &mut ParsedPacket,
        mut packet: &mut BytesMut,
        answer: Answer,
        protocol: ClientQueryProtocol,
    ) -> Result<(), failure::Error> {
        if answer.packet.len() < DNS_RESPONSE_MIN_SIZE || !dns::qr(&answer.packet) {
            xbail!(DNSError::Unexpected);
        }
        packet.put_slice(&*answer.packet);
        if let Some(ttl) = answer.ttl {
            dns::set_ttl(&mut packet, ttl).map_err(|_| DNSError::InternalError)?
        };

        {
            let original_qname = match parsed_packet.question_raw() {
                Some((original_qname, ..)) => original_qname,
                None => xbail!(DNSError::Unexpected),
            };
            dns::overwrite_qname(&mut packet, original_qname)?;
        }

        let tid = parsed_packet.tid();
        dns::set_tid(&mut packet, tid);

        // let packet_len = packet.len();
        // if packet.len() < DNS_RESPONSE_MIN_SIZE
        //     || (protocol == ClientQueryProtocol::UDP && packet_len > DNS_MAX_UDP_SIZE)
        //     || (protocol == ClientQueryProtocol::TCP && packet_len > DNS_MAX_TCP_SIZE)
        // {
        //     let normalized_question = match NormalizedQuestion::from_parsed_packet(parsed_packet) {
        //         Ok(normalized_question) => normalized_question,
        //         Err(_) => xbail!(DNSError::InvalidPacket),
        //     };
        //     let (qtype, qclass) = parsed_packet.qtype_qclass().ok_or(DNSError::Unexpected)?;
        //     let original_qname = match parsed_packet.question_raw() {
        //         Some((original_qname, ..)) => original_qname,
        //         None => xbail!(DNSError::Unexpected),
        //     };
        //     packet = dns::build_refused_packet(original_qname, qtype, qclass, tid)?;
        // }

        // match protocol {
        //     ClientQueryProtocol::UDP
        //         if packet_len > DNS_UDP_NOEDNS0_MAX_SIZE as usize
        //             && (packet_len > DNS_MAX_UDP_SIZE as usize
        //                 || packet_len > parsed_packet.max_payload()) =>
        //     {
        //         let (qtype, qclass) = parsed_packet.qtype_qclass().ok_or(DNSError::Unexpected)?;
        //         let original_qname = match parsed_packet.question_raw() {
        //             Some((original_qname, ..)) => original_qname,
        //             None => xbail!(DNSError::Unexpected),
        //         };
        //         packet = dns::build_tc_packet(original_qname, qtype, qclass, tid)?;
        //     }
        //     ClientQueryProtocol::UDP => debug_assert!(packet_len <= DNS_MAX_UDP_SIZE),

        //     ClientQueryProtocol::TCP => {
        //         if packet_len > DNS_MAX_TCP_SIZE {
        //             xbail!(DNSError::InternalError)
        //         }
        //         packet.reserve(2);
        //         unsafe {
        //             packet.set_len(2 + packet_len);
        //             ptr::copy(packet.as_ptr(), packet.as_mut_ptr().offset(2), packet_len);
        //         }
        //         BigEndian::write_u16(&mut packet, packet_len as u16);
        //     }
        // }
        Ok(())
    }

    fn deliver_to_client(
        &mut self,
        parsed_packet: &mut ParsedPacket,
        response_packet: &mut BytesMut,
        answer: Answer,
        protocol: ClientQueryProtocol,
    ) -> Result<(), failure::Error> {
        // let hooks_arc = self.globals.hooks_arc.read();
        // if hooks_arc.enabled(Stage::Deliver) {
        //     let (action, packet) = hooks_arc
        //         .apply_serverside(
        //             self.session_state.as_mut().unwrap(),
        //             answer.packet.clone(),
        //             Stage::Deliver,
        //         )
        //         .map_err(|e| DNSError::HookError(e))?;
        //     match action {
        //         Action::Deliver | Action::Synth | Action::Pass | Action::Pipe => {
        //             answer.packet = packet;
        //         }
        //         Action::Fail => {
        //             let tid = parsed_packet.tid();
        //             let (qtype, qclass) = parsed_packet.qtype_qclass().ok_or(DNSError::Unexpected)?;
        //             let original_qname = match parsed_packet.question_raw() {
        //                 Some((original_qname, ..)) => original_qname,
        //                 None => xbail!(DNSError::Unexpected),
        //             };
        //             answer.packet = dns::build_refused_packet(original_qname, qtype, qclass, tid)?;
        //         }
        //         _ => return Err(DNSError::Refused.into()),
        //     }
        // }
        self.rewrite_according_to_original_query(parsed_packet, response_packet, answer, protocol)
    }

    pub fn create(
        globals: Arc<Globals>,
        mut parsed_packet: ParsedPacket,
        response: &mut BytesMut,
        protocol: ClientQueryProtocol,
        session_state: SessionState,
    ) -> Option<Box<Future<Item = (), Error = failure::Error> + Send>> {
        let mut query_router = QueryRouter {
            globals,
            session_state: Some(session_state),
        };
        let mut resp_clone = response.clone();
        match query_router.create_answer(&mut parsed_packet) {
            Ok(AnswerOrFuture::Answer(answer)) => {
                    match query_router.deliver_to_client(&mut parsed_packet, response, answer, protocol) {
                        Ok(packet) => None,
                        Err(e) => Some(Box::new(future::err(e)))
                    }
            }
            Ok(AnswerOrFuture::Future(future)) => {
                let fut = future.and_then(move |(answer, session_state)| {
                    query_router.session_state =
                        session_state.or_else(|| Some(SessionState::default()));
                    let packet = query_router
                        .deliver_to_client(&mut parsed_packet, &mut resp_clone, answer, protocol)
                        .expect("Unable to rewrite according to the original query");
                    future::ok(packet)
                }).then(|packet| packet);
                Some(Box::new(fut))
            }
            Ok(AnswerOrFuture::AnswerAndFuture((answer, future))) => {
                match query_router.deliver_to_client(&mut parsed_packet, response, answer, protocol) {
                    Ok(packet) => {},
                    Err(e) => return Some(Box::new(future::err(e))),
                };
                let fut = future.and_then(move |(answer, session_state)| {
                    query_router.session_state =
                        session_state.or_else(|| Some(SessionState::default()));
                    future::ok(())
                });
                Some(Box::new(fut))
            }
            Err(e) => Some(Box::new(future::err(e))),
        }
    }

    fn create_answer(
        &mut self,
        mut parsed_packet: &mut ParsedPacket,
    ) -> Result<AnswerOrFuture, failure::Error> {
        if let Some(answer) =
            SpecialQueries::handle_special_queries(&self.globals, &mut parsed_packet)
        {
            return Ok(AnswerOrFuture::Answer(answer));
        };

        let hooks_arc = self.globals.hooks_arc.read();
        let action = hooks_arc
            .apply_clientside(
                self.session_state.as_mut().unwrap(),
                parsed_packet,
                Stage::Recv,
            )
            .map_err(|e| DNSError::HookError(e))?;
        match action {
            Action::Pass | Action::Pipe | Action::Purge => {
                self.session_state
                    .as_mut()
                    .expect("session_state is None")
                    .inner
                    .write()
                    .bypass_cache = true
            }
            Action::Drop => return Err(DNSError::Refused.into()),
            Action::Fail => {
                let tid = parsed_packet.tid();
                let (qtype, qclass) = parsed_packet.qtype_qclass().ok_or(DNSError::Unexpected)?;
                let original_qname = match parsed_packet.question_raw() {
                    Some((original_qname, ..)) => original_qname,
                    None => xbail!(DNSError::Unexpected),
                };
                let packet = dns::build_refused_packet(original_qname, qtype, qclass, tid)?;
                let answer = Answer::from(packet);
                return Ok(AnswerOrFuture::Answer(answer));
            }
            Action::Hash | Action::Lookup | Action::Default => {}
            _ => return Err(DNSError::Unimplemented.into()),
        }
        let (custom_hash, bypass_cache, prefetch) = {
            let session_state_inner = self.session_state
                .as_ref()
                .expect("session_state is None")
                .inner
                .read();
            let env_i64 = &session_state_inner.env_i64;
            let prefetch = *env_i64.get(&b"req.prefetch".to_vec()).unwrap_or(&0i64) as u64;
            (
                session_state_inner.custom_hash,
                session_state_inner.bypass_cache,
                prefetch,
            )
        };
        let mut answer_from_cache = None;
        let mut prefetched = false;
        if !bypass_cache {
            let cache_key =
                CacheKey::from_parsed_packet(&mut parsed_packet, custom_hash, bypass_cache)?;
            let cache_entry = self.globals.cache.clone().get2(&cache_key);
            if let Some(cache_entry) = cache_entry {
                if !cache_entry.is_expired() {
                    prefetched = cache_entry.ttl_is_less_than(prefetch);
                    let answer = Answer::from(cache_entry.packet);
                    answer_from_cache = Some(answer);
                }
            }
        }
        let answer_from_cache = if let Some(answer_from_cache) = answer_from_cache {
                return Ok(AnswerOrFuture::Answer(answer_from_cache));
        } else {
            if hooks_arc.enabled(Stage::Miss) {
                let action = hooks_arc
                    .apply_clientside(
                        self.session_state.as_mut().unwrap(),
                        parsed_packet,
                        Stage::Miss,
                    )
                    .map_err(|e| DNSError::HookError(e))?;
                match action {
                    Action::Pass | Action::Fetch | Action::Default => {}
                    Action::Drop | Action::Fail => return Err(DNSError::Refused.into()),
                    _ => return Err(DNSError::Unimplemented.into()),
                }
            }
            None
        };

        let (response_tx, response_rx) = oneshot::channel();
        let session_state = if prefetched {
            self.session_state.as_ref().unwrap().clone()
        } else {
            self.session_state.take().unwrap()
        };
        let client_query = ClientQuery::udp(response_tx, &mut parsed_packet, session_state)?;
        let fut_send = self.globals
            .resolver_tx
            .clone()
            .send(client_query)
            .map_err(|_| DNSError::InternalError.into());

        let client_query_fut = response_rx
            .map_err(|e| DNSError::InternalError.into())
            .and_then(move |resolver_response| {
                let answer = Answer::from(resolver_response.packet);
                Ok((answer, resolver_response.session_state))
            });

        let fut_timeout = fut_send
            .and_then(move |_| client_query_fut)
            .timeout(time::Duration::from_millis(UPSTREAM_TOTAL_TIMEOUT_MS))
            .map_err(move |e| {
                if e.is_inner() {
                    e.into_inner().unwrap()   
                } else {
                    DNSError::TimerError.into()
                }
            });

        if prefetched {
            Ok(AnswerOrFuture::AnswerAndFuture((
                answer_from_cache.unwrap(),
                Box::new(fut_timeout),
            )))
        } else {
            Ok(AnswerOrFuture::Future(Box::new(fut_timeout)))
        }
    }
}

struct SpecialQueries;

impl SpecialQueries {
    fn handle_special_queries(
        globals: &Globals,
        parsed_packet: &mut ParsedPacket,
    ) -> Option<Answer> {
        let tid = parsed_packet.tid();
        let (qtype, qclass) = parsed_packet.qtype_qclass()?;

        if qclass == dns::DNS_CLASS_IN && qtype == dns::DNS_TYPE_ANY {
            debug!("ANY query");
            let original_qname = match parsed_packet.question_raw() {
                Some((original_qname, ..)) => original_qname,
                None => return None,
            };
            let packet =
                dns::build_any_packet(original_qname, qtype, qclass, tid, globals.config.max_ttl)
                    .unwrap();
            let mut answer = Answer::from(packet);
            answer.special = true;
            return Some(answer);
        }

        if qclass == dns::DNS_CLASS_CH && qtype == dns::DNS_TYPE_TXT {
            debug!("CHAOS TXT");
            let original_qname = match parsed_packet.question_raw() {
                Some((original_qname, ..)) => original_qname,
                None => return None,
            };
            let packet = dns::build_version_packet(
                original_qname,
                qtype,
                qclass,
                tid,
                globals.config.max_ttl,
            ).unwrap();
            let mut answer = Answer::from(packet);
            answer.special = true;
            return Some(answer);
        }

        if qclass != dns::DNS_CLASS_IN {
            debug!("!IN class");
            let original_qname = match parsed_packet.question_raw() {
                Some((original_qname, ..)) => original_qname,
                None => return None,
            };
            let packet = dns::build_refused_packet(original_qname, qtype, qclass, tid).unwrap();
            let mut answer = Answer::from(packet);
            answer.special = true;
            return Some(answer);
        }
        None
    }
}
