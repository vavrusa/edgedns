//! A Client Queries Handler is the main entry point of a Resolver.
//!
//! It accepts queries received as messages from the Udp and Tcp listeners,
//! and initiate the chain of futures required to fetch the responses.
//!
//! The chain includes coalescing similar queries, retrying, marking servers as
//! unresponsive after too many timeouts, and bringing them back to life after
//! regular probes have been successfully received.

use super::{DEFAULT_GRACE_SEC, FAILURE_TTL, UPSTREAM_PROBES_DELAY_MS,
            UPSTREAM_QUERY_MAX_TIMEOUT_MS};
use crate::cache::{Cache, CacheKey};
use crate::client_query::{ClientQuery, ResolverResponse};
use coarsetime::{Duration, Instant};
use crate::config::Config;
use crate::dns;
use crate::dns::*;
use crate::errors::*;
use futures::Future;
use futures::Stream;
use futures::future;
use futures::sync::mpsc::Receiver;
use futures::sync::oneshot;
use crate::globals::Globals;
use jumphash::JumpHasher;
use parking_lot::{Mutex, RwLock};
use rand::prelude::*;
use rand::distributions::{Distribution, Uniform};
use crate::resolver::{LoadBalancingMode, ResolverCore};
use std::collections::HashMap;
use std::io;
use std::net;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::time;
use tokio::prelude::*;
use tokio::timer::{Timeout};
use crate::upstream_server::{UpstreamServer, UpstreamServerForQuery};
use crate::varz::Varz;
use log::{debug, info};

#[derive(Default)]
pub struct WaitingClients {
    pub client_queries: Vec<ClientQuery>,
    pub upstream_tx: Option<oneshot::Sender<Vec<u8>>>,
}

#[derive(Default)]
pub struct PendingQueriesInner {
    pub waiting_clients: HashMap<UpstreamQuestion, Arc<Mutex<WaitingClients>>>,
    pub local_question_to_waiting_client: HashMap<LocalUpstreamQuestion, UpstreamQuestion>,
}

#[derive(Clone, Default)]
pub struct PendingQueries {
    pub inner: Arc<RwLock<PendingQueriesInner>>,
}

pub struct ResolverQueriesHandler {
    globals: Globals,
    net_ext_udp_sockets_rc: Arc<Vec<net::UdpSocket>>,
    jumphasher: JumpHasher,
}

impl Clone for ResolverQueriesHandler {
    fn clone(&self) -> Self {
        ResolverQueriesHandler {
            globals: self.globals.clone(),
            net_ext_udp_sockets_rc: Arc::clone(&self.net_ext_udp_sockets_rc),
            jumphasher: self.jumphasher,
        }
    }
}

impl ResolverQueriesHandler {
    pub fn new(resolver_core: &ResolverCore) -> Self {
        ResolverQueriesHandler {
            globals: resolver_core.globals.clone(),
            net_ext_udp_sockets_rc: Arc::clone(&resolver_core.net_ext_udp_sockets_rc),
            jumphasher: resolver_core.jumphasher,
        }
    }

    pub fn fut_process_stream(
        &self,
        resolver_rx: Receiver<ClientQuery>,
    ) -> impl Future {
        let mut self_inner = self.clone();
        let fut_client_query = resolver_rx.for_each(move |client_query| {
            let fut = self_inner
                .fut_process_client_query(client_query)
                .map_err(|_| {});
            tokio::spawn(fut);
            Ok(())
        });
        fut_client_query.map_err(|_| io::Error::last_os_error())
    }

    fn fut_process_client_query(
        &mut self,
        mut client_query: ClientQuery,
    ) -> impl Future<Item = (), Error = DNSError> {
        debug!("Incoming client query");

        let (custom_hash, bypass_cache) = {
            let session_state = client_query.session_state.as_ref().unwrap().inner.read();
            (session_state.custom_hash, session_state.bypass_cache)
        };
        let local_upstream_question = LocalUpstreamQuestion {
            qname_lc: client_query.normalized_question.qname_lc.clone(), // XXX - maybe make qname_lc a Rc
            qtype: client_query.normalized_question.qtype,
            qclass: client_query.normalized_question.qclass,
            dnssec: client_query.normalized_question.dnssec,
            custom_hash,
            bypass_cache,
        };
        let mut pending_queries_inner = self.globals.pending_queries.inner.write();
        let upstream_question = pending_queries_inner
            .local_question_to_waiting_client
            .get(&local_upstream_question)
            .cloned();
        if let Some(upstream_question) = upstream_question {
            debug!("Already in-flight");
            let waiting_clients = pending_queries_inner
                .waiting_clients
                .get_mut(&upstream_question)
                .expect("No waiting clients, but existing local question");
            waiting_clients.lock().client_queries.push(client_query);
            return future::ok(());
        }
        let tid: u16 = rand::random();
        let packet = match dns::build_query_packet(&client_query.normalized_question, tid, false) {
            Err(e) => return future::err(e),
            Ok(packet) => packet,
        };
        {
            let session_state = &mut client_query.session_state.as_mut().unwrap().inner.write();
            if !session_state.director.upstream_servers_socket_addrs.is_empty() {
                let upstream_servers_for_query: Vec<UpstreamServerForQuery> =
                    session_state.director.upstream_servers_socket_addrs
                        .iter()
                        .map(|&remote_addr| remote_addr.into())
                        .collect();
                session_state.upstream_servers_for_query = upstream_servers_for_query;
            }
        }
        let remote_addr = {
            let upstream_servers_for_query = &client_query
                .session_state
                .as_ref()
                .unwrap()
                .inner
                .read()
                .upstream_servers_for_query;
            if upstream_servers_for_query.is_empty() {
                return future::err(DNSError::NoServers);
            }
            let upstream_server_i = self.jumphasher.slot(
                &NormalizedQuestionKey::from_normalized_question(&client_query.normalized_question),
                upstream_servers_for_query.len() as u32,
            ) as usize;
            let upstream_server_for_query = &upstream_servers_for_query[upstream_server_i];
            upstream_server_for_query.remote_addr
        };
        let net_ext_udp_sockets = &self.net_ext_udp_sockets_rc;
        let mut rng = rand::thread_rng();
        let random_ext_socket_i = Uniform::new(0, net_ext_udp_sockets.len()).sample(&mut rng);
        let net_ext_udp_socket = &net_ext_udp_sockets[random_ext_socket_i];
        if let Err(e) = net_ext_udp_socket.send_to(&packet, remote_addr) {
            return future::err(DNSError::Io(e));
        }
        debug!("Query sent to upstream");

        let upstream_question = UpstreamQuestion {
            qname_lc: local_upstream_question.qname_lc.clone(),
            qtype: local_upstream_question.qtype,
            qclass: local_upstream_question.qclass,
            local_port: net_ext_udp_socket.local_addr().unwrap().port(),
            tid,
            server_addr: remote_addr,
        };
        let already_present = pending_queries_inner
            .local_question_to_waiting_client
            .insert(local_upstream_question.clone(), upstream_question.clone()) // XXX - Make upstream_question a Rc
            .is_some();
        debug_assert!(!already_present);

        let (upstream_tx, upstream_rx): (
            oneshot::Sender<Vec<u8>>,
            oneshot::Receiver<Vec<u8>>,
        ) = oneshot::channel();

        let waiting_clients = Arc::new(Mutex::new(WaitingClients {
            client_queries: vec![client_query],
            upstream_tx: Some(upstream_tx),
        }));
        pending_queries_inner
            .waiting_clients
            .insert(upstream_question, waiting_clients.clone());

        let pending_queries = self.globals.pending_queries.clone();
        let local_upstream_question_inner = local_upstream_question.clone();
        let mut cache_inner = self.globals.cache.clone();
        let (min_ttl, max_ttl, failure_ttl) = (
            self.globals.config.min_ttl,
            self.globals.config.max_ttl,
            FAILURE_TTL,
        );
        let fut = upstream_rx
            .map_err(|_| {})
            .and_then(move |upstream_packet| {
                let response_base = ResolverResponse {
                    packet: Arc::new(upstream_packet),
                    dnssec: false,
                    session_state: None,
                };
                let mut waiting_clients = waiting_clients.lock();
                for client_query in &mut waiting_clients.client_queries {
                    let mut response = response_base.clone();
                    response.session_state = client_query.session_state.take();
                    let _ = client_query.response_tx.take().unwrap().send(response);
                }
                waiting_clients.client_queries.clear();

                let mut pending_queries = pending_queries.inner.write();
                let upstream_question = pending_queries
                    .local_question_to_waiting_client
                    .remove(&local_upstream_question_inner)
                    .expect("Local upstream question vanished");
                pending_queries
                    .waiting_clients
                    .remove(&upstream_question)
                    .expect("Waiting clients set vanished");

                if let Ok(ttl) = dns::min_ttl(&response_base.packet, min_ttl, max_ttl, failure_ttl)
                {
                    match dns::rcode(&response_base.packet) {
                        DNS_RCODE_NOERROR | DNS_RCODE_NXDOMAIN => {
                            let cache_key = CacheKey::from_local_upstream_question(
                                local_upstream_question_inner,
                            );
                            cache_inner.insert(cache_key, response_base.packet.to_vec(), ttl);
                        }
                        _ => {}
                    }
                }
                future::ok(())
            });

        let mut pending_queries = self.globals.pending_queries.clone();
        let globals = self.globals.clone();
        let fut_timeout = Box::new(fut)
            .timeout(
                time::Duration::from_millis(UPSTREAM_QUERY_MAX_TIMEOUT_MS),
            )
            .map_err(move |_| {
                info!("Upstream timeout");
                let upstream_question_waiting_clients =
                    pending_queries.remove_from_local_upstream_question(&local_upstream_question);
                if let Some((upstream_question, waiting_clients)) =
                    upstream_question_waiting_clients
                {
                    FailureHandler::handle_failure(globals, upstream_question, waiting_clients);
                }
            });

        tokio::spawn(fut_timeout);
        future::ok(())
    }
}

impl PendingQueries {
    pub fn remove_from_local_upstream_question(
        &mut self,
        local_upstream_question: &LocalUpstreamQuestion,
    ) -> Option<(UpstreamQuestion, Arc<Mutex<WaitingClients>>)> {
        let mut pending_queries = self.inner.write();
        pending_queries
            .local_question_to_waiting_client
            .remove(local_upstream_question)
            .and_then(|upstream_question| {
                let waiting_clients = pending_queries
                    .waiting_clients
                    .remove(&upstream_question)
                    .unwrap_or_else(|| Arc::new(Mutex::new(WaitingClients::default())));
                Some((upstream_question, waiting_clients))
            })
    }
}

struct FailureHandler;

impl FailureHandler {
    fn handle_failure(
        globals: Globals,
        upstream_question: UpstreamQuestion,
        waiting_clients: Arc<Mutex<WaitingClients>>,
    ) {
        let servfail_packet = match dns::build_servfail_packet(
            &upstream_question.qname_lc,
            upstream_question.qtype,
            upstream_question.qclass,
            upstream_question.tid,
        ) {
            Err(_) => return,
            Ok(servfail_packet) => servfail_packet,
        };
        let servfail_response = ResolverResponse {
            packet: Arc::new(servfail_packet),
            dnssec: false,
            session_state: None,
        };
        let mut waiting_clients = waiting_clients.lock();
        let client_queries = &mut waiting_clients.client_queries;
        for client_query in client_queries {
            let response =
                Self::get_stale_or_default_response(&globals, client_query, &servfail_response);
            let _ = client_query.response_tx.take().unwrap().send(response);
        }
    }

    fn get_stale_or_default_response(
        globals: &Globals,
        client_query: &mut ClientQuery,
        default_response: &ResolverResponse,
    ) -> ResolverResponse {
        let session_state = client_query
            .session_state
            .take()
            .expect("session_state is None");
        let (custom_hash, bypass_cache, grace) = {
            let session_state_inner = session_state.inner.read();
            let env_i64 = &session_state_inner.env_i64;
            let grace = *env_i64
                .get(&b"beresp.grace".to_vec())
                .or_else(|| env_i64.get(&b"beresp.stale_if_error".to_vec()))
                .unwrap_or(&(DEFAULT_GRACE_SEC as i64)) as u64;

            (
                session_state_inner.custom_hash,
                session_state_inner.bypass_cache,
                grace,
            )
        };
        let mut response = default_response.clone();
        response.session_state = Some(session_state);
        if !bypass_cache {
            let cache_key = CacheKey::from_normalized_question(
                &client_query.normalized_question,
                custom_hash,
                bypass_cache,
            );
            let cache_entry = globals.cache.clone().get(&cache_key);
            if let Some(cache_entry) = cache_entry {
                if grace >= cache_entry.ttl() {
                    response = ResolverResponse {
                        packet: cache_entry.packet,
                        dnssec: client_query.normalized_question.dnssec,
                        session_state: response.session_state,
                    };
                }
            }
        }
        response
    }
}
