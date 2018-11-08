//! UDP Listeners accept connections from clients over UDP.
//!
//! A query whose response is cached will be answered immediately by UDP Listeners.
//!
//! Queries for non-cached responses are forwarded to Resolvers over a single-message
//! Future channel.
//!
//! UDP Listeners don't keep any state and don't schedule any futures. Which also
//! means that they don't handle timeouts if Resolvers are unresponsive.
//!
//! Timeouts are currently handled by the Resolvers themselves.

use super::EdgeDNSContext;
use crate::cache::Cache;
use crate::client_query::*;
use crate::config::Config;
use crate::dns;
use dnssector::DNSSector;
use crate::errors::*;
use failure;
use futures::Sink;
use futures::future::{self, Future};
use futures::oneshot;
use futures::stream::Stream;
use futures::sync::mpsc::Sender;
use crate::globals::Globals;
use crate::hooks::{Action, Hooks, SessionState, Stage};
use parking_lot::RwLock;
use crate::query_router::*;
use crate::resolver_queries_handler::PendingQueries;
use std::io;
use std::net::{self, SocketAddr};
use std::rc::Rc;
use std::sync::{mpsc, Arc};
use std::thread;
use tokio::prelude::*;
use tokio::timer::*;
use tokio::net::{UdpSocket, UdpFramed};
use tokio::runtime::Runtime;
use tokio::codec::BytesCodec;
use tokio::reactor::Handle;
use crate::udp_stream::*;
use crate::net_helpers::*;
use crate::varz::Varz;
use bytes::{BytesMut, BufMut};

use super::{DNS_QUERY_MAX_SIZE, DNS_QUERY_MIN_SIZE};

pub struct UdpAcceptorCore {
    globals: Arc<Globals>,
    service_ready_tx: Option<mpsc::SyncSender<u8>>,
}

impl UdpAcceptorCore {
    async fn run(self, mut socket: UdpSocket) {

        let mut buf = vec![0; 1024];
        let mut answer_buf = BytesMut::with_capacity(1024);

        loop {
            let (sock, packet, count, peer) = await!(socket.recv_dgram(buf)).unwrap();
            self.globals.varz.client_queries_udp.inc();
            if count < DNS_QUERY_MIN_SIZE || count > DNS_QUERY_MAX_SIZE {
                self.globals.varz.client_queries_errors.inc();
                socket = sock;
                buf = packet;
                continue;
            }

            let dns_sector = DNSSector::new(packet[0..count].to_vec()).unwrap();
            buf = packet;

            let parsed_packet = match dns_sector.parse() {
                Ok(parsed_packet) => parsed_packet,
                Err(e) => { socket = sock; continue },
            };

            let session_state = SessionState::default();
            session_state.inner.write().upstream_servers_for_query = self.globals
                .default_upstream_servers_for_query
                .as_ref()
                .clone();
            let query_router = QueryRouter::create(
                self.globals.clone(),
                parsed_packet,
                &mut answer_buf,
                ClientQueryProtocol::UDP,
                session_state.clone(),
            );

            match query_router {
                Some(fut) => {
                    await!(fut).unwrap();
                },
                None => {}
            };

            let (sock, buf) = await!(sock.send_dgram(answer_buf, &peer)).unwrap();
            socket = sock;
            answer_buf = buf;
           
        }
    }

    pub async fn spawn(
        globals: Arc<Globals>,
        edgedns_context: &EdgeDNSContext,
        resolver_tx: Sender<ClientQuery>,
        service_ready_tx: mpsc::SyncSender<u8>,
    ) {
        let net_udp_socket =
            socket_udp_bound(&edgedns_context.config.listen_addr)
            .expect("Unable to create a UDP client socket");

        for _ in 0..255 {
            let globals = globals.clone();
            let service_ready_tx = service_ready_tx.clone();
            let socket = UdpSocket::from_std(
                net_udp_socket
                    .try_clone()
                    .expect("Unable to clone UDP socket"),
                    &Handle::default(),
            ).expect("Cannot create a UDP stream");

            tokio::spawn_async(async move {
                let udp_acceptor_core = UdpAcceptorCore {
                    globals: globals,
                    service_ready_tx: Some(service_ready_tx),
                };

                await!(udp_acceptor_core
                    .run(socket));
            });
        }

        service_ready_tx
            .send(0)
            .map_err(|_| io::Error::last_os_error()).unwrap();
    }
}
