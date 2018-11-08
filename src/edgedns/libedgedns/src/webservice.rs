//! Expose metrics via the Prometheus API

use futures::future;
use futures::prelude::*;
use tokio::runtime::Runtime;
use tokio::net::TcpListener;
use hyper::server::conn::Http;
use hyper::service::Service;
use hyper::{Body, Method, Request, Response, StatusCode};
use mime::Mime;
use prometheus::{self, Encoder, TextEncoder};
use std::io;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use log::info;
use crate::varz::{StartInstant, Varz};

use super::EdgeDNSContext;

#[derive(Clone)]
pub struct WebService {
    varz: Varz,
}

impl Service for WebService {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = hyper::Error;
    type Future = Box<Future<Item = Response<Body>, Error = Self::Error> + Send>;

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        if req.uri().path() != "/metrics" {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap();
            return Box::new(future::ok(response));
        }
        let StartInstant(start_instant) = self.varz.start_instant;
        let uptime = start_instant.elapsed().as_secs();
        self.varz.uptime.set(uptime as f64);
        let client_queries =
            self.varz.client_queries_udp.get() + self.varz.client_queries_tcp.get();
        self.varz.client_queries.set(client_queries);
        let metric_families = prometheus::gather();
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        Box::new(future::ok(
            Response::builder()
                .header(hyper::header::CONTENT_LENGTH, buffer.len() as u64)
                .header(hyper::header::CONTENT_TYPE, encoder.format_type())
                .body(Body::from(buffer))
                .unwrap(),
        ))
    }
}

impl WebService {
    fn new(edgedns_context: &EdgeDNSContext) -> WebService {
        WebService {
            varz: Arc::clone(&edgedns_context.varz),
        }
    }

    pub fn spawn(
        edgedns_context: &EdgeDNSContext,
        service_ready_tx: mpsc::SyncSender<u8>,
        rt: &mut Runtime,
    ) {
        let listen_addr = edgedns_context
            .config
            .webservice_listen_addr
            .parse()
            .expect("Unsupport listen address for the prometheus service");

        let service = WebService::new(edgedns_context);
        let listener = TcpListener::bind(&listen_addr).unwrap();
        let mut http = Http::new();
        http.keep_alive(false);
        let server = listener.incoming().for_each(move |io| {
                let conn = http.serve_connection(io, service.clone()).map_err(|_| {});
                tokio::spawn(conn);
                Ok(())
        });

        rt.spawn(server.map_err(|_| {}));
        service_ready_tx.send(2).unwrap();

        info!("Webservice started on {}", listen_addr);
    }
}
