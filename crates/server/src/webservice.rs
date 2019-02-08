//! Expose metrics via the Prometheus API
use hyper::rt::Future;
use hyper::service::service_fn_ok;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use libedgedns::Context;
use log::*;
use prometheus;
use prometheus::{Encoder, TextEncoder};
use std::sync::Arc;
use stream_cancel::Tripwire;
use tokio::executor::DefaultExecutor;

#[derive(Clone)]
pub struct WebService {}

impl WebService {
    pub fn spawn(context: Arc<Context>, tripwire: Tripwire) {
        let config = &context.config;
        if !config.webservice_enabled {
            return;
        }

        let listen_addr = config
            .webservice_listen_addr
            .parse()
            .expect("Unsupport listen address for the prometheus service");

        let new_service = move || {
            let context = context.clone();

            service_fn_ok(move |req: Request<Body>| {
                let mut response = Response::new(Body::empty());

                match (req.method(), req.uri().path()) {
                    // Serve metrics
                    (&Method::GET, "/metrics") => {
                        // Update lazily calculated metrics
                        let cache_stats = context.cache.stats();
                        context.varz.cache_hits.set(cache_stats.hits as f64);
                        context.varz.cache_misses.set(cache_stats.misses as f64);
                        context.varz.cache_inserted.set(cache_stats.inserted as f64);
                        context.varz.cache_evicted.set(cache_stats.evicted as f64);
                        context
                            .varz
                            .cache_recent_len
                            .set(cache_stats.recent_len as f64);
                        context.varz.cache_test_len.set(cache_stats.test_len as f64);
                        context
                            .varz
                            .cache_frequent_len
                            .set(cache_stats.frequent_len as f64);
                        // TODO: update uptime

                        // Render metrics in Prometheus format
                        let metric_families = prometheus::gather();
                        let mut buffer = vec![];
                        let encoder = TextEncoder::new();
                        encoder.encode(&metric_families, &mut buffer).unwrap();
                        *response.body_mut() = Body::from(buffer);
                    }

                    // Serve pending conductor queries
                    (&Method::GET, "/conductor") => {
                        let mut buffer = String::new();
                        context.conductor.clone().process_list(&mut buffer);
                        *response.body_mut() = Body::from(buffer);
                    }

                    // The 404 Not Found route...
                    _ => {
                        *response.status_mut() = StatusCode::NOT_FOUND;
                    }
                };

                response
            })
        };

        let server = Server::bind(&listen_addr)
            .executor(DefaultExecutor::current())
            .serve(new_service)
            .with_graceful_shutdown(tripwire)
            .map_err(|e| eprintln!("server error: {}", e));

        tokio::spawn(server.then(|_| {
            info!("webserver done");
            Ok(())
        }));
    }
}
