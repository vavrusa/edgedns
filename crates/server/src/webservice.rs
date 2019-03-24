/// An optional HTTP server serving metrics, troubleshooting tools, and DNS over HTTPS.
use base64;
use bytes::{Bytes, BytesMut};
use hyper::rt::Future;
use hyper::service::{make_service_fn, service_fn};
use hyper::{
    body, header, server::conn::AddrStream, Body, Chunk, Method, Request, Response, Server,
    StatusCode,
};
use libedgedns::{ClientRequest, Context, QueryRouter, UPSTREAM_TOTAL_TIMEOUT_MS};
use log::*;
use prometheus::{self, Encoder, TextEncoder};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;
use stream_cancel::Tripwire;
use tokio::executor::DefaultExecutor;
use tokio::prelude::*;
use url::Url;

#[derive(Clone)]
pub struct WebService {}

impl WebService {
    /// Spawns the service on listener from server configuration.
    pub fn spawn(
        context: Arc<Context>,
        query_router: Arc<QueryRouter>,
        tripwire: Tripwire,
    ) -> Result<(), hyper::error::Error> {
        let config = &context.config;
        if !config.webservice_enabled {
            return Ok(());
        }

        let listen_addr = config.webservice_listen_addr;
        let listener = TcpListener::bind(listen_addr).expect("bind to webservice.listen_addr");
        info!("webservice bound to {}", listen_addr);

        Self::spawn_listener(context, query_router, listener, tripwire)
    }

    /// Spawns the service on specified listener.
    pub fn spawn_listener(
        context: Arc<Context>,
        query_router: Arc<QueryRouter>,
        listener: TcpListener,
        tripwire: Tripwire,
    ) -> Result<(), hyper::error::Error> {
        let config = &context.config;
        if !config.webservice_enabled {
            return Ok(());
        }

        let service = make_service_fn(move |socket: &AddrStream| {
            let context = context.clone();
            let router = query_router.clone();
            let remote_addr = socket.remote_addr();

            // TODO: Support for client idle timeouts https://github.com/hyperium/hyper/issues/1628
            trace!("http client connected: {}", remote_addr);

            // Construct a service future for the client stream
            service_fn(move |req| response(req, context.clone(), router.clone(), remote_addr))
                .into_future()
                .timeout(Duration::from_millis(UPSTREAM_TOTAL_TIMEOUT_MS))
        });

        let server = Server::from_tcp(listener)?
            .http2_max_concurrent_streams(1024)
            .http1_max_buf_size(65535 + 2)
            .tcp_nodelay(true)
            .tcp_sleep_on_accept_errors(true)
            .executor(DefaultExecutor::current())
            .serve(service)
            .with_graceful_shutdown(tripwire)
            .map_err(|e| eprintln!("server error: {}", e));

        tokio::spawn(server.then(|_| Ok(())));

        Ok(())
    }
}

/// Generates a response to HTTP request.
fn response(
    req: Request<Body>,
    context: Arc<Context>,
    query_router: Arc<QueryRouter>,
    mut peer_addr: SocketAddr,
) -> Box<Future<Item = Response<Body>, Error = hyper::Error> + Send> {
    let mut response = Response::new(Body::empty());
    let base_url = Url::parse("http://localhost").unwrap();
    let (method, path) = (req.method(), req.uri().path());
    trace!("http request started: {} {}", method, path);

    // Get original peer address if the request is forwarded
    let h = req.headers();
    if let Some(Ok(original_peer)) = h
        .get(header::FORWARDED)
        .or_else(|| h.get("x-forwarded-for"))
        .map(|x| x.to_str())
    {
        trace!("request forwarded for {}", original_peer);
        peer_addr = original_peer.parse().unwrap_or(peer_addr);
    }

    match (method, path) {
        // Serve metrics
        (&Method::GET, "/metrics") => {
            // Update uptime
            context.varz.update_uptime();
            // Update lazily calculated metrics
            let cache_stats = context.cache.stats();
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

            // Render metrics in Prometheus format
            let metric_families = prometheus::gather();
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            *response.body_mut() = Body::from(buffer);
        }

        // Serve pending conductor queries
        (&Method::GET, "/pending-queries") => {
            let mut buffer = String::new();
            context.conductor.clone().pending_queries(&mut buffer);
            *response.body_mut() = Body::from(buffer);
        }

        // Serve DNS over HTTPS (GET)
        (&Method::GET, "/dns-query") => {
            let query_string = req
                .uri()
                .path_and_query()
                .map(|x| x.as_str())
                .unwrap_or(path);
            let request_url = match base_url.join(query_string) {
                Ok(url) => url,
                Err(e) => {
                    debug!("failed to parse request URI: {}", e);
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Box::new(future::ok(response));
                }
            };

            match h.get(header::ACCEPT).map(|v| v.to_str()) {
                Some(Ok("application/dns-message")) => {
                    if let Some((_, msg_b64)) = request_url.query_pairs().find(|(k, _v)| k == "dns")
                    {
                        if let Ok(msg) = base64::decode_config(&*msg_b64, base64::URL_SAFE) {
                            let (sender, resp_body) = Body::channel();
                            // Spawn client request as a separate future as Hyper doesn't support async
                            tokio::spawn_async(resolve_dns(
                                msg.into(),
                                peer_addr,
                                sender,
                                query_router.clone(),
                            ));
                            return Box::new(future::ok(Response::new(resp_body)));
                        }
                    }

                    *response.status_mut() = StatusCode::BAD_REQUEST;
                }
                Some(Ok("application/dns-json")) => {
                    *response.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
                }
                _ => {
                    *response.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
                }
            }
        }

        // Serve DNS over HTTPS (POST)
        (&Method::POST, "/dns-query") => {
            match h.get(header::CONTENT_TYPE).map(|v| v.to_str()) {
                Some(Ok("application/dns-message")) => {
                    let body = req.into_body().concat2().and_then(move |body| {
                        let (sender, resp_body) = Body::channel();
                        // Spawn client request as a separate future as Hyper doesn't support async
                        tokio::spawn_async(resolve_dns(
                            body.into(),
                            peer_addr,
                            sender,
                            query_router.clone(),
                        ));
                        Ok(Response::new(resp_body))
                    });

                    return Box::new(body);
                }
                Some(Ok("application/dns-json")) => {
                    *response.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
                }
                _ => {
                    *response.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
                }
            }
        }

        // The 404 Not Found route...
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };

    Box::new(future::ok(response))
}

/// Resolves DNS request and sends the response to the HTTP body channel.
async fn resolve_dns(
    msg: Bytes,
    peer_addr: SocketAddr,
    mut sender: body::Sender,
    query_router: Arc<QueryRouter>,
) {
    let client_request = match ClientRequest::new(msg, peer_addr) {
        Ok(client_request) => client_request,
        Err(e) => {
            warn!("failed to create a request: {:?}", e);
            return;
        }
    };

    match await!(query_router.resolve(client_request, BytesMut::new())) {
        Ok(msg) => {
            trace!("have response ready for http client: {:?}", msg);
            drop(sender.send_data(Chunk::from(msg.freeze())))
        }
        Err(e) => {
            trace!("failed to send response: {:?}", e);
        }
    }
}
