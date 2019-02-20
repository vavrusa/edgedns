use crate::config::Config;
use domain_core::bits::*;
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(feature = "tracing")]
mod zipkin_tracer {
    use super::*;
    use log::{debug, error};
    use parking_lot::Mutex;
    use rand::{thread_rng, Rng};
    use std::time::SystemTime;
    use stream_cancel::{StreamExt, Tripwire};
    use tokio::prelude::*;
    use zipkin::{self, report, span};
    use zipkin_reporter_http;

    struct Reporter {
        report: Box<dyn zipkin::Report + Send + Sync>,
        local_endpoint: zipkin::Endpoint,
    }

    /// Tracer is a globally shared instance for tracing requests.
    pub struct Tracer {
        reporter: Arc<Reporter>,
        worker: Mutex<Option<zipkin_reporter_http::Worker>>,
        sampling_rate: f64,
    }

    impl Tracer {
        /// Create a tracer configuration from configuration.
        pub fn from_config(config: &Arc<Config>) -> Self {
            let local_endpoint = zipkin::Endpoint::builder().service_name("edgedns").build();

            if !config.tracing_enabled {
                return Tracer {
                    reporter: Arc::new(Reporter {
                        report: Box::new(report::NopReporter {}),
                        local_endpoint,
                    }),
                    worker: Mutex::new(None),
                    sampling_rate: 0.0,
                };
            }

            let (report, worker) = if let Some(ref url) = config.tracing_reporter_url {
                debug!("configured tracer with reporter: {}", url);
                let (stream, report) = zipkin_reporter_http::Builder::new(url.clone())
                    .concurrency(1)
                    .queue_size(250)
                    .chunk_size(1)
                    .build();
                (
                    Box::new(report) as Box<zipkin::Report + Send + Sync>,
                    Some(stream),
                )
            } else {
                debug!("configured tracer with default logging reporter");
                (Box::new(report::LoggingReporter {}) as Box<_>, None)
            };

            Tracer {
                reporter: Arc::new(Reporter {
                    report,
                    local_endpoint,
                }),
                worker: Mutex::new(worker),
                sampling_rate: config.tracing_sampling_rate,
            }
        }

        /// Start the reporting worker.
        pub fn start(&self, tripwire: Tripwire) {
            if let Some(worker) = self.worker.lock().take() {
                debug!("starting tracing reporter worker");
                tokio::spawn(
                    worker
                        .take_until(tripwire)
                        .map_err(move |e| error!("error reporting trace spans: {:?}", e))
                        .for_each(move |_| Ok(())),
                );
            }
        }

        /// Create a new span to start tracing the query resolution.
        pub fn new_span(&self, question: &Question<ParsedDname>) -> Option<Span> {
            if self.sampling_rate <= 0.0 {
                return None;
            }

            if self.sampling_rate < 1.0 && thread_rng().gen_range(0.0, 1.0) >= self.sampling_rate {
                return None;
            }

            Some(
                Span::new(self.reporter.clone(), None)
                    .with_name("client-query")
                    .with_tag(
                        "dns.query",
                        &format!("{} {}", question.qname(), question.qtype()),
                    ),
            )
        }
    }

    /// Span is a trace of a single operation, you can create nested spans with `new_span`.
    #[derive(Clone)]
    pub struct Span {
        inner: Arc<Mutex<SpanInner>>,
    }

    impl Span {
        /// Create a new span with defined name and optional parent.
        fn new(reporter: Arc<Reporter>, parent: Option<Span>) -> Self {
            let span_id = Self::next_id();
            let mut span = span::Span::builder();

            // Configure span trace and parent
            let trace_id = match parent {
                Some(ref parent) => {
                    let parent = parent.inner.lock();
                    let trace_id = parent.trace_id;
                    span.trace_id(trace_id.into())
                        .parent_id(parent.span_id.into())
                        .id(span_id.into())
                        .kind(zipkin::Kind::Client);
                    trace_id
                }
                None => {
                    let trace_id = span_id;
                    span.trace_id(trace_id.into())
                        .id(span_id.into())
                        .kind(zipkin::Kind::Server);
                    trace_id
                }
            };

            Span {
                inner: Arc::new(Mutex::new(SpanInner {
                    reporter,
                    span,
                    sealed: Vec::new(),
                    parent,
                    timestamp: SystemTime::now(),
                    trace_id,
                    span_id,
                    disabled: false,
                })),
            }
        }
        /// Discard the trace, which prevents it from being reported.
        /// This is useful when deciding whether to report a span after it has been created.
        pub fn discard(&self) {
            self.inner.lock().disabled = true;
        }

        /// Create a new span with current span as its parent.
        pub fn new_child(&self) -> Self {
            let reporter = self.inner.lock().reporter.clone();
            Self::new(reporter, Some(self.clone()))
        }

        /// Set the span name.
        pub fn with_name(self, name: &str) -> Self {
            self.inner.lock().span.name(name);
            self
        }

        /// Set a span tag.
        pub fn with_tag(self, key: &str, value: &str) -> Self {
            self.tag(key, value);
            self
        }

        /// Set remote endpoint information.
        pub fn with_remote_endpoint(self, service_name: &str, addr: SocketAddr) -> Self {
            self.inner.lock().span.remote_endpoint(
                zipkin::Endpoint::builder()
                    .service_name(service_name)
                    .ip(addr.ip())
                    .port(addr.port())
                    .build(),
            );
            self
        }

        /// Add a tag.
        pub fn tag(&self, key: &str, value: &str) {
            self.inner.lock().span.tag(key, value);
        }

        /// Annotate the span with a value.
        pub fn annotate(&self, value: &str) {
            let annotation = zipkin::Annotation::now(value);
            self.inner.lock().span.annotation(annotation);
        }

        fn next_id() -> [u8; 8] {
            let mut id = [0; 8];
            thread_rng().fill(&mut id);
            id
        }
    }

    struct SpanInner {
        reporter: Arc<Reporter>,
        span: zipkin::span::Builder,
        sealed: Vec<zipkin::span::Span>,
        parent: Option<Span>,
        timestamp: SystemTime,
        trace_id: [u8; 8],
        span_id: [u8; 8],
        disabled: bool,
    }

    impl Drop for SpanInner {
        fn drop(&mut self) {
            if self.disabled {
                return;
            }

            // Update timing information and build the span
            let span = {
                self.span.timestamp(self.timestamp);
                if let Ok(duration) = self.timestamp.elapsed() {
                    self.span.duration(duration);
                }
                self.span
                    .local_endpoint(self.reporter.local_endpoint.clone());
                self.span.build()
            };
            self.sealed.push(span);

            // If the span is nested, fold into parent span, otherwise send to report.
            match self.parent {
                Some(ref parent) => {
                    let mut parent = parent.inner.lock();
                    if !parent.disabled {
                        parent.sealed.extend_from_slice(&self.sealed);
                    }
                }
                None => {
                    for span in self.sealed.iter() {
                        self.reporter.report.report2(span.clone());
                    }
                }
            }
        }
    }
}

// No-op implementation when tracing is disabled.
#[cfg(not(feature = "tracing"))]
mod noop_tracer {
    use super::*;
    use stream_cancel::Tripwire;

    pub struct Tracer;
    #[derive(Clone)]
    pub struct Span;

    impl Tracer {
        pub fn from_config(_config: &Arc<Config>) -> Self {
            Self {}
        }
        pub fn start(&self, _tripwire: Tripwire) {
            // NOP
        }
        pub fn new_span(&self, _question: &Question<ParsedDname>) -> Option<Span> {
            None
        }
    }

    impl Span {
        pub fn discard(&self) {
            unimplemented!()
        }
        pub fn new_child(&self) -> Self {
            unimplemented!()
        }
        pub fn with_name(self, _name: &str) -> Self {
            unimplemented!()
        }
        pub fn with_tag(self, _key: &str, _value: &str) -> Self {
            unimplemented!()
        }
        pub fn with_remote_endpoint(self, _service_name: &str, _addr: SocketAddr) -> Self {
            unimplemented!()
        }
        pub fn tag(&self, _key: &str, _value: &str) {
            unimplemented!()
        }
        pub fn annotate(&self, _value: &str) {
            unimplemented!()
        }
    }
}

#[cfg(feature = "tracing")]
pub use crate::tracing::zipkin_tracer::*;

#[cfg(not(feature = "tracing"))]
pub use crate::tracing::noop_tracer::*;
