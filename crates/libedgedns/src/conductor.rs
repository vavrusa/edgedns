use crate::query_router::Scope;
use crate::cache::CacheKey;
use crate::codecs::*;
use domain_core::bits::*;
use futures::sync::{mpsc, oneshot};
use futures::future::Either;
use log::*;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fmt::Write;
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::slice::Iter;
use futures::stream::Stream;
use tokio::net::{TcpStream, UdpSocket};
use tokio::prelude::*;

/// Default buffer size for internal channels before backpressure.
const DEFAULT_CHANNEL_SIZE : usize = 1000;
/// Default timeout for message exchange
const DEFAULT_TIMEOUT : Duration = Duration::from_millis(1500);
/// Default keepalive interval for idle connections
const DEFAULT_KEEPALIVE : Duration = Duration::from_millis(10_000);

/// Origin trait returns a slice of addresses for conductor.
/// The implementations of the trait define the order and size of the slice
/// for each request.
pub trait Origin: Send + Sync {
	fn get(&self) -> &[SocketAddr];
	fn get_scoped(&self, request: &Scope) -> &[SocketAddr] {
		self.get()
	}
	fn iter(&self) -> Iter<SocketAddr> {
		self.get().iter()
	}
}

#[derive(Default)]
struct PendingQueries {
	inner: RwLock<HashMap<CacheKey, Vec<oneshot::Sender<Message>>>>
}

impl PendingQueries {
	pub fn start(&self, key: &CacheKey, sink: oneshot::Sender<Message>) -> bool {
		let mut locked = self.inner.write();
		match locked.get_mut(&key) {
			Some(v) => {
				v.push(sink);
				false
			}
			None => {
				locked.insert(key.clone(), vec![sink]);
				true
			}
		}
	}

	// Find the list of tickets waiting for this answer and clear it
	pub fn finish(&self, resp: &Message) {
		let key = resp.into();
		let mut locked = self.inner.write();
		match locked.remove(&key) {
			Some(sinks) => {
				info!("forwarding to {} sinks {}", sinks.len(), key);
				for sink in sinks {
					drop(sink.send(resp.clone()));
				}
			}
			None => {
				warn!("conductor received message {} that doesn't have a query waiting for it", key);
			}
		};
	}
}

type PendingConnectionSink = mpsc::Sender<(Message, oneshot::Sender<Message>)>;
type PendingConnections = HashMap<SocketAddr, PendingConnectionSink>;

/// Conductor internal configuration.
/// The feature flags should be set when creating a Conductor instance using Builder,
/// but they can be changed during runtime as well unlike Builder parameters.
#[derive(Clone)]
struct Config {
	enable_connection_reuse: bool,
	enable_tcp: bool,
	enable_udp: bool,
	queue_size: usize,
}

impl Default for Config {
	fn default() -> Self {
		Self {
			enable_connection_reuse: true,
			enable_tcp: true,
			enable_udp: true,
			queue_size: DEFAULT_CHANNEL_SIZE,
		}
	}
}

#[derive(Clone)]
pub struct Conductor {
	pending: Arc<PendingQueries>,
	connections: Arc<RwLock<PendingConnections>>,
	config: Config,
}

impl Conductor {
	pub fn new() -> Arc<Self> {
		Builder::default().build()
	}

	fn from_builder(builder: Builder) -> Arc<Self> {
		Arc::new(Self {
			pending: Arc::new(PendingQueries::default()),
			connections: Arc::new(RwLock::new(PendingConnections::new())),
			config: builder.config,
		})
	}

	fn find_open_connection(&self, origin: &Arc<Origin>) -> Option<(SocketAddr, PendingConnectionSink)> {
		if self.config.enable_connection_reuse {
			for addr in origin.get() {
				if let Some(sink) = self.connections.write().get(&addr) {
					return Some((*addr, sink.clone()));
				}
			}
		}

		None
	}

	fn exchange_with_established_connection(&self, sink: PendingConnectionSink, query: &Message) -> impl Future<Item = (), Error = IoError> {
		let (tx, rx) = oneshot::channel();
		let pending = self.pending.clone();
		sink.send((query.clone(), tx))
			.map_err(move |e| {
				warn!("failed to reuse send {}", e);
				IoError::new(ErrorKind::BrokenPipe, "cannot send to background connection")
			})
			.and_then(move |e| {
				info!("sent ok {:?}", e);
				rx
				.into_future()
				.timeout(DEFAULT_TIMEOUT / 2)
				.map_err(move |e| {
					warn!("failed to receive response {}", e);
					IoError::new(ErrorKind::TimedOut, "cannot receive from background connection")
				})
			})
			.and_then(move |res| {
				info!("received from bg {:?}", res);
				pending.finish(&res);
				Ok(())
			})
	}

	fn exchange_with_new_udp(&self, addr: &SocketAddr, query: Message) -> impl Future<Item = (), Error = IoError> {
		let pending = self.pending.clone();

		// Try to create a UDP socket, and wrap it in a transport codec
		let socket = match UdpSocket::bind(&"0.0.0.0:0".parse().unwrap()) {
			Ok(socket) => udp_framed_transport(socket),
			Err(e) => return Either::A(future::err(e))
		};

		// Exchange message over UDP
		let addr = *addr;
		Either::B(
			socket
			.send((query.as_bytes().clone(), addr))
			.and_then(move |stream| {
				stream
				// Filter only messages from requested target
				.filter_map(move |(response, from)| {
					if from == addr { Some(response) } else { None }
				})
				.into_future()
				.timeout(DEFAULT_TIMEOUT)
				.map_err(move |_e| {
					IoError::new(ErrorKind::TimedOut, "timed out when waiting for response on socket")
				})
				// Parse the response into message and unblock waiting futures
				.and_then(move |(response, _stream)| {
					match response {
						Some(response) => {
							match Message::from_bytes(response.into()) {
								Ok(message) => {
									pending.finish(&message);
									Ok(())
								},
								Err(_e) => Err(IoError::new(ErrorKind::InvalidData, "invalid response"))
							}
						},
						None => Err(IoError::new(ErrorKind::UnexpectedEof, "socket closed when waiting for response"))
					}
				})
			})
		)
	}

	fn exchange_with_new_tcp(&self, addr: &SocketAddr, query: Message) -> impl Future<Item = (Message, FramedStream), Error = IoError> {
		let pending = self.pending.clone();
		TcpStream::connect(addr)
			// .timeout(DEFAULT_TIMEOUT)
			// .map_err(move |e| {
			// 	warn!("error when connecting {:?}", e);
			// 	IoError::new(ErrorKind::ConnectionAborted, "could not connect to origin")
			// })
			.map(tcp_framed_transport)
			.and_then(move |stream| {
				stream
					.send(query.as_slice().into())
					.and_then(move |stream| stream.into_future()
					.timeout(DEFAULT_TIMEOUT)
					.map_err(move |_e| IoError::new(ErrorKind::UnexpectedEof, "no response within timeout")))
			})
			.and_then(move |(response, stream)| {
				match response {
					Some(response) => {
						match Message::from_bytes(response.into()) {
							Ok(message) => {
								pending.finish(&message);
								Ok((message, stream))
							},
							Err(_e) => Err(IoError::new(ErrorKind::InvalidData, "invalid response"))
						}
					},
					None => Err(IoError::new(ErrorKind::UnexpectedEof, "connection closed whilst waiting for response"))
				}
			})
	}

	fn save_established_connection(&self, addr: SocketAddr, stream: FramedStream) -> impl Future<Item = (), Error = IoError> {
		// Save connection in pending queue
		let connections = self.connections.clone();
		let (sender, receiver) = mpsc::channel(self.config.queue_size);
		connections.write().insert(addr, sender);

		// Spawn background message writer
		let pending = Arc::new(PendingQueries::default());
		let (sink, stream) = stream.split();
		let sender_future = {
			let pending = pending.clone();
			receiver
				.map(move |(msg, sink)| {
					info!("bg conn receiver got {:?}", msg);
					pending.start(&CacheKey::from(&msg), sink);
					msg.as_bytes().clone()
				})
				.timeout(DEFAULT_KEEPALIVE)
				.map_err(move |e| {
					info!("receiver error {:?}", e);
					IoError::new(ErrorKind::UnexpectedEof, "invalid response")
				})
				.fold(sink, move |sink, msg| {
					info!("forwarding {:?}", msg);
					sink.send(msg)
				})
				.then(move |res| {
					info!("done processing {:?}", res.is_ok());
					Ok(())
				})
		};

		// Spawn background message reader
		let receiver_future = {
			stream
				.timeout(Duration::from_millis(30_000))
				.for_each(move |resp| {
					info!("read response in bg connection {:?}", resp.len());
					if let Ok(packet) = Message::from_bytes(resp.into()) {
						pending.finish(&packet);
					}
					Ok(())
				})
				.map_err(move |e| warn!("read bg failed {:?}", e))
				.then(move |_| {
					info!("clearing conn for {}", addr);
					connections.write().remove(&addr);
					Ok(())
				})
		};

		sender_future.join(receiver_future).map(|_| ())
	}

	/// Try to select a viable origin endpoint and perform DNS message exchange.
	fn exchange(&self, scope: Scope, query: Message, origin: Arc<Origin>) -> impl Future<Item = (), Error = IoError> {
		
		// First try to find an open connection that can be reused.
		// If there's no open connection, or it doesn't produce a response
		// within a reasonable time, then continue.
		let config = self.config.clone();
		let try_reuse_connection = match self.find_open_connection(&origin) {
			Some((_, sink)) => {
				Either::A(self.exchange_with_established_connection(sink, &query))
			},
			None => Either::B(future::err(IoError::new(ErrorKind::NotConnected, "no background connection to origin"))),
		};

		// TODO: iterate over addresses
		let addr = *origin.get().first().unwrap();

		// Exchange the message over a new connection
		let conductor_ref = self.clone();
		let try_exchange_with_new_connection = if config.enable_tcp {
			Either::A(
				self.exchange_with_new_tcp(&addr, query)
					.and_then(move |(_, stream)| {
						if config.enable_connection_reuse {
							tokio::spawn(
								conductor_ref
									.save_established_connection(addr, stream)
									.map_err(move |e| {
										warn!("error in saved connection {:?}", e);
									})
							);
						}
						Ok(())
					})
			)
		} else {
			Either::B(self.exchange_with_new_udp(&addr, query))
		};

		// Compose the futures together
		try_reuse_connection.or_else(move |e| {
			info!("failed to reuse an established connection: {:?}", e);
			try_exchange_with_new_connection
		})
	}

	/// Resolve a query with given origin, and wait for response.
	pub fn resolve(&self, scope: Scope, query: Message, origin: Arc<Origin>) -> impl Future<Item = Message, Error = IoError> {
		// Create a waitable future for the query result
		let (tx, rx) = oneshot::channel::<Message>();
		let wait_response = rx
			.map_err(|_| IoError::new(ErrorKind::UnexpectedEof, "cannot receive a query response"))
			.into_future();

		// If the query is already being solved, register a waitable future
		if self.pending.start(&CacheKey::from(&query), tx) {
			Either::A(
				self.exchange(scope, query, origin)
				.and_then(|_| wait_response)
			)
		} else {
			Either::B(wait_response)
		}
	}

	pub fn process_list(&self, f: &mut String) {
		let pending_guard = self.pending.inner.write();
		for (key, ticket_list) in &*pending_guard {
			writeln!(
				f,
				"{}\t{} waiting",
				key,
				ticket_list.len()
			)
			.unwrap();
		}
	}
}

// Builder interface for creating a Conductor instance
#[derive(Default)]
pub struct Builder {
	config: Config,
}

impl Builder {
	/// Build conductor with support for UDP.
	#[allow(dead_code)]
	pub fn with_udp(mut self, value: bool) -> Self {
		self.config.enable_udp = value;
		self
	}

	/// Build conductor with support for TCP.
	#[allow(dead_code)]
	pub fn with_tcp(mut self, value: bool) -> Self {
		self.config.enable_tcp = value;
		if !value {
			self.config.enable_connection_reuse = false;
		}
		self
	}

	/// Build conductor with support for reusing TCP connections.
	/// This implies support for TCP.
	#[allow(dead_code)]
	pub fn with_tcp_reuse(mut self, value: bool) -> Self {
		self.config.enable_connection_reuse = value;
		if value {
			self.config.enable_tcp = value;	
		}
		self
	}

	/// Use defined queue size (default is 1000).
	#[allow(dead_code)]
	pub fn with_queue_size(mut self, value: usize) -> Self {
		self.config.queue_size = value;
		self
	}

	/// Convert the Builder into the Recursor with defined configuration.
	pub fn build(self) -> Arc<Conductor> {
		Conductor::from_builder(self)
	}
}

#[cfg(test)]
mod test {
	use super::{Builder, Conductor};
	use crate::query_router::Scope;
	use crate::test_utils::{echo_udp_server, spawn_and_wait, TestOrigin, DOMAINS};
	use bytes::Bytes;
	use domain_core::bits::*;
	use domain_core::iana::*;
	use std::sync::Arc;
	use std::net::SocketAddr;
	use std::time::Duration;
	use test::{black_box, Bencher};
	use tokio::prelude::*;
	use tokio::runtime::current_thread::Runtime;

	const MAX_TEST_DURATION: Duration = Duration::from_millis(60_000);

	fn bench_batched(b: &mut Bencher, conductor: Arc<Conductor>) {
		

		let (echo_server, addr) = echo_udp_server(MAX_TEST_DURATION);
		let peer_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
		let origin: Arc<TestOrigin> = Arc::new(addr.into());
		let messages : Vec<Message> = DOMAINS.iter().take(2).map(|dname| {
			let mut mb = MessageBuilder::with_capacity(512);
			mb.push(Question::new(dname, Rtype::Any, Class::Ch)).expect("pushed question");
			mb.freeze()
		}).collect();

		let scope = Scope::new(messages[0].as_bytes().clone(), peer_addr).unwrap();

		// Run mock responder
		let mut runtime = Runtime::new().expect("runtime");
		runtime.spawn(echo_server);

		let mut bench_closure = || {
			let fut = {
				let messages = messages.clone();
				let origin = origin.clone();
				let conductor = conductor.clone();
				let scope = scope.clone();
				let set = (0..1000).map(move |i| {
					conductor
						.resolve(scope.clone(), messages[i%2].clone(), origin.clone())
						.and_then(|_| Ok(()))
						.map_err(|e| eprintln!("resolver err {}", e))
				});
				future::join_all(set)
			};

			black_box(runtime.block_on(fut).expect("spawn and wait"));
		};

		// Warmup and test
		bench_closure();
		b.iter(bench_closure);
	}

	#[bench]
	fn batched_1k(b: &mut Bencher) {
		let conductor = Builder::default()
			.build();
		bench_batched(b, conductor)
	}

	#[bench]
	fn batched_udp_1k(b: &mut Bencher) {
		let conductor = Builder::default()
			.with_tcp(false)
			.build();
		bench_batched(b, conductor)
	}

	#[bench]
	fn batched_noreuse_1k(b: &mut Bencher) {
		let conductor = Builder::default()
			.with_tcp_reuse(false)
			.build();
		bench_batched(b, conductor)
	}
}
