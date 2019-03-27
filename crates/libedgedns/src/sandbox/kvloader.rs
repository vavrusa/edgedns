/// Apps loader that loads sandboxed apps from a key-value store.
use crate::context::Context;
use crate::error::Error;
use crate::sandbox::{sandbox::replace_instance, sandbox::InstanceMap};
use base64;
use log::*;
use memcache_async::ascii;
use ring::{digest, hmac};
use std::fmt::Display;
use std::io::{self, ErrorKind};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::{Duration, Instant};
use stream_cancel::{StreamExt, Tripwire};
use tokio::await;
use tokio::net::{TcpStream, UnixStream};
use tokio::prelude::*;
use tokio::timer::Interval;
use url::Url;

/// Interval between reloads.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

enum Client {
    Unix(ascii::Protocol<UnixStream>),
    Tcp(ascii::Protocol<TcpStream>),
}

impl Client {
    async fn get<'a, K: Display>(&'a mut self, key: &'a K) -> Result<Vec<u8>, io::Error> {
        match self {
            Client::Unix(ref mut c) => await!(c.get(key)),
            Client::Tcp(ref mut c) => await!(c.get(key)),
        }
    }
}

/// A loader to load apps from a key-value store.
///
/// It looks for app manifest under `{prefix}/manifest`, and tries to reload the apps from the manifest.
/// The apps are expected to be under keys `{prefix}/apps/{app}`.
///
/// The manifest contains the list of enabled apps with the following structure:
///
/// ```
/// <key>:<digest>[:<signature>]
/// ```
///
/// Where:
/// * `key` is the KV key containing the binary
/// * `digest` is a sha256 digest of the binary for integrity check and change notification (hex-encoded)
/// * `signature` is a HMAC signature of the binary (to make sure it was added by a trusted party) (base64 encoded)
pub struct KVLoader {
    uri: Url,
    _config: toml::value::Table,
    signing_key: Option<hmac::SigningKey>,
    prefix: String,
}

impl KVLoader {
    /// Creates a new KVLoader instance from the configuration.
    pub fn new(uri: Url, config: toml::value::Table) -> Self {
        let signing_key = uri
            .query_pairs()
            .find(|(k, _)| k == "signing_key")
            .and_then(|(_, v)| base64::decode_config(v.as_bytes(), base64::URL_SAFE).ok())
            .map(|x| hmac::SigningKey::new(&digest::SHA256, &x));

        // Warn user as the binaries from the KV will be implicitly trusted
        if signing_key.is_none() {
            warn!("apps loader configured without the 'signing_key', all apps in the KV will be trusted");
        }

        let prefix = uri
            .query_pairs()
            .find(|(k, _)| k == "prefix")
            .and_then(|(_, v)| Some(v.into_owned()))
            .unwrap_or("".to_owned());

        Self {
            uri,
            _config: config,
            signing_key,
            prefix,
        }
    }

    /// Starts the reloader that scans KV store for apps manifest.
    pub async fn start(
        me: Arc<KVLoader>,
        instances: InstanceMap,
        context: Arc<Context>,
        cancel: Tripwire,
    ) {
        let mut ticker = Interval::new(Instant::now(), DEFAULT_POLL_INTERVAL).take_until(cancel);
        while let Some(_) = await!(ticker.next()) {
            if let Err(e) = await!(me.load(&instances, &context)) {
                error!("failed to reload apps: {}", e);
            }
        }
    }

    /// Loads WASM apps inside the `path` with current configuration.
    pub async fn load<'a>(
        &'a self,
        instances: &'a InstanceMap,
        context: &'a Arc<Context>,
    ) -> Result<(), Error> {
        // Connect to the configured path
        let mut client = match self.uri.has_authority() {
            false => {
                trace!("connecting to local socket: {}", self.uri.path());
                let sock = await!(UnixStream::connect(self.uri.path()))?;
                Client::Unix(ascii::Protocol::new(sock))
            }
            true => {
                trace!("connecting to tcp socket: {}", self.uri);
                let mut addr = self.uri.with_default_port(|_| Err(()))?.to_socket_addrs()?;
                let sock = await!(TcpStream::connect(&addr.next().unwrap()))?;
                Client::Tcp(ascii::Protocol::new(sock))
            }
        };

        // Mark all apps to sweep the removed ones after reading the manifest
        for (_, mut value) in instances.write().iter_mut() {
            value.1 = SystemTime::UNIX_EPOCH;
        }

        // Read app manifest
        let now = SystemTime::now();
        let manifest_key = [&self.prefix, "/manifest"].concat();
        let manifest =
            String::from_utf8(await!(client.get(&manifest_key))?).unwrap_or("".to_owned());
        for mut pair in manifest.split(';').map(|x| x.split(',')) {
            let key = pair.next().ok_or(ErrorKind::InvalidData)?.trim().to_owned();
            let signature = pair.next().ok_or(ErrorKind::InvalidData)?.trim();
            let signature = base64::decode(&signature).map_err(|_| ErrorKind::InvalidData)?;

            // Check if the app digest has changed before reloading
            if let Some(ref mut x) = instances.write().get_mut(&key) {
                if x.2 == signature {
                    x.1 = now;
                    continue;
                }
            }

            let data = await!(client.get(&key))?;
            let data = base64::decode(&data).map_err(|_| ErrorKind::InvalidData)?;

            // If the signing key is provided, verify the app signature
            if let Some(ref signing_key) = self.signing_key {
                if let Err(e) = hmac::verify_with_own_key(signing_key, &data, &signature) {
                    error!("failed to verify signature for app {}: {}", key, e);
                    continue;
                }
            }

            replace_instance(key, &data, now, signature, &instances, context.clone())?;
        }

        // Mark all apps to sweep the removed ones after reading the manifest
        instances.write().retain(|k, v| {
            if v.1 == SystemTime::UNIX_EPOCH {
                trace!("closing app {}", k);
                v.0.cancel();
                false
            } else {
                true
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::{test_context, TEST_APP};
    use std::net::SocketAddr;
    use stream_cancel::Trigger;
    use tokio::await;
    use tokio::codec::{Framed, LinesCodec};
    use tokio::net::TcpListener;

    const SIGNING_KEY: &[u8] = b"mysecretkey";

    // Generate manifest for test app
    fn mock_manifest() -> String {
        let key = hmac::SigningKey::new(&digest::SHA256, SIGNING_KEY);
        let signature = hmac::sign(&key, &TEST_APP);
        format!("/apps/test:{}", base64::encode(&signature))
    }

    // Start a mock KV serving the test app
    fn mock_kv() -> (SocketAddr, Trigger) {
        let (trigger, cancel) = Tripwire::new();
        let listener =
            TcpListener::bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap()).expect("tcp listener");
        let local_addr = listener.local_addr().unwrap();
        tokio::spawn(
            listener
                .incoming()
                .take_until(cancel)
                .map_err(|e| panic!("{}", e))
                .for_each(|socket| {
                    let (sink, stream) = Framed::new(socket, LinesCodec::new()).split();
                    stream
                        .map(move |line| {
                            if line.contains("get /manifest") {
                                let x = mock_manifest();
                                format!("VALUE /manifest 0 {}\r\n{}\r\n", x.len(), x)
                            } else if line.contains("get /apps/test") {
                                let x = base64::encode(TEST_APP);
                                format!("VALUE /manifest 0 {}\r\n{}\r\n", x.len(), x)
                            } else {
                                format!("END\r\n")
                            }
                        })
                        .forward(sink)
                        .map_err(|err| eprintln!("I/O error: {:?}", err))
                        .and_then(move |_| Ok(()))
                })
                .and_then(|_| Ok(())),
        );

        (local_addr, trigger)
    }

    #[test]
    fn it_loads() {
        tokio::run_async(
            async move {
                // Create a mock KV and env
                let instances = InstanceMap::default();
                let context = test_context();
                let (addr, cancel) = mock_kv();

                // Create a loader with bad signing key
                let url = format!(
                    "memcache://{}?signing_key={}",
                    addr,
                    base64::encode(b"badkey")
                )
                .parse()
                .expect("url");
                let loader = KVLoader::new(url, toml::value::Table::new());
                await!(loader.load(&instances, &context)).expect("load works");
                assert_eq!(instances.read().len(), 0);

                // Create a loader with good signing key
                let url = format!(
                    "memcache://{}?signing_key={}",
                    addr,
                    base64::encode(SIGNING_KEY)
                )
                .parse()
                .expect("url");
                let loader = KVLoader::new(url, toml::value::Table::new());

                // Test that load from KV works
                await!(loader.load(&instances, &context)).expect("load works");
                assert_eq!(instances.read().len(), 1);
                assert_eq!(
                    instances.read().iter().next().map(|(x, _)| x.to_owned()),
                    Some("/apps/test".to_owned())
                );
                drop(cancel)
            },
        )
    }
}
