//! Global configuration of the EdgeDNS server
//!
//! This configuration cannot currently be updated without restarting the
//! server.

use crate::error::{Error, Result};
use crate::forwarder::LoadBalancingMode;
use log::*;
use native_tls::{Identity, TlsAcceptor};
use std::convert::TryFrom;
use std::fs::File;
use std::io::prelude::*;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use toml;
use url::Url;

/// EdgeDNS server type definition.
/// The server can operate in either forwarder mode, or fully recursive mode.
/// The forwarder mode can be set to either decrement TTL or not.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum ServerType {
    Authoritative,
    Forwarder,
    Recursive,
}

impl Default for ServerType {
    fn default() -> ServerType {
        ServerType::Forwarder
    }
}

impl FromStr for ServerType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "authoritative" => Ok(ServerType::Authoritative),
            "forwarder" => Ok(ServerType::Forwarder),
            "recursive" => Ok(ServerType::Recursive),
            _ => Err(Error::from("Invalid value for the server type")),
        }
    }
}

/// Configuration for a local listener.
#[derive(Clone)]
pub struct Listener {
    pub address: SocketAddr,
    pub tls: Option<TlsAcceptor>,
    pub proxy_protocol: bool,
    pub internal: bool,
}

impl Listener {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            tls: None,
            proxy_protocol: false,
            internal: false,
        }
    }

    fn with_config(&mut self, config: &toml::Value) -> Result<()> {
        // Enable proxy protocol (https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) on this listener.
        if let Some(val) = config.get("proxy_protocol") {
            self.proxy_protocol = val.as_bool().unwrap_or(false);
        }

        // Enable TLS with given certificate bundle on this listener.
        if let Some(tls) = config.get("tls") {
            // Only pkcs12 certificate is supported currently
            let cert = match tls.as_array() {
                Some(x) => {
                    if x.len() != 2 {
                        None
                    } else {
                        Some((x[0].as_str(), x[1].as_str()))
                    }
                }
                None => None,
            };

            match cert {
                Some((Some(cert), Some(pass))) => {
                    // Load the file from disk
                    let bytes = read_to_end(cert)?;
                    let identity = Identity::from_pkcs12(&bytes, &pass)
                        .map_err(|e| Error::from(format!("failed to load {}: {}", cert, e)))?;
                    let acceptor = TlsAcceptor::builder(identity).build()?;
                    self.tls = Some(acceptor);
                }
                _ => return Err(Error::from("expected an array with [cert.p12, password]")),
            }
        }

        Ok(())
    }
}

impl TryFrom<&str> for Listener {
    type Error = Error;
    fn try_from(x: &str) -> Result<Listener> {
        let address = x.parse::<SocketAddr>()?;
        Ok(Listener::new(address))
    }
}

#[derive(Clone)]
pub struct Config {
    pub server_type: ServerType,
    pub decrement_ttl: bool,
    pub upstream_servers_str: Vec<String>,
    pub lbmode: LoadBalancingMode,
    pub upstream_max_failure_duration: Duration,
    pub cache_size: usize,
    pub listen: Vec<Arc<Listener>>,
    pub webservice_enabled: bool,
    pub webservice_listen_addr: SocketAddr,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub user: Option<String>,
    pub group: Option<String>,
    pub chroot_dir: Option<String>,
    pub identity: Option<String>,
    pub version: Option<String>,
    pub max_tcp_clients: usize,
    pub max_waiting_clients: usize,
    pub max_active_queries: usize,
    pub max_clients_waiting_for_query: usize,
    pub max_upstream_connections: usize,
    pub tracing_enabled: bool,
    pub tracing_reporter_url: Option<Url>,
    pub tracing_sampling_rate: f64,
    pub tracing_only_failures: bool,
    pub apps_location: Option<Url>,
    pub apps_config: toml::value::Table,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_type: ServerType::default(),
            decrement_ttl: true,
            upstream_servers_str: Vec::new(),
            lbmode: LoadBalancingMode::default(),
            upstream_max_failure_duration: Duration::from_millis(2500),
            cache_size: 250_000,
            listen: vec![Arc::new(Listener::try_from("0.0.0.0:53").unwrap())],
            webservice_enabled: false,
            webservice_listen_addr: "0.0.0.0:9090".parse().unwrap(),
            min_ttl: 1,
            max_ttl: 86_400,
            user: None,
            group: None,
            chroot_dir: None,
            identity: None,
            version: None,
            max_tcp_clients: 250,
            max_waiting_clients: 1_000_000,
            max_active_queries: 100_000,
            max_clients_waiting_for_query: 1_000,
            max_upstream_connections: 500,
            tracing_enabled: false,
            tracing_reporter_url: None,
            tracing_sampling_rate: 0.01,
            tracing_only_failures: false,
            apps_location: None,
            apps_config: toml::value::Table::new(),
        }
    }
}

impl Config {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Config> {
        let mut fd = File::open(path)?;
        let mut toml = String::new();
        fd.read_to_string(&mut toml)?;
        Self::from_string(&toml)
    }

    pub fn from_string(toml: &str) -> Result<Config> {
        let toml_config = match toml.parse() {
            Ok(toml_config) => toml_config,
            Err(_) => {
                return Err(Error::from("Syntax error - config file is not valid TOML"));
            }
        };
        Self::parse(&toml_config)
    }

    fn parse(toml_config: &toml::Value) -> Result<Config> {
        let config_upstream = toml_config.get("upstream");
        let server_type = config_upstream
            .and_then(|x| x.get("type"))
            .map_or("authoritative", |x| {
                x.as_str().expect("upstream.type must be a string")
            })
            .parse()
            .expect("upstream.type");
        let decrement_ttl = match server_type {
            ServerType::Authoritative => false,
            ServerType::Forwarder => true,
            ServerType::Recursive => true,
        };

        let upstream_servers_str = config_upstream
            .and_then(|x| x.get("servers"))
            .expect("upstream.servers is required")
            .as_array()
            .expect("Invalid list of upstream servers")
            .iter()
            .map(|x| {
                x.as_str()
                    .expect("upstream servers must be strings")
                    .to_owned()
            })
            .collect();

        let lbmode_str = config_upstream
            .and_then(|x| x.get("strategy"))
            .map_or("uniform", |x| {
                x.as_str().expect("upstream.strategy must be a string")
            });
        let lbmode = match lbmode_str {
            "fallback" => LoadBalancingMode::Fallback,
            "uniform" => LoadBalancingMode::Uniform,
            "consistent" => LoadBalancingMode::Consistent,
            "minload" => LoadBalancingMode::MinLoad,
            _ => {
                return Err(Error::from(
                    "Invalid value for the load balancing/failover strategy",
                ));
            }
        };

        let upstream_max_failure_duration = Duration::from_millis(
            config_upstream
                .and_then(|x| x.get("max_failure_duration"))
                .map_or(2500, |x| {
                    x.as_integer()
                        .expect("upstream.max_failure_duration must be an integer")
                }) as u64,
        );

        let config_cache = toml_config.get("cache");

        let cache_size = config_cache
            .and_then(|x| x.get("max_items"))
            .map_or(250_000, |x| {
                x.as_integer().expect("cache.max_items must be an integer")
            }) as usize;

        let min_ttl = config_cache.and_then(|x| x.get("min_ttl")).map_or(60, |x| {
            x.as_integer().expect("cache.min_ttl must be an integer")
        }) as u32;

        let max_ttl = config_cache
            .and_then(|x| x.get("max_ttl"))
            .map_or(86_400, |x| {
                x.as_integer().expect("cache.max_ttl must be an integer")
            }) as u32;

        let config_network = toml_config.get("network");

        let listen = config_network.and_then(|x| x.get("listen")).map_or(
            vec![Arc::new(Listener::try_from("0.0.0.0:53").unwrap())],
            move |x| {
                match x.as_str() {
                    Some(x) => {
                        // Insert single listener
                        vec![Arc::new(
                            Listener::try_from(x)
                                .expect("network.listen must be an address or table"),
                        )]
                    }
                    None => {
                        // Collect multiple listeners
                        x.as_array()
                            .expect("network.listen must be an address or table")
                            .iter()
                            .map(|opts| {
                                let mut listener = Listener::try_from(
                                    opts.get("address")
                                        .expect("network.listen.address is required")
                                        .as_str()
                                        .expect("network.listen.address must be a string"),
                                )
                                .expect("network.listen.address is a valid address");

                                // Optional configuration
                                listener
                                    .with_config(opts)
                                    .expect("network.listen.tls configuration");

                                // Marking for internal interfaces
                                listener.internal = opts.get("internal").map_or(false, |x| {
                                    x.as_bool()
                                        .expect("network.listen.internal must be boolean")
                                });

                                Arc::new(listener)
                            })
                            .collect()
                    }
                }
            },
        );

        let config_webservice = toml_config.get("webservice");

        let webservice_enabled = config_webservice
            .and_then(|x| x.get("enabled"))
            .map_or(false, |x| {
                x.as_bool().expect("webservice.enabled must be a boolean")
            });

        let webservice_listen_addr = config_webservice
            .and_then(|x| x.get("listen"))
            .map_or("0.0.0.0:9090", |x| {
                x.as_str().expect("webservice.listen_addr must be a string")
            })
            .parse()
            .expect("webservice.listen_addr must be a valid address");

        let config_global = toml_config.get("global");

        let user = config_global
            .and_then(|x| x.get("user"))
            .map(|x| x.as_str().expect("global.user must be a string").to_owned());

        let group = config_global.and_then(|x| x.get("group")).map(|x| {
            x.as_str()
                .expect("global.group must be a string")
                .to_owned()
        });

        let chroot_dir = config_global.and_then(|x| x.get("chroot_dir")).map(|x| {
            x.as_str()
                .expect("global.chroot must be a string")
                .to_owned()
        });

        let max_tcp_clients =
            config_global
                .and_then(|x| x.get("max_tcp_clients"))
                .map_or(250, |x| {
                    x.as_integer()
                        .expect("global.max_tcp_clients must be an integer")
                }) as usize;

        let max_waiting_clients = config_global
            .and_then(|x| x.get("max_waiting_clients"))
            .map_or(1_000_000, |x| {
                x.as_integer()
                    .expect("global.max_waiting_clients must be an integer")
            }) as usize;

        let max_active_queries = config_global
            .and_then(|x| x.get("max_active_queries"))
            .map_or(100_000, |x| {
                x.as_integer()
                    .expect("global.max_active_queries must be an integer")
            }) as usize;

        let max_clients_waiting_for_query = config_global
            .and_then(|x| x.get("max_clients_waiting_for_query"))
            .map_or(1_000, |x| {
                x.as_integer()
                    .expect("global.max_clients_waiting_for_query must be an integer")
            }) as usize;

        let max_upstream_connections = config_global
            .and_then(|x| x.get("max_upstream_connections"))
            .map_or(500, |x| {
                x.as_integer()
                    .expect("global.max_upstream_connections must be an integer")
            }) as usize;

        if max_clients_waiting_for_query == 0 {
            warn!(
                "configured with unbounded number of clients waiting for query, default: {}",
                1_000
            );
        }

        let identity = config_global.and_then(|x| x.get("identity")).map(|x| {
            x.as_str()
                .expect("global.identity must be a string")
                .to_owned()
        });

        let version = config_global.and_then(|x| x.get("version")).map(|x| {
            x.as_str()
                .expect("global.version must be a string")
                .to_owned()
        });

        let config_tracing = toml_config.get("tracing");

        let tracing_enabled = config_tracing
            .and_then(|x| x.get("enabled"))
            .map_or(false, |x| {
                x.as_bool().expect("tracing.enabled must be a boolean")
            });

        let tracing_reporter_url = config_tracing.and_then(|x| x.get("reporter_url")).map(|x| {
            let uri = x.as_str().expect("tracing.reporter_url must be a string");
            Url::parse(uri).expect("tracing.reporter_url must be a valid URI")
        });

        let tracing_sampling_rate = config_tracing
            .and_then(|x| x.get("sampling_rate"))
            .map_or(0.01, |x| {
                x.as_float().expect("tracing.sampling_rate must be a float")
            }) as f64;

        let tracing_only_failures =
            config_tracing
                .and_then(|x| x.get("only_failures"))
                .map_or(false, |x| {
                    x.as_bool()
                        .expect("tracing.only_failures must be a boolean")
                });

        let config_apps = toml_config.get("apps");
        let apps_location = config_apps.and_then(|x| x.get("location")).map(|x| {
            let uri = x.as_str().expect("apps.location must be a string");
            Url::parse(uri).expect("apps.location must be a valid URI")
        });

        let apps_config = match config_apps {
            Some(config) => {
                let mut t = toml::value::Table::new();
                if let Some(table) = config.as_table() {
                    for (k, v) in table.iter() {
                        if v.is_table() {
                            t.insert(k.to_string(), v.clone());
                        }
                    }
                }
                t
            }
            None => toml::value::Table::new(),
        };

        Ok(Config {
            server_type,
            decrement_ttl,
            upstream_servers_str,
            lbmode,
            upstream_max_failure_duration,
            cache_size,
            listen,
            webservice_enabled,
            webservice_listen_addr,
            min_ttl,
            max_ttl,
            user,
            group,
            chroot_dir,
            identity,
            version,
            max_tcp_clients,
            max_waiting_clients,
            max_active_queries,
            max_clients_waiting_for_query,
            max_upstream_connections,
            tracing_enabled,
            tracing_reporter_url,
            tracing_sampling_rate,
            tracing_only_failures,
            apps_location,
            apps_config,
        })
    }
}

fn read_to_end<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut file = File::open(path)?;
    file.read_to_end(&mut buf)?;
    Ok(buf)
}
