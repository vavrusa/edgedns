//! Global configuration of the EdgeDNS server
//!
//! This configuration cannot currently be updated without restarting the
//! server.

use crate::forwarder::LoadBalancingMode;
use http::Uri;
use log::*;
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use toml;

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
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authoritative" => Ok(ServerType::Authoritative),
            "forwarder" => Ok(ServerType::Forwarder),
            "recursive" => Ok(ServerType::Recursive),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid value for the server type",
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub server_type: ServerType,
    pub decrement_ttl: bool,
    pub upstream_servers_str: Vec<String>,
    pub lbmode: LoadBalancingMode,
    pub upstream_max_failure_duration: Duration,
    pub cache_size: usize,
    pub udp_ports: u16,
    pub listen_addr: String,
    pub webservice_enabled: bool,
    pub webservice_listen_addr: String,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub user: Option<String>,
    pub group: Option<String>,
    pub chroot_dir: Option<String>,
    pub udp_acceptor_threads: usize,
    pub tcp_acceptor_threads: usize,
    pub dnstap_enabled: bool,
    pub dnstap_backlog: usize,
    pub dnstap_socket_path: Option<String>,
    pub identity: Option<String>,
    pub version: Option<String>,
    pub max_tcp_clients: usize,
    pub max_waiting_clients: usize,
    pub max_active_queries: usize,
    pub max_clients_waiting_for_query: usize,
    pub max_upstream_connections: usize,
    pub hooks_basedir: Option<String>,
    pub hooks_socket_path: Option<String>,
    pub tracing_enabled: bool,
    pub tracing_reporter_url: Option<Uri>,
    pub tracing_sampling_rate: f64,
    pub tracing_only_failures: bool,
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
            udp_ports: 8,
            listen_addr: "0.0.0.0:53".to_string(),
            webservice_enabled: false,
            webservice_listen_addr: "0.0.0.0:9090".to_string(),
            min_ttl: 1,
            max_ttl: 86_400,
            user: None,
            group: None,
            chroot_dir: None,
            udp_acceptor_threads: 1,
            tcp_acceptor_threads: 1,
            dnstap_enabled: false,
            dnstap_backlog: 0,
            dnstap_socket_path: None,
            identity: None,
            version: None,
            max_tcp_clients: 250,
            max_waiting_clients: 1_000_000,
            max_active_queries: 100_000,
            max_clients_waiting_for_query: 1_000,
            max_upstream_connections: 500,
            hooks_basedir: None,
            hooks_socket_path: None,
            tracing_enabled: false,
            tracing_reporter_url: None,
            tracing_sampling_rate: 0.01,
            tracing_only_failures: false,
        }
    }
}

impl Config {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Config, Error> {
        let mut fd = File::open(path)?;
        let mut toml = String::new();
        fd.read_to_string(&mut toml)?;
        Self::from_string(&toml)
    }

    pub fn from_string(toml: &str) -> Result<Config, Error> {
        let toml_config = match toml.parse() {
            Ok(toml_config) => toml_config,
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Syntax error - config file is not valid TOML",
                ));
            }
        };
        Self::parse(&toml_config)
    }

    fn parse(toml_config: &toml::Value) -> Result<Config, Error> {
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
            "uniform" => LoadBalancingMode::Uniform,
            "consistent" => LoadBalancingMode::Consistent,
            // "minload" => LoadBalancingMode::MinLoad,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
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

        let udp_ports = config_network
            .and_then(|x| x.get("udp_ports"))
            .map_or(8, |x| {
                x.as_integer()
                    .expect("network.udp_ports must be an integer")
            }) as u16;

        let listen_addr = config_network
            .and_then(|x| x.get("listen"))
            .map_or("0.0.0.0:53", |x| {
                x.as_str().expect("network.listen_addr must be a string")
            })
            .to_owned();

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
            .to_owned();

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

        let udp_acceptor_threads = config_global
            .and_then(|x| x.get("threads_udp"))
            .map_or(1, |x| {
                x.as_integer()
                    .expect("global.threads_udp must be an integer")
            }) as usize;

        let tcp_acceptor_threads = config_global
            .and_then(|x| x.get("threads_tcp"))
            .map_or(1, |x| {
                x.as_integer()
                    .expect("global.threads_tcp must be an integer")
            }) as usize;

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

        let config_dnstap = toml_config.get("dnstap");

        let dnstap_enabled = config_dnstap
            .and_then(|x| x.get("enabled"))
            .map_or(false, |x| {
                x.as_bool().expect("dnstap.enabled must be a boolean")
            });

        let dnstap_backlog = config_dnstap
            .and_then(|x| x.get("backlog"))
            .map_or(4096, |x| {
                x.as_integer().expect("dnstap.backlog must be an integer")
            }) as usize;

        let dnstap_socket_path = config_dnstap.and_then(|x| x.get("socket_path")).map(|x| {
            x.as_str()
                .expect("dnstap.socket_path must be a string")
                .to_owned()
        });

        let config_hooks = toml_config.get("hooks");

        let hooks_basedir = config_hooks.and_then(|x| x.get("basedir")).map(|x| {
            x.as_str()
                .expect("hooks.basedir must be a string")
                .to_owned()
        });

        let hooks_socket_path = config_hooks.and_then(|x| x.get("socket_path")).map(|x| {
            x.as_str()
                .expect("hooks.socket_path must be a string")
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
            Uri::from_str(uri).expect("tracing.reporter_url must be a valid URI")
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

        Ok(Config {
            server_type,
            decrement_ttl,
            upstream_servers_str,
            lbmode,
            upstream_max_failure_duration,
            cache_size,
            udp_ports,
            listen_addr,
            webservice_enabled,
            webservice_listen_addr,
            min_ttl,
            max_ttl,
            user,
            group,
            chroot_dir,
            udp_acceptor_threads,
            tcp_acceptor_threads,
            dnstap_enabled,
            dnstap_backlog,
            dnstap_socket_path,
            identity,
            version,
            max_tcp_clients,
            max_waiting_clients,
            max_active_queries,
            max_clients_waiting_for_query,
            max_upstream_connections,
            hooks_basedir,
            hooks_socket_path,
            tracing_enabled,
            tracing_reporter_url,
            tracing_sampling_rate,
            tracing_only_failures,
        })
    }
}
