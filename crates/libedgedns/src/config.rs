//! Global configuration of the EdgeDNS server
//!
//! This configuration cannot currently be updated without restarting the
//! server.

use coarsetime::Duration;
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::path::Path;
use toml;
use crate::forwarder::LoadBalancingMode;



#[derive(Clone, Debug, Default)]
pub struct Config {
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
    pub dnstap_identity: Option<String>,
    pub dnstap_version: Option<String>,
    pub max_tcp_clients: usize,
    pub max_waiting_clients: usize,
    pub max_active_queries: usize,
    pub max_clients_waiting_for_query: usize,
    pub hooks_basedir: Option<String>,
    pub hooks_socket_path: Option<String>,
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
        let decrement_ttl_str = config_upstream
            .and_then(|x| x.get("type"))
            .map_or("authoritative", |x| {
                x.as_str().expect("upstream.type must be a string")
            });
        let decrement_ttl = match decrement_ttl_str {
            "authoritative" => false,
            "resolver" => true,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid value for the type of upstream servers. Must be \
                     'authoritative or 'resolver'",
                ));
            }
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

        let dnstap_identity = config_dnstap.and_then(|x| x.get("identity")).map(|x| {
            x.as_str()
                .expect("dnstap.identity must be a string")
                .to_owned()
        });

        let dnstap_version = config_dnstap.and_then(|x| x.get("version")).map(|x| {
            x.as_str()
                .expect("dnstap.version must be a string")
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

        Ok(Config {
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
            dnstap_identity,
            dnstap_version,
            max_tcp_clients,
            max_waiting_clients,
            max_active_queries,
            max_clients_waiting_for_query,
            hooks_basedir,
            hooks_socket_path,
        })
    }
}
