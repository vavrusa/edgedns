//! Pre/post cache/request hooks

use crate::c_abi;
use crate::client_query::ClientQuery;
use dnssector::{self, DNSSector, ParsedPacket};
use glob::glob;
use libloading::{self, Library};
#[cfg(unix)]
use libloading::os::unix::Symbol;
#[cfg(windows)]
use libloading::os::windows::Symbol;
use nix::libc::{c_int, c_void};
use parking_lot::RwLock;
use qp_trie::Trie;
use siphasher::sip128::SipHasher13;
use std::ffi::OsStr;
use std::mem;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;
use crate::upstream_server::UpstreamServerForQuery;
use log::{debug, info, warn, error};

const MASTER_SERVICE_LIBRARY_NAME: &str = "master";
#[cfg(any(target_os = "macos", target_os = "ios"))]
const DLL_EXT: &str = "dylib";
#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
const DLL_EXT: &str = "so";
#[cfg(target_os = "windows")]
const DLL_EXT: &str = "dll";

#[derive(Clone, Debug, Default)]
pub struct Director {
    pub upstream_servers_socket_addrs: Vec<SocketAddr>,
}

#[derive(Clone, Debug)]
pub struct SessionStateInner {
    pub service_id: Option<Vec<u8>>,
    pub env_str: Trie<Vec<u8>, Vec<u8>>,
    pub env_i64: Trie<Vec<u8>, i64>,
    pub env_bool: Trie<Vec<u8>, bool>,
    pub backends: Trie<Vec<u8>, SocketAddr>,
    pub director: Director,
    pub upstream_servers_for_query: Vec<UpstreamServerForQuery>,
    pub custom_hash: (u64, u64),
    pub bypass_cache: bool,
}

impl Default for SessionStateInner {
    fn default() -> SessionStateInner {
        SessionStateInner {
            service_id: None,
            env_str: Trie::new(),
            env_i64: Trie::new(),
            env_bool: Trie::new(),
            backends: Trie::new(),
            upstream_servers_for_query: Vec::new(),
            director: Director::default(),
            custom_hash: (0, 0),
            bypass_cache: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SessionState {
    pub inner: Arc<RwLock<SessionStateInner>>,
}

impl SessionState {
    pub fn shallow_clone(&self) -> SessionState {
        let inner = self.inner.read();
        SessionState {
            inner: Arc::new(RwLock::new(inner.clone())),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Deliver = 1,
    DeliverStale = 2,
    Done = 3,
    Error = 4,
    Fetch = 5,
    Hash = 6,
    HitForPass = 7,
    Lookup = 8,
    Pass = 9,
    Pipe = 10,
    Restart = 11,
    Purge = 12,
    Synth = 13,
    Drop = 14,
    Fail = 15,
    Miss = 16,
    Default = 17,
}

impl From<Action> for c_int {
    fn from(v: Action) -> c_int {
        v as c_int
    }
}

impl From<c_int> for Action {
    fn from(id: c_int) -> Action {
        match id {
            x if x == Action::Deliver.into() => Action::Deliver,
            x if x == Action::DeliverStale.into() => Action::DeliverStale,
            x if x == Action::Done.into() => Action::Done,
            x if x == Action::Error.into() => Action::Error,
            x if x == Action::Fetch.into() => Action::Fetch,
            x if x == Action::Hash.into() => Action::Hash,
            x if x == Action::HitForPass.into() => Action::HitForPass,
            x if x == Action::Lookup.into() => Action::Lookup,
            x if x == Action::Pass.into() => Action::Pass,
            x if x == Action::Pipe.into() => Action::Pipe,
            x if x == Action::Restart.into() => Action::Restart,
            x if x == Action::Purge.into() => Action::Purge,
            x if x == Action::Synth.into() => Action::Synth,
            x if x == Action::Fail.into() => Action::Fail,
            x if x == Action::Miss.into() => Action::Miss,
            x if x == Action::Default.into() => Action::Default,
            _ => Action::Drop,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Stage {
    Recv,
    Hash,
    Hit,
    Miss,
    Deliver,
    Synth,
}

type HookSymbolClientT = unsafe extern "C" fn(
    *const c_abi::FnTable,
    *mut SessionState,
    *const dnssector::c_abi::FnTable,
    *mut ParsedPacket,
) -> c_int;

struct ServiceHooks {
    library: Arc<Library>,
    hook_recv: Option<Symbol<HookSymbolClientT>>,
    hook_deliver: Option<Symbol<HookSymbolClientT>>,
    hook_hit: Option<Symbol<HookSymbolClientT>>,
    hook_miss: Option<Symbol<HookSymbolClientT>>,
}

struct Service {
    service_hooks: Option<ServiceHooks>,
}

pub struct Hooks {
    services: Trie<Vec<u8>, Service>,
    master_service_id: Vec<u8>,
    libraries_path: Option<String>,
}

impl Service {
    fn new(library_path: Option<&str>) -> Result<Service, &'static str> {
        let library_path = match library_path {
            None => {
                return Ok(Service {
                    service_hooks: None,
                })
            }
            Some(library_path) => library_path,
        };
        let library = match Library::new(library_path) {
            Err(e) => {
                error!("Cannot load the dynamic library [{}] [{}]", library_path, e);
                return Err("Unable to load the dynamic library");
            }
            Ok(library) => Arc::new(library),
        };

        let library_inner = Arc::clone(&library);

        let hook_recv_hl: libloading::Result<libloading::Symbol<HookSymbolClientT>> =
            unsafe { library_inner.get(b"hook_recv") };
        let hook_recv = hook_recv_hl.ok().map(|hook| unsafe { hook.into_raw() });

        let hook_deliver_hl: libloading::Result<libloading::Symbol<HookSymbolClientT>> =
            unsafe { library_inner.get(b"hook_deliver") };
        let hook_deliver = hook_deliver_hl.ok().map(|hook| unsafe { hook.into_raw() });

        let hook_hit_hl: libloading::Result<libloading::Symbol<HookSymbolClientT>> =
            unsafe { library_inner.get(b"hook_hit") };
        let hook_hit = hook_hit_hl.ok().map(|hook| unsafe { hook.into_raw() });

        let hook_miss_hl: libloading::Result<libloading::Symbol<HookSymbolClientT>> =
            unsafe { library_inner.get(b"hook_miss") };
        let hook_miss = hook_miss_hl.ok().map(|hook| unsafe { hook.into_raw() });

        let service_hooks = ServiceHooks {
            library,
            hook_recv,
            hook_deliver,
            hook_hit,
            hook_miss,
        };
        Ok(Service {
            service_hooks: Some(service_hooks),
        })
    }
}

impl Hooks {
    pub fn load_library_for_service_id(
        &mut self,
        library_path_str: &str,
        service_id: &[u8],
    ) -> Result<(), &'static str> {
        debug!("Loading dynamic library [{}]", library_path_str);
        let services = &mut self.services;
        let service = match Service::new(Some(library_path_str)) {
            Ok(service) => service,
            Err(_) => return Err("Unable to register the service"),
        };

        if services.insert(service_id.to_vec(), service).is_some() {
            debug!("Replacing a previous version of the library");
        }
        Ok(())
    }

    pub fn load_library(&mut self, library_path: &PathBuf) -> Result<(), &'static str> {
        let stem = match library_path.file_stem() {
            None => return Err("Missing stem from file name"),
            Some(stem) => stem,
        };
        debug!("Loading dynamic library [{}]", library_path.display());
        let services = &mut self.services;
        let service_id = if stem == MASTER_SERVICE_LIBRARY_NAME {
            info!("Loading master dynamic library");
            &self.master_service_id
        } else {
            match stem.to_str() {
                None => return Err("Unsupported path name"),
                Some(stem) => stem.as_bytes(),
            }
        };
        let library_path_str = match library_path.to_str() {
            None => return Err("Unsupported path name"),
            Some(path_str) => path_str,
        };
        let service = match Service::new(Some(library_path_str)) {
            Ok(service) => service,
            Err(_) => return Err("Unable to register the service"),
        };

        if services.insert(service_id.to_vec(), service).is_some() {
            debug!("Replacing a previous version of the library");
        }
        Ok(())
    }

    fn load_libraries(&mut self) {
        let path_expr = {
            let libraries_path = match self.libraries_path {
                None => return,
                Some(ref libraries_path) => libraries_path,
            };
            format!("{}/*.{}", libraries_path, DLL_EXT)
        };
        for library_path in glob(&path_expr).expect("Unsupported path for dynamic libraries") {
            let library_path = match library_path {
                Err(_) => continue,
                Ok(ref library_path) => library_path,
            };
            match self.load_library(library_path) {
                Ok(()) => {}
                Err(e) => warn!("[{}]: {}", library_path.display(), e),
            }
        }
    }

    pub fn unregister_service(&mut self, service_id: &[u8]) -> Result<(), &'static str> {
        debug!("Unregistering service [{:?}]", service_id);
        self.services.remove(service_id);
        Ok(())
    }

    pub fn new(libraries_path: Option<&str>) -> Self {
        let services = Trie::new();
        let master_service_id = Vec::new();
        let mut hooks = Hooks {
            services,
            master_service_id,
            libraries_path: libraries_path.map(|x| x.to_owned()),
        };
        hooks.load_libraries();
        hooks
    }

    #[inline]
    pub fn enabled(&self, _stage: Stage) -> bool {
        let service = self.services.get(&self.master_service_id);
        match service {
            Some(x) => x.service_hooks.is_some(),
            None => false,
        }
    }

    fn apply_clientside_for_service(
        &self,
        service: &Service,
        session_state: &mut SessionState,
        parsed_packet: &mut ParsedPacket,
        stage: Stage,
    ) -> Action {
        let service_hooks = service.service_hooks.as_ref().unwrap();
        let hook = match stage {
            Stage::Recv => service_hooks.hook_recv.as_ref(),
            Stage::Deliver => service_hooks.hook_deliver.as_ref(),
            Stage::Miss => service_hooks.hook_miss.as_ref(),
            _ => return Action::Drop,
        };
        let hook = match hook {
            Some(hook) => hook,
            None => return Action::Default,
        };
        let fn_table = c_abi::fn_table();
        let dnssector_fn_table = dnssector::c_abi::fn_table();
        let action =
            unsafe { hook(&fn_table, session_state, &dnssector_fn_table, parsed_packet) }.into();
        action
    }

    fn apply_clientside_master(
        &self,
        session_state: &mut SessionState,
        parsed_packet: &mut ParsedPacket,
        stage: Stage,
    ) -> Result<Action, &'static str> {
        // master service hooks
        let service = self.services
            .get(&self.master_service_id)
            .expect("Nonexistent master service");
        let action =
            self.apply_clientside_for_service(service, session_state, parsed_packet, stage);
        Ok(action)
    }

    pub fn apply_clientside(
        &self,
        session_state: &mut SessionState,
        parsed_packet: &mut ParsedPacket,
        stage: Stage,
    ) -> Result<Action, &'static str> {
        if !self.enabled(stage) {
            return Ok(Action::Default);
        }

        let action = self.apply_clientside_master(session_state, parsed_packet, stage)?;
        match action {
            Action::Fail | Action::Drop | Action::Restart => return Ok(action),
            _ => {}
        }

        // service_id hooks
        let service = {
            let service_id = &session_state.inner.read().service_id;
            debug!("service_id={:?}", service_id);
            if service_id.is_none() {
                return Ok(action);
            }
            let service_id = service_id.as_ref().unwrap();
            match self.services.get(service_id) {
                None => {
                    warn!(
                        "service_id={:?} but no loaded shared library with that id",
                        service_id
                    );
                    return Ok(action);
                }
                Some(service) => service,
            }
        };
        let action =
            self.apply_clientside_for_service(service, session_state, parsed_packet, stage);
        Ok(action)
    }

    fn apply_serverside_for_service(
        &self,
        service: &Service,
        session_state: &mut SessionState,
        parsed_packet: &mut ParsedPacket,
        stage: Stage,
    ) -> Action {
        let service_hooks = service.service_hooks.as_ref().unwrap();
        let hook = match stage {
            Stage::Deliver => service_hooks.hook_deliver.as_ref(),
            Stage::Hit => service_hooks.hook_hit.as_ref(),
            _ => return Action::Drop,
        };
        let hook = match hook {
            Some(hook) => hook,
            None => return Action::Default,
        };
        let fn_table = c_abi::fn_table();
        let dnssector_fn_table = dnssector::c_abi::fn_table();
        let action =
            unsafe { hook(&fn_table, session_state, &dnssector_fn_table, parsed_packet) }.into();
        action
    }

    fn apply_serverside_master(
        &self,
        session_state: &mut SessionState,
        parsed_packet: &mut ParsedPacket,
        stage: Stage,
    ) -> Result<Action, &'static str> {
        let service = self.services
            .get(&self.master_service_id)
            .expect("Nonexistent master service");
        let action =
            self.apply_serverside_for_service(service, session_state, parsed_packet, stage);
        Ok(action)
    }

    pub fn apply_serverside(
        &self,
        session_state: &mut SessionState,
        packet: Vec<u8>,
        stage: Stage,
    ) -> Result<(Action, Vec<u8>), &'static str> {
        if !self.enabled(stage) {
            return Ok((Action::Pass, packet));
        }
        let ds = match DNSSector::new(packet) {
            Ok(ds) => ds,
            Err(e) => {
                warn!("Cannot parse packet: {}", e);
                return Err("Cannot parse packet");
            }
        };
        let mut parsed_packet = match ds.parse() {
            Ok(parsed_packet) => parsed_packet,
            Err(e) => {
                warn!("Invalid packet: {}", e);
                return Err("Invalid packet");
            }
        };

        let action = self.apply_serverside_master(session_state, &mut parsed_packet, stage)?;
        match action {
            Action::Fail | Action::Drop | Action::Restart => {
                return Ok((action, parsed_packet.into_packet()))
            }
            _ => {}
        }

        // service_id hooks
        let service = {
            let service_id = &session_state.inner.read().service_id;
            debug!("service_id={:?}", service_id);
            if service_id.is_none() {
                return Ok((action, parsed_packet.into_packet()));
            }
            let service_id = service_id.as_ref().unwrap();
            match self.services.get(service_id) {
                None => {
                    warn!(
                        "service_id={:?} but no loaded shared library with that id",
                        service_id
                    );
                    return Ok((action, parsed_packet.into_packet()));
                }
                Some(service) => service,
            }
        };
        let action =
            self.apply_serverside_for_service(service, session_state, &mut parsed_packet, stage);
        Ok((action, parsed_packet.into_packet()))
    }
}
