/// Loader for sandboxed applications.
use crate::config::Config;
use crate::context::Context;
use crate::query_router::Scope;
use crate::sandbox::{self, fsloader::FSLoader, Instance};
use bytes::BytesMut;
use guest_types as guest;
use log::*;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use stream_cancel::Tripwire;
use tokio::await;

/// Map of named guest app instances.
pub type InstanceMap = Arc<RwLock<HashMap<String, (Instance, SystemTime)>>>;

/// Generic loader interface.
enum Loader {
    FS(Arc<FSLoader>),
}

/// Interface for the guest app sandbox.
#[derive(Default)]
pub struct Sandbox {
    instances: InstanceMap,
    loader: Option<Loader>,
}

impl Sandbox {
    /// Spawns a async background reloader.
    pub fn start(&self, context: Arc<Context>, cancel: Tripwire) {
        match self.loader {
            Some(Loader::FS(ref loader)) => {
                // Load immediately on startup
                if let Err(e) = loader.load(&self.instances, &context) {
                    error!("failed to load apps: {:?}", e);
                }
                let instances = self.instances.clone();
                tokio::spawn_async(FSLoader::start(loader.clone(), instances, context, cancel))
            }
            None => {}
        }
    }

    /// Resolve apps for phase.
    pub async fn resolve<'a>(
        &'a self,
        phase: guest::Phase,
        scope: &'a Scope,
        mut answer: BytesMut,
    ) -> (BytesMut, guest::Action) {
        let mut action = guest::Action::Pass;
        let instances: Vec<Instance> = self
            .instances
            .read()
            .values()
            .map(|(x, _)| x.clone())
            .collect();
        trace!("resolving phase {:?}", phase);
        for instance in instances.iter() {
            match await!(sandbox::run_hook(instance, phase, scope, answer)) {
                Ok((_answer, _action)) => {
                    answer = _answer;
                    action = _action;
                }
                Err(e) => {
                    debug!("phase {:?} failed: {:?}", phase, e);
                    return (BytesMut::new(), guest::Action::Pass);
                }
            }
        }

        (answer, action)
    }
}

/// Cancel all running instances on close.
impl Drop for Sandbox {
    fn drop(&mut self) {
        for (_, (instance, ..)) in self.instances.write().drain() {
            instance.cancel();
        }
    }
}

/// Build from configuration pattern
impl From<&Arc<Config>> for Sandbox {
    fn from(config: &Arc<Config>) -> Self {
        let loader = match config.apps_location {
            Some(ref uri) => match uri.scheme_str() {
                None => {
                    let path = Path::new(uri.path());
                    Some(Loader::FS(Arc::new(FSLoader::new(
                        path,
                        config.apps_config.clone(),
                    ))))
                }
                _ => panic!("location scheme {:?} not supported", uri.scheme_str()),
            },
            None => None,
        };

        Self {
            loader,
            instances: InstanceMap::default(),
        }
    }
}
