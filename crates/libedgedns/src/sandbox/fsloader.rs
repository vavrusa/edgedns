/// Apps loader that loads sandboxed apps from a local directory.
use crate::context::Context;
use crate::error::Error;
use crate::sandbox::instantiate;
use crate::sandbox::sandbox::InstanceMap;
use log::*;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use stream_cancel::{StreamExt, Tripwire};
use tokio::await;
use tokio::prelude::*;
use tokio::timer::Interval;

/// Interval between reloads.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// A loader to load apps from local filesystem.
///
/// It looks for WASM files inside the `location` path, and tries to reload them
/// on regular intervals if the mtime changes.
pub struct FSLoader {
    path: PathBuf,
    config: toml::value::Table,
}

impl FSLoader {
    /// Creates a new FSLoader instance from the configuration.
    pub fn new<P: AsRef<Path>>(path: P, config: toml::value::Table) -> Self {
        FSLoader {
            path: path.as_ref().to_path_buf(),
            config,
        }
    }

    /// Starts the reloader that scans `path` for WASM apps.
    pub async fn start(
        me: Arc<FSLoader>,
        instances: InstanceMap,
        context: Arc<Context>,
        cancel: Tripwire,
    ) {
        let mut ticker = Interval::new_interval(DEFAULT_POLL_INTERVAL).take_until(cancel);
        while let Some(_) = await!(ticker.next()) {
            if let Err(e) = me.load(&instances, &context) {
                error!("failed to reload apps: {}", e);
            }
        }
    }

    /// Loads WASM apps inside the `path` with current configuration.
    pub fn load(&self, instances: &InstanceMap, context: &Arc<Context>) -> Result<(), Error> {
        if !self.path.is_dir() {
            return Err(Error::Io(io::Error::from(io::ErrorKind::InvalidInput)));
        }

        for entry in fs::read_dir(&self.path)? {
            let path = entry?.path();

            let filename = match path.file_name().and_then(|x| x.to_str()) {
                Some(name) if name.ends_with(".wasm") => name.trim_end_matches(".wasm"),
                _ => continue,
            };

            if !self.config.contains_key(filename) {
                continue;
            }

            let time = std::fs::metadata(&path)?.modified()?;

            match instances.read().get(&String::from(filename)) {
                Some(v) if v.1 == time => continue,
                _ => (),
            }

            trace!("reloading app '{}'", filename);
            let data = Self::read_to_end(PathBuf::from(&path))?;
            let instance = instantiate(String::from(filename), &data, context.clone())
                .map_err(|e| Error::from(format!("{:?}", e).as_str()))?;
            if let Some(old_instance) = instances
                .write()
                .insert(String::from(filename), (instance, time))
            {
                old_instance.0.cancel();
            }
        }

        Ok(())
    }

    fn read_to_end(path: PathBuf) -> Result<Vec<u8>, io::Error> {
        let mut buf: Vec<u8> = Vec::new();
        let mut file = std::fs::File::open(path)?;
        file.read_to_end(&mut buf)?;
        Ok(buf)
    }
}
