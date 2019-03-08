/// Apps loader that loads sandboxed apps from a local directory.
use crate::context::Context;
use crate::error::Error;
use crate::sandbox::{self, sandbox::InstanceMap};
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
            let filename = filename.to_owned();

            match instances.read().get(&filename) {
                Some(v) if v.1 == time => continue,
                _ => (),
            }

            // Instantiate the app
            trace!("reloading app '{}'", filename);
            let data = Self::read_to_end(PathBuf::from(&path))?;
            let instance = sandbox::instantiate(filename.clone(), &data, context.clone())
                .map_err(|e| Error::from(format!("{:?}", e).as_str()))?;

            // Replace the previous instance
            let prev = instances.write().insert(filename, (instance.clone(), time));
            if let Some((instance, ..)) = prev {
                instance.cancel();
            }

            // Start the entrypoint
            tokio::spawn(sandbox::run(instance).map_err(|e| {
                if !e.is_cancellation() {
                    error!("error while running the app: {:?}", e)
                }
            }));
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

#[cfg(test)]
mod test {
    use super::{FSLoader, InstanceMap};
    use crate::test_utils::{test_context, test_root_path, TEST_APP};
    use std::fs::File;
    use std::io::prelude::*;
    use toml;

    #[test]
    fn it_loads() {
        // Write a test app file
        let path = test_root_path();
        File::create(path.join("test_app.wasm"))
            .unwrap()
            .write_all(TEST_APP)
            .unwrap();

        // Try to load it from disk
        let context = test_context();
        let config = {
            let mut t = toml::value::Table::new();
            t.insert(
                "test_app".to_owned(),
                toml::value::Value::Table(toml::value::Table::new()),
            );
            t
        };

        let instances = InstanceMap::default();
        let loader = FSLoader::new(path, config);
        tokio::run_async(
            async move {
                loader.load(&instances, &context).expect("loaded instance");
                drop(loader);
            },
        );
    }
}
