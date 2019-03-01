//! Dynamic module support

use crate::context::Context;
use crate::error::Error;
use crate::query_router::Scope;
use crate::sandbox::{instantiate, Instance};
use bytes::BytesMut;
use guest::Action;
use log::*;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use stream_cancel::{StreamExt, Tripwire};
use tokio::await;
use tokio::prelude::*;
use tokio::timer::Interval;

#[derive(Debug)]
pub enum Phase {
    PreCache,
    PostCache,
}

type InstanceMap = HashMap<String, (Instance, SystemTime)>;

/// A loader to load apps from filesystem.
///
/// It finds the wasm binary from `location`, and tries to reload them
/// if mtime changes based on the `reload_interval_sec` setting.
pub struct FSLoader {
    context: Arc<Context>,
    loaded: Arc<RwLock<InstanceMap>>,
}

impl FSLoader {
    pub fn new(ctx: Arc<Context>) -> Self {
        FSLoader {
            context: ctx.clone(),
            loaded: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn reload(loader: Arc<Self>, cancel: Tripwire) {
        let dir = match &loader.context.config.apps_location {
            Some(s) => s.clone(),
            None => {
                return;
            }
        };

        let mut ticker = loader
            .context
            .config
            .apps_reload_interval_sec
            .map(|duration| Interval::new_interval(duration).take_until(cancel));

        while true {
            Self::reload_dir(
                loader.context.clone(),
                Path::new(&dir),
                loader.loaded.clone(),
            );

            if let Some(stream) = &mut ticker {
                if await!(stream.next()).is_some() {
                    continue;
                }
            }
            break;
        }

        // match loader.context.config.apps_reload_interval_sec {
        //     Some(duration) => {
        //         let mut stream = Interval::new_interval(duration).take_until(cancel);
        //         while let Some(_) = await!(stream.next()) {
        //             Self::reload_dir(
        //                 loader.context.clone(),
        //                 Path::new(&dir),
        //                 loader.loaded.clone(),
        //             );
        //         }
        //     }
        //     None => {
        //         Self::reload_dir(
        //             loader.context.clone(),
        //             Path::new(&dir),
        //             loader.loaded.clone(),
        //         );
        //     }
        // }
    }

    /// Spawns a async background reloader.
    pub fn spawn(loader: Arc<FSLoader>, tripwire: Tripwire) {
        tokio::spawn_async(
            async move {
                await!(FSLoader::reload(loader, tripwire));
            },
        );
    }

    pub async fn run_phase<'a>(
        &'a self,
        phase: Phase,
        scope: &'a Scope,
        answer: BytesMut,
    ) -> (Action, BytesMut) {
        let loaded = self.loaded.read();
        for (name, instance) in loaded.iter() {
            // TODO: implement multi phase hook in sandbox
        }
        (Action::Pass, answer)
    }

    fn reload_dir(
        ctx: Arc<Context>,
        dir: &Path,
        loaded: Arc<RwLock<InstanceMap>>,
    ) -> Result<(), Error> {
        if !dir.is_dir() {
            return Err(Error::Io(io::Error::from(io::ErrorKind::InvalidInput)));
        }

        for entry in fs::read_dir(dir)? {
            let path = entry?.path();

            let filename = match path.file_name().and_then(|x| x.to_str()) {
                Some(name) if name.ends_with(".wasm") => name.trim_end_matches(".wasm"),
                _ => continue,
            };

            if let Some(config) = &ctx.config.apps_config {
                if !config.contains_key(filename) {
                    continue;
                }
            }

            let time = std::fs::metadata(&path)?.modified()?;

            match loaded.read().get(&String::from(filename)) {
                Some(v) if v.1 == time => continue,
                _ => (),
            }

            info!("reloading module {} ", filename);
            let data = Self::read_to_end(PathBuf::from(&path))?;
            let instance = instantiate(String::from(filename), &data, ctx.clone())
                .map_err(|e| Error::from(format!("{:?}", e).as_str()))?;
            if let Some(old_instance) = loaded
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
