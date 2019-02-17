use crate::cache::Cache;
use crate::conductor::Conductor;
use crate::config::Config;
use crate::varz::{self, Varz};
use std::sync::Arc;

#[derive(Clone)]
pub struct Context {
    pub config: Arc<Config>,
    pub conductor: Arc<Conductor>,
    pub cache: Cache,
    pub varz: Varz,
}

impl Context {
    pub fn new(config: Config) -> Arc<Context> {
        let config = Arc::new(config);
        Arc::new(Context {
            cache: Cache::from(&config),
            conductor: Arc::new(Conductor::from(&config)),
            varz: varz::current(),
            config,
        })
    }
}
