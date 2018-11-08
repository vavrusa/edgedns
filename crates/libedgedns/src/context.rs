use crate::cache::Cache;
use crate::conductor::Conductor;
use crate::config::Config;
use crate::varz::Varz;
use std::sync::Arc;

#[derive(Clone)]
pub struct Context {
    pub config: Arc<Config>,
    pub conductor: Arc<Conductor>,
    pub cache: Cache,
    pub varz: Varz,
}

impl Context {
    pub fn new(
        config: Arc<Config>,
        conductor: Arc<Conductor>,
        cache: Cache,
        varz: Varz,
    ) -> Arc<Context> {
        Arc::new(Context {
            config,
            cache,
            conductor,
            varz,
        })
    }
}
