use crate::cache::Cache;
use crate::conductor::Conductor;
use crate::config::Config;
use crate::recursor::Recursor;
use crate::varz::Varz;
use parking_lot::RwLock;
use std::sync::Arc;

// TODO: turn this into a hashmap
#[derive(Default)]
pub struct ContextResolvers {
    pub recursor: Option<Recursor>,
}

#[derive(Clone)]
pub struct Context {
    pub config: Arc<Config>,
    pub conductor: Arc<Conductor>,
    pub cache: Cache,
    pub varz: Varz,
    pub resolvers: Arc<RwLock<ContextResolvers>>,
}

impl Context {
    pub fn new(
        config: Arc<Config>,
        conductor: Arc<Conductor>,
        cache: Cache,
        varz: Varz,
    ) -> Arc<Context> {
        let context = Arc::new(Context {
            config,
            cache,
            conductor,
            varz,
            resolvers: Arc::new(RwLock::new(ContextResolvers::default())),
        });
        // TODO: add a separate function to load resolvers
        context.resolvers.write().recursor = Some(Recursor::new(context.clone()));
        context
    }
}
