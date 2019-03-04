use crate::{Context, Scope};
use bytes::{Bytes, BytesMut};
use core::ffi::c_void;
use futures::future::Shared;
use futures::sync::oneshot::{channel, Receiver, Sender};
use log::*;
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use slab::Slab;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use tokio::prelude::*;
use guest;

// Re-export environment instantiation.
use wasmer_runtime::{error, Ctx, Value};
mod host_calls;
mod loader;
pub use loader::FSLoader;

#[derive(Debug)]
pub enum CallError {
    IO(Error),
    VM(Box<error::CallError>),
}

/// Wrapper for `wasmer_runtime::Instance`, to implement traits and
/// methods.
pub struct InstanceWrapper {
    name: String,
    inner: Mutex<wasmer_runtime::Instance>,
    /// server context
    context: Arc<Context>,
    /// indexed by request_id
    request_states: RwLock<Slab<RequestState>>,
    /// guest registered futures
    guest_futures: RwLock<Slab<GuestFutureState>>,
    /// list of future ID to run
    scheduled_queue: Mutex<Vec<usize>>,
    /// function to call on each message
    callback_message: RwLock<HashMap<guest::Phase, GuestCallback>>,
    /// channel to cancel all the futures spawned by the instance
    cancel: (Mutex<Option<Sender<()>>>, Shared<Receiver<()>>),
}

unsafe impl Send for InstanceWrapper {}
unsafe impl Sync for InstanceWrapper {}

// // TODO: stop and recycle all the futures
impl Drop for InstanceWrapper {
    fn drop(&mut self) {
        let ptr = self.inner.lock().context_mut().data as *mut Instance;
        if ptr.is_null() {
            warn!("[{}] empty context ptr", self);
            return;
        }
        unsafe {
            Box::from_raw(ptr);
        }
    }
}

impl fmt::Display for InstanceWrapper {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

pub type Instance = Arc<InstanceWrapper>;

fn from_context(ctx: &mut Ctx) -> &'static mut Instance {
    unsafe { &mut *(ctx.data as *mut Instance) }
}

/// Make a instance from binary wasm data.
pub fn instantiate(name: String, data: &[u8], context: Arc<Context>) -> error::Result<Instance> {
    wasmer_runtime::instantiate(data, host_calls::import_objects()).map(|wasmer_instance| {
        let instance = Arc::new(InstanceWrapper {
            name: name,
            inner: Mutex::new(wasmer_instance),
            context: context,
            scheduled_queue: Mutex::new(Vec::new()),
            guest_futures: RwLock::new(Slab::new()),
            request_states: RwLock::new(Slab::new()),
            callback_message: RwLock::new(HashMap::new()),
            cancel: {
                let (s, r) = channel();
                (Mutex::new(Some(s)), r.shared())
            },
        });
        {
            let mut i = instance.inner.lock();
            let mut ctx = i.context_mut();
            ctx.data = Box::leak(Box::new(instance.clone())) as *mut _ as *mut c_void;
        }
        instance
    })
}

/// Start an instance by calling the function `run`.
pub fn run(instance: &Instance) -> impl Future<Item = (), Error = CallError> {
    match instance.inner.lock().call("run", &[]) {
        Ok(_) => future::Either::A({
            let mut guest_tasks = instance.scheduled_queue.lock();
            let guest_future = GuestFuture::new(instance.clone()).with_tasks(&*guest_tasks);
            guest_tasks.clear();

            guest_future.map(|_| ()).map_err(CallError::IO)
        }),
        Err(e) => future::Either::B(future::err(CallError::VM(e))),
    }
}

/// Run instance registered hook.
pub fn run_hook(
    instance: &Instance,
    phase: guest::Phase,
    scope: &Scope,
    answer: BytesMut,
) -> impl Future<Item = (BytesMut, guest::Action), Error = CallError> {
    // Check if callback is installed
    let callbacks = instance.callback_message.read();
    let cb = match callbacks.get(&phase) {
        Some(cb) => cb,
        None => return future::Either::A(future::ok((answer, guest::Action::Pass))),
    };

    // Register request state
    let req = GuestFuture::new(instance.clone()).with_request(scope, answer.clone());

    // Instantiate a future to drive the guest-side future
    match cb.call(&instance, Some(req.request_id.unwrap() as i32)) {
        Ok(values) => {
            // Check if task finished eagerly
            if let Some(Value::I32(res)) = values.first() {
                if let guest::Async::Ready(action) = guest::Async::from(*res) {
                    instance.scheduled_queue.lock().pop();
                    return future::Either::A(future::ok((answer, action.into())));
                }
            };

            // The closure registered a future, if the guest registered multiple tasks,
            // they will be executed sequentially.
            match instance.scheduled_queue.lock().pop() {
                Some(task_handle) => future::Either::B({
                    req.with_tasks(&[task_handle]).then(move |res| match res {
                        Ok((action, request)) => {
                            let answer = request.expect("request state").1;
                            Ok((answer, guest::Action::from(action)))
                        }
                        Err(e) => Err(CallError::IO(e)),
                    })
                }),
                // Closure did not register a future, something must be wrong
                None => future::Either::A(future::err(CallError::IO(Error::new(
                    ErrorKind::InvalidInput,
                    "closure does not return a future",
                )))),
            }
        }
        Err(message) => future::Either::A(future::err(message)),
    }
}

impl InstanceWrapper {
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn cancel(&self) {
        *self.cancel.0.lock() = None;
    }

    fn create_task(&self) -> usize {
        self.guest_futures
            .write()
            .insert(GuestFutureState::default())
    }

    fn get_requests(&self) -> RwLockReadGuard<Slab<RequestState>> {
        self.request_states.read()
    }

    fn get_requests_mut(&self) -> RwLockWriteGuard<Slab<RequestState>> {
        self.request_states.write()
    }

    fn remove_task(&self, task_id: usize) -> GuestFutureState {
        self.guest_futures.write().remove(task_id)
    }

    fn get_tasks(&self) -> RwLockReadGuard<Slab<GuestFutureState>> {
        self.guest_futures.read()
    }

    fn get_tasks_mut(&self) -> RwLockWriteGuard<Slab<GuestFutureState>> {
        self.guest_futures.write()
    }

    fn call(&self, fn_name: &str, args: &[Value]) -> Result<Vec<Value>, Box<error::CallError>> {
        self.inner.lock().call(fn_name, args)
    }
}

/// Execution state for each client request.
/// This allows storing state for per-request guest futures.
type RequestState = (Scope, BytesMut);

/// Indirect reference to guest installed callback.
#[derive(Clone, Copy, Default)]
pub(crate) struct GuestCallback {
    ptr: (i32, i32), // Fat pointer for guest closure
}

impl GuestCallback {
    /// Check if the callback pointer is valid.
    fn is_valid(&self) -> bool {
        self.ptr.0 >= 0 && self.ptr.1 >= 0
    }

    /// Call the guest callback through an indirect call.
    fn call(&self, instance: &Instance, request_id: Option<i32>) -> Result<Vec<Value>, CallError> {
        if !self.is_valid() {
            return Err(CallError::IO(ErrorKind::NotFound.into()));
        }

        let ptr = self.ptr;
        match request_id {
            Some(id) => instance
                .call(
                    "__hook_trampoline",
                    &[Value::I32(id), Value::I32(ptr.0), Value::I32(ptr.1)],
                )
                .map_err(|e| CallError::VM(e)),
            None => instance
                .call(
                    "__closure_trampoline",
                    &[Value::I32(ptr.0), Value::I32(ptr.1)],
                )
                .map_err(|e| CallError::VM(e)),
        }
    }
}

#[derive(Default)]
struct GuestFutureState {
    cb: GuestCallback,
    data: Option<Vec<u8>>,
    waiting: Option<task::Task>,
    closed: bool,
}

/// Future representing a guest generated stream of items.
struct GuestStream {
    instance: Instance,
    task_handle: usize,
    cancel: Shared<Receiver<()>>,
}

impl GuestStream {
    fn new(instance: Instance, task_handle: usize) -> Self {
        Self {
            cancel: instance.cancel.1.clone(),
            instance,
            task_handle,
        }
    }
}

impl Stream for GuestStream {
    type Item = Bytes;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.cancel.poll() {
            Ok(p) => {
                if p.is_ready() {
                    return Err(Error::new(ErrorKind::Other, "future canceled"));
                }
            }
            Err(_) => {
                return Err(Error::new(ErrorKind::Other, "future canceled"));
            }
        }

        match self.instance.get_tasks_mut().get_mut(self.task_handle) {
            Some(GuestFutureState {
                ref mut data,
                ref mut waiting,
                closed,
                ..
            }) => {
                let data = match data {
                    Some(ref mut data) => data,
                    None => return Err(ErrorKind::UnexpectedEof.into()),
                };

                // Remember task blocked on NotReady for later wakeup
                if data.is_empty() {
                    trace!(
                        "[{}] polling stream #{}, not ready",
                        self.instance,
                        self.task_handle
                    );
                    // Return EOF if all buffered data has been processed and closed flag is raised
                    if *closed {
                        trace!(
                            "[{}] polling stream #{}, EOF",
                            self.instance,
                            self.task_handle
                        );
                        if let Some(task) = waiting.take() {
                            task.notify();
                        }
                        return Ok(Async::Ready(None));
                    } else {
                        // Remember task blocked on NotReady for later wakeup
                        waiting.replace(task::current());
                        return Ok(Async::NotReady);
                    }
                }

                let v = Bytes::from(data.clone());
                trace!(
                    "[{}] polling stream #{}, ready {}B",
                    self.instance,
                    self.task_handle,
                    v.len()
                );
                data.clear();

                // Wake up the task waiting on this stream
                if let Some(task) = waiting.take() {
                    task.notify();
                }

                Ok(Async::Ready(Some(v)))
            }
            None => {
                trace!(
                    "[{}] tried polling stream #{}, not found",
                    self.instance,
                    self.task_handle
                );
                Err(ErrorKind::NotFound.into())
            }
        }
    }
}

impl Drop for GuestStream {
    fn drop(&mut self) {
        trace!("[{}] dropping stream #{}", self.instance, self.task_handle);
        drop(self.instance.remove_task(self.task_handle))
    }
}

/// Future representing an asynchronous guest computation.
pub struct GuestFuture {
    instance: Instance,
    task_queue: VecDeque<usize>,
    request_id: Option<usize>,
    cancel: Shared<Receiver<()>>,
}

impl GuestFuture {
    fn new(instance: Instance) -> Self {
        Self {
            cancel: instance.cancel.1.clone(),
            instance,
            task_queue: VecDeque::new(),
            request_id: None,
        }
    }

    /// Add guest task queue to the future.
    fn with_tasks(mut self, task_queue: &[usize]) -> Self {
        self.task_queue.extend(task_queue);
        self
    }

    /// Associate the future with the host request, the guest future takes ownership of the request.
    fn with_request(mut self, scope: &Scope, answer: BytesMut) -> Self {
        let request_id = self
            .instance
            .request_states
            .write()
            .insert((scope.clone(), answer));
        self.request_id = Some(request_id);
        self
    }

    /// Returns the host request associated with this future.
    fn request(&self) -> Option<RequestState> {
        match self.request_id {
            Some(request_id) => self.instance.get_requests().get(request_id).cloned(),
            None => None,
        }
    }

    /// Finish current guest task from the future, and remove it from the task queue.
    fn finish_current_task(&mut self) -> Option<GuestFutureState> {
        match self.task_queue.pop_front() {
            Some(task_handle) => Some(self.instance.remove_task(task_handle)),
            None => None,
        }
    }
}

impl Drop for GuestFuture {
    fn drop(&mut self) {
        trace!("[{}] dropping future #{:?}", self.instance, self.task_queue);
        if let Some(id) = self.request_id {
            let mut states = self.instance.request_states.write();
            if states.contains(id) {
                states.remove(id);
            }
        }
        for task_handle in self.task_queue.iter() {
            drop(self.instance.remove_task(*task_handle))
        }
    }
}

impl Future for GuestFuture {
    type Item = (guest::AsyncValue, Option<RequestState>);
    type Error = std::io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.cancel.poll() {
            Ok(p) => {
                if p.is_ready() {
                    return Err(Error::new(ErrorKind::Other, "future canceled"));
                }
            }
            Err(_) => {
                return Err(Error::new(ErrorKind::Other, "future canceled"));
            }
        }

        // Get next task callback from the queue
        let task_handle = match self.task_queue.front() {
            Some(task_handle) => *task_handle,
            None => {
                trace!("[{}] guest future no tasks to poll", self.instance);
                return Err(ErrorKind::UnexpectedEof.into());
            }
        };

        trace!("[{}] guest future polling #{}", self.instance, task_handle);

        // Get guest callback for the next task
        let cb = match self.instance.get_tasks().get(task_handle) {
            Some(ref state) => state.cb,
            None => return Err(ErrorKind::NotFound.into()),
        };

        // Poll guest future. The poller fn is not exported, so it can't be called directly,
        // so we use a built-in trampoline function to call it.
        match cb.call(&self.instance, None) {
            Ok(values) => {
                // Parse the async result code.
                let state = match values.first() {
                    Some(Value::I32(x)) => guest::Async::from(*x),
                    _ => guest::Async::Error(guest::Error::Unknown),
                };
                trace!(
                    "[{}] guest future #{} return: {:?}",
                    self.instance,
                    task_handle,
                    state
                );
                match state {
                    guest::Async::NotReady => Ok(Async::NotReady),
                    guest::Async::Error(e) => {
                        drop(self.finish_current_task());
                        Err(Error::new(ErrorKind::Other, e.to_string()))
                    }
                    guest::Async::Ready(v) => {
                        drop(self.finish_current_task());
                        if self.task_queue.is_empty() {
                            Ok(Async::Ready((v, self.request())))
                        } else {
                            trace!(
                                "[{}] guest future #{} finished as subtask: {:?}",
                                self.instance,
                                task_handle,
                                v
                            );
                            Ok(Async::NotReady)
                        }
                    }
                }
            }
            Err(message) => {
                warn!(
                    "[{}] guest future #{} trap: {:?}",
                    self.instance, task_handle, message
                );
                drop(self.finish_current_task());
                Err(ErrorKind::Other.into())
            }
        }
    }
}
