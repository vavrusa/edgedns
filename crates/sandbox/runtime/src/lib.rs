use bytes::{Bytes, BytesMut};
use guest;
use libedgedns::{Context, Scope};
use log::*;
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use slab::Slab;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use tokio::prelude::*;
use core::ffi::c_void;

// Re-export environment instantiation.
use wasmer_runtime::{error, Ctx, Value};
mod host_calls;

#[derive(Debug)]
pub enum CallError {
  IO(Error),
  VM(Box<error::CallError>),
}

pub type Instance = Arc<Mutex<InstanceWrapper>>;

/// Wrapper for `wasmer_runtime::Instance`, to implement traits and
/// methods.
pub struct InstanceWrapper {
    name: String,
    inner: wasmer_runtime::Instance,
}

impl InstanceWrapper {
    pub fn new(name: String, i: wasmer_runtime::Instance) -> Self {
        InstanceWrapper{
            name: name,
            inner: i,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}
unsafe impl Send for InstanceWrapper {}
unsafe impl Sync for InstanceWrapper {}


impl Drop for InstanceWrapper {
    fn drop(&mut self) {
        unsafe {
            Box::from_raw(self.inner.context_mut().data as *mut SharedState);
        }
    }
}

pub fn instantiate(name: String, shared_state: SharedState, data: &[u8]) -> error::Result<Instance> {
    wasmer_runtime::instantiate(data, host_calls::import_objects())
        .map(|mut instance|{
            let mut ctx = instance.context_mut();
            ctx.data = Box::leak(Box::new(shared_state)) as *mut _ as *mut c_void;
            Arc::new(Mutex::new(InstanceWrapper::new(name, instance)))
        })
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
  fn call(
    &self,
    runtime: &SharedState,
    instance: Instance,
    request_id: Option<i32>,
  ) -> Result<Vec<Value>, CallError> {
    if !self.is_valid() {
      return Err(CallError::IO(ErrorKind::NotFound.into()));
    }

    let ptr = self.ptr;
    match request_id {
      Some(id) => runtime.call(
        instance.clone(),
        "__hook_trampoline",
        &[Value::I32(id), Value::I32(ptr.0), Value::I32(ptr.1)],
      ).map_err(|e| CallError::VM(e)),
      None => runtime.call(
        instance.clone(),
        "__closure_trampoline",
        &[Value::I32(ptr.0), Value::I32(ptr.1)],
      ).map_err(|e| CallError::VM(e)),
    }
  }
}

/// Current instance executed by the runtime.
/// The current is updated on each `RuntimeState::call` invocation,
/// as each runtime can execute 1 guest at a time.
#[derive(Clone, Copy, Debug)]
struct Current {
  //instance: Option<&Instance>,
}

impl Default for Current {
  fn default() -> Self {
    Self {
      //instance: None
    }
  }
}

/// Runtime state for guest exection.
struct RuntimeState {
  context: Arc<Context>,
  //runtime: Arc<Mutex<WasmContext>>,
  request_states: RwLock<Slab<RequestState>>,
  guest_futures: RwLock<Slab<GuestFutureState>>,
  scheduled_queue: Mutex<Vec<usize>>,
  callback_message: RwLock<GuestCallback>,
}

unsafe impl Send for RuntimeState {}
unsafe impl Sync for RuntimeState {}

/// Shareable handle for runtime state.
#[derive(Clone)]
pub struct SharedState {
  inner: Arc<RuntimeState>,
}

impl From<&mut Ctx> for &mut SharedState {
  fn from(ctx: &mut Ctx) -> &'static mut SharedState {
      unsafe { &mut *(ctx.data as *mut SharedState) }
  }
}

impl SharedState {
  pub fn new(context: Arc<Context>) -> Self {
    Self {
      inner: Arc::new(RuntimeState {
        context,
        scheduled_queue: Mutex::new(Vec::new()),
        guest_futures: RwLock::new(Slab::new()),
        request_states: RwLock::new(Slab::new()),
        callback_message: RwLock::new(GuestCallback::default()),
      }),
    }
  }

  pub fn invoke_start(
    &self,
    instance: Instance,
  ) -> impl Future<Item = (), Error = CallError> {
    match self.call(instance.clone(), "run", &[]) {
      Ok(_) => future::Either::A(self.spawned_futures(instance.clone())),
      Err(e) => future::Either::B(future::err(CallError::VM(e))),
    }
  }

  pub fn invoke_hook(
    &self,
    instance: Instance,
    scope: Scope,
    answer: BytesMut,
  ) -> impl Future<Item = (BytesMut, guest::Action), Error = CallError> {
    // Check if callback is installed
    let cb = self.inner.callback_message.read();

    // Register request state
    // TODO: move to separate state for each InstanceIndex
    let request_id = self.inner.request_states.write().insert((scope, answer));

    // Instantiate a future to drive the guest-side future
    match cb.call(self, instance.clone(), Some(request_id as i32)) {
      Ok(values) => {
        // Check if task finished eagerly
        if let Some(Value::I32(res)) = values.first() {
          if let guest::Async::Ready(action) = guest::Async::from(*res) {
            self.inner.scheduled_queue.lock().pop();
            let (_, answer) = self.inner.request_states.write().remove(request_id);
            return future::Either::A(future::ok((answer, action.into())));
          }
        };

        // TODO: forbid creating multiple futures from closure
        // The closure registered a future
        let self_clone = self.clone();
        match self.inner.scheduled_queue.lock().pop() {
          Some(task_handle) => future::Either::B(GuestFuture::new(self.clone(), instance.clone(), task_handle).then(
            move |res| {
              let (_, answer) = self_clone.inner.request_states.write().remove(request_id);
              match res {
                Ok(action) => Ok((answer, guest::Action::from(action))),
                Err(e) => Err(CallError::IO(e)),
              }
            },
          )),
          // Closure did not register a future, something must be wrong
          None => {
            drop(self_clone.inner.request_states.write().remove(request_id));
            future::Either::A(future::err(CallError::IO(Error::new(
              ErrorKind::InvalidInput,
              "closure does not return a future",
            ))))
          }
        }
      }
      Err(message) => {
        drop(self.inner.request_states.write().remove(request_id));
        future::Either::A(future::err(message))
      }
    }
  }

  fn create_task(&self) -> usize {
    self
      .inner
      .guest_futures
      .write()
      .insert(GuestFutureState::default())
  }

  fn get_requests(&self) -> RwLockReadGuard<Slab<RequestState>> {
    self.inner.request_states.read()
  }

  fn get_requests_mut(&self) -> RwLockWriteGuard<Slab<RequestState>> {
    self.inner.request_states.write()
  }

  fn remove_task(&self, task_id: usize) -> GuestFutureState {
    self.inner.guest_futures.write().remove(task_id)
  }

  fn get_tasks(&self) -> RwLockReadGuard<Slab<GuestFutureState>> {
    self.inner.guest_futures.read()
  }

  fn get_tasks_mut(&self) -> RwLockWriteGuard<Slab<GuestFutureState>> {
    self.inner.guest_futures.write()
  }

  fn call(
    &self,
    instance: Instance,
    field_name: &str,
    args: &[Value],
  ) -> Result<Vec<Value>, Box<error::CallError>> {
      instance.lock().inner.call(field_name, args)
  }

  fn spawned_futures(&self, instance: Instance) -> impl Future<Item = (), Error = CallError> {
    let mut queue = self.inner.scheduled_queue.lock();
    let vec: Vec<GuestFuture> = queue
      .iter()
      .map(|task_handle| {
        trace!("[] scheduling guest future #{}", *task_handle);
        GuestFuture::new(self.clone(), instance.clone(), *task_handle)
      })
      .collect();
    queue.clear();

    future::join_all(vec).then(move |_| Ok::<(), CallError>(()))
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
pub struct GuestFuture {
  host_state: SharedState,
  instance: Instance,
  task_handle: usize,
}

struct GuestStream {
  host_state: SharedState,
  //instance: &Instance,
  task_handle: usize,
}

impl Stream for GuestStream {
  type Item = Bytes;
  type Error = Error;

  fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
    match self
      .host_state
      .get_tasks_mut()
      .get_mut(self.task_handle)
    {
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
            "[] polling stream #{}, not ready",
            self.task_handle
          );
          // Return EOF if all buffered data has been processed and closed flag is raised
          if *closed {
            trace!("[] polling stream #{}, EOF", self.task_handle);
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
          "[] polling stream #{}, ready {}B",
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
          "[] tried polling stream #{}, not found",
          self.task_handle
        );
        Err(ErrorKind::NotFound.into())
      }
    }
  }
}

impl Drop for GuestStream {
  fn drop(&mut self) {
    trace!("[], dropping stream #{}", self.task_handle);
    drop(self.host_state.remove_task(self.task_handle))
  }
}

/// Future representing an asynchronous guest computation.
impl GuestFuture {
  fn new(host_state: SharedState, instance: Instance, task_handle: usize) -> Self {
    Self {
        host_state,
        instance,
        task_handle,
    }
  }
}

impl Future for GuestFuture {
  type Item = guest::AsyncValue;
  type Error = std::io::Error;

  fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
    let cb = match self.host_state.get_tasks().get(self.task_handle) {
      Some(ref state) => state.cb,
      _ => return Err(ErrorKind::NotFound.into()),
    };

    // Poll guest future. The poller fn is not exported, so it can't be called directly,
    // so we use a built-in trampoline function to call it.
    match cb.call(&self.host_state, self.instance.clone(), None) {
      Ok(values) => {
        // Parse the async result code.
        let state = match values.first() {
          Some(Value::I32(x)) => guest::Async::from(*x),
          _ => guest::Async::Error(guest::Error::Unknown),
        };
        trace!("[] guest future #{} return: {:?}", self.task_handle, state);
        match state {
          guest::Async::NotReady => Ok(Async::NotReady),
          guest::Async::Error(_) => {
            // TODO: map guest side error
            let _ = self.host_state.remove_task(self.task_handle);
            Err(ErrorKind::Other.into())
          }
          guest::Async::Ready(v) => {
            let _ = self.host_state.remove_task(self.task_handle);
            Ok(Async::Ready(v))
          }
        }
      }
      Err(message) => {
        warn!("[] guest future #{} trap: {:?}", self.task_handle, message);
        let _ = self.host_state.remove_task(self.task_handle);
        Err(ErrorKind::Other.into())
      }
    }
  }
}
