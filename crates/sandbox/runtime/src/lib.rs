use bytes::{Bytes, BytesMut};
use guest;
use libedgedns::{Context, Scope};
use log::*;
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use slab::Slab;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::rc::Rc;
use std::sync::Arc;
use tokio::prelude::*;
use wasmtime_jit::{
  instantiate as wasm_instantiate, ActionOutcome, Compiler, InstanceIndex, Namespace, RuntimeValue,
};
use wasmtime_runtime::{Export, VMContext, VMMemoryDefinition};

// Re-export environment instantiation.
mod host_calls;
pub use crate::host_calls::instantiate;

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
    index: InstanceIndex,
    request_id: Option<i32>,
  ) -> Result<Vec<RuntimeValue>, Error> {
    if !self.is_valid() {
      return Err(ErrorKind::NotFound.into());
    }

    let ptr = self.ptr;
    match request_id {
      Some(id) => runtime.call(
        index,
        "__hook_trampoline",
        &[
          RuntimeValue::I32(id),
          RuntimeValue::I32(ptr.0),
          RuntimeValue::I32(ptr.1),
        ],
      ),
      None => runtime.call(
        index,
        "__closure_trampoline",
        &[RuntimeValue::I32(ptr.0), RuntimeValue::I32(ptr.1)],
      ),
    }
  }
}

/// Convenience structure for WASM compiler context.
pub struct WasmContext {
  compiler: Compiler,
  namespace: Namespace,
}

/// Current instance executed by the runtime.
/// The current is updated on each `RuntimeState::call` invocation,
/// as each runtime can execute 1 guest at a time.
#[derive(Clone, Copy, Debug)]
struct Current {
  index: Option<InstanceIndex>,
  memory: *mut VMMemoryDefinition,
}

impl Default for Current {
  fn default() -> Self {
    Self {
      index: None,
      memory: std::ptr::null_mut(),
    }
  }
}

/// Runtime state for guest exection.
struct RuntimeState {
  context: Arc<Context>,
  current: RwLock<Current>,
  runtime: Arc<Mutex<WasmContext>>,
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

impl From<*mut VMContext> for &mut SharedState {
  fn from(vmctx: *mut VMContext) -> &'static mut SharedState {
    unsafe {
      (&mut *vmctx)
        .host_state()
        .downcast_mut::<SharedState>()
        .expect("shared host state")
    }
  }
}

impl SharedState {
  pub fn new(context: Arc<Context>, compiler: Compiler, namespace: Namespace) -> Self {
    let runtime = Arc::new(Mutex::new(WasmContext {
      compiler,
      namespace,
    }));

    Self::with_runtime(context, runtime)
  }

  pub fn with_runtime(context: Arc<Context>, runtime: Arc<Mutex<WasmContext>>) -> Self {
    Self {
      inner: Arc::new(RuntimeState {
        context,
        current: RwLock::new(Current::default()),
        scheduled_queue: Mutex::new(Vec::new()),
        guest_futures: RwLock::new(Slab::new()),
        request_states: RwLock::new(Slab::new()),
        callback_message: RwLock::new(GuestCallback::default()),
        runtime,
      }),
    }
  }

  pub fn load(
    &self,
    data: Vec<u8>,
    global_exports: Rc<RefCell<HashMap<String, Option<Export>>>>,
  ) -> Result<InstanceIndex, Error> {
    let WasmContext {
      ref mut namespace,
      ref mut compiler,
    } = *self.inner.runtime.lock();

    // Import host calls and environment
    if namespace.get_instance_index("env").is_none() {
      let compiled_env = instantiate(self.clone()).expect("instantiating env");
      namespace.instance(Some("env".to_owned()), compiled_env);
    }

    // Instantiate WASM code
    let compiled = wasm_instantiate(compiler, &data, namespace, global_exports)
      .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

    // Register it in the namespace.
    let index = namespace.instance(None, compiled);
    trace!("[{}] instantiated WASM code", index);
    Ok(index)
  }

  pub fn invoke_start(&self, index: InstanceIndex) -> impl Future<Item = (), Error = Error> {
    match self.call(index, "run", &[]) {
      Ok(_) => future::Either::A(self.spawned_futures(index)),
      Err(e) => future::Either::B(future::err(e)),
    }
  }

  pub fn invoke_hook(
    &self,
    index: InstanceIndex,
    scope: Scope,
    answer: BytesMut,
  ) -> impl Future<Item = (BytesMut, guest::Action), Error = Error> {
    // Check if callback is installed
    let cb = self.inner.callback_message.read();

    // Register request state
    // TODO: move to separate state for each InstanceIndex
    let request_id = self.inner.request_states.write().insert((scope, answer));

    // Instantiate a future to drive the guest-side future
    match cb.call(self, index, Some(request_id as i32)) {
      Ok(values) => {
        // Check if task finished eagerly
        if let Some(RuntimeValue::I32(res)) = values.first() {
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
          Some(task_handle) => future::Either::B(
            GuestFuture::new(self.clone(), index, task_handle).then(move |res| {
              let (_, answer) = self_clone.inner.request_states.write().remove(request_id);
              match res {
                Ok(action) => Ok((answer, guest::Action::from(action))),
                Err(e) => Err(e),
              }
            }),
          ),
          // Closure did not register a future, something must be wrong
          None => {
            drop(self_clone.inner.request_states.write().remove(request_id));
            future::Either::A(future::err(Error::new(
              ErrorKind::InvalidInput,
              "closure does not return a future",
            )))
          }
        }
      }
      Err(message) => {
        drop(self.inner.request_states.write().remove(request_id));
        future::Either::A(future::err(Error::new(ErrorKind::Other, message)))
      }
    }
  }

  /// Return current executed instance.
  fn current(&self) -> Current {
    *self.inner.current.read()
  }

  fn create_task(&self, _index: InstanceIndex) -> usize {
    self
      .inner
      .guest_futures
      .write()
      .insert(GuestFutureState::default())
  }

  fn get_requests(&self, _index: InstanceIndex) -> RwLockReadGuard<Slab<RequestState>> {
    self.inner.request_states.read()
  }

  fn get_requests_mut(&self, _index: InstanceIndex) -> RwLockWriteGuard<Slab<RequestState>> {
    self.inner.request_states.write()
  }

  fn remove_task(&self, _index: InstanceIndex, task_id: usize) -> GuestFutureState {
    self.inner.guest_futures.write().remove(task_id)
  }

  fn get_tasks(&self, _index: InstanceIndex) -> RwLockReadGuard<Slab<GuestFutureState>> {
    self.inner.guest_futures.read()
  }

  fn get_tasks_mut(&self, _index: InstanceIndex) -> RwLockWriteGuard<Slab<GuestFutureState>> {
    self.inner.guest_futures.write()
  }

  fn inspect_memory_mut(&self, start: usize, len: usize) -> Result<&mut [u8], Error> {
    let ptr = self.current().memory;
    if ptr.is_null() {
      return Err(ErrorKind::NotFound.into());
    }
    unsafe {
      let definition = &*ptr;
      if start + len > definition.current_length {
        return Err(ErrorKind::InvalidInput.into());
      }
      Ok(
        &mut std::slice::from_raw_parts_mut(definition.base, definition.current_length)
          [start..start + len],
      )
    }
  }

  fn inspect_memory(&self, start: usize, len: usize) -> Result<&[u8], Error> {
    self
      .inspect_memory_mut(start, len)
      .and_then(|s| Ok(s as &[u8]))
  }

  fn call(
    &self,
    index: InstanceIndex,
    field_name: &str,
    args: &[RuntimeValue],
  ) -> Result<Vec<RuntimeValue>, Error> {
    // Set the current index in the global state before calling into WASM to always call the right instance
    let WasmContext {
      ref mut namespace,
      ref mut compiler,
    } = *self.inner.runtime.lock();

    // Memory definition of the caller module is not exported in VMContext.
    // Ideally, the VMContext would have a field that points to the module that called the host function.
    // TODO: https://github.com/CraneStation/wasmtime/issues/39
    let instance = namespace.get_instance(index);
    let memory = match unsafe { instance.lookup_immutable("memory") } {
      Some(Export::Memory { definition, .. }) => definition,
      _ => std::ptr::null_mut(),
    };

    {
      *self.inner.current.write() = Current {
        index: Some(index),
        memory,
      };
    }

    let result = namespace
      .invoke(compiler, index, field_name, args)
      .map_err(|e| e.to_string())
      .unwrap();

    // Reset current instance
    {
      *self.inner.current.write() = Current::default();
    }

    match result {
      ActionOutcome::Returned { values } => {
        trace!("[{}] guest call return: {:?}", index, values);
        Ok(values)
      }
      ActionOutcome::Trapped { message } => {
        warn!("[{}] guest call trap: {}", index, message);
        Err(Error::new(ErrorKind::Other, message))
      }
    }
  }

  fn spawned_futures(&self, index: InstanceIndex) -> impl Future<Item = (), Error = Error> {
    let mut queue = self.inner.scheduled_queue.lock();
    let vec: Vec<GuestFuture> = queue
      .iter()
      .map(|task_handle| {
        trace!("[{}] scheduling guest future #{}", index, *task_handle);
        GuestFuture::new(self.clone(), index, *task_handle)
      })
      .collect();
    queue.clear();

    future::join_all(vec).then(move |_| Ok::<(), Error>(()))
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
  index: InstanceIndex,
  task_handle: usize,
}

struct GuestStream {
  host_state: SharedState,
  index: InstanceIndex,
  task_handle: usize,
}

impl Stream for GuestStream {
  type Item = Bytes;
  type Error = Error;

  fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
    match self
      .host_state
      .get_tasks_mut(self.index)
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
            "[{}] polling stream #{}, not ready",
            self.index,
            self.task_handle
          );
          // Return EOF if all buffered data has been processed and closed flag is raised
          if *closed {
            trace!("[{}] polling stream #{}, EOF", self.index, self.task_handle);
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
          self.index,
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
          self.index,
          self.task_handle
        );
        Err(ErrorKind::NotFound.into())
      }
    }
  }
}

impl Drop for GuestStream {
  fn drop(&mut self) {
    trace!("[{}], dropping stream #{}", self.index, self.task_handle);
    drop(self.host_state.remove_task(self.index, self.task_handle))
  }
}

/// Future representing an asynchronous guest computation.
impl GuestFuture {
  fn new(host_state: SharedState, index: InstanceIndex, task_handle: usize) -> Self {
    Self {
      host_state,
      index,
      task_handle,
    }
  }
}

impl Future for GuestFuture {
  type Item = guest::AsyncValue;
  type Error = std::io::Error;

  fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
    let cb = match self.host_state.get_tasks(self.index).get(self.task_handle) {
      Some(ref state) => state.cb,
      _ => return Err(ErrorKind::NotFound.into()),
    };

    // Poll guest future. The poller fn is not exported, so it can't be called directly,
    // so we use a built-in trampoline function to call it.
    match cb.call(&self.host_state, self.index, None) {
      Ok(values) => {
        // Parse the async result code.
        let state = match values.first() {
          Some(RuntimeValue::I32(x)) => guest::Async::from(*x),
          _ => guest::Async::Error(guest::Error::Unknown),
        };
        trace!(
          "[{}] guest future #{} return: {:?}",
          self.index,
          self.task_handle,
          state
        );
        match state {
          guest::Async::NotReady => Ok(Async::NotReady),
          guest::Async::Error(_) => {
            // TODO: map guest side error
            let _ = self.host_state.remove_task(self.index, self.task_handle);
            Err(ErrorKind::Other.into())
          }
          guest::Async::Ready(v) => {
            let _ = self.host_state.remove_task(self.index, self.task_handle);
            Ok(Async::Ready(v))
          }
        }
      }
      Err(message) => {
        warn!(
          "[{}] guest future #{} trap: {}",
          self.index, self.task_handle, message
        );
        let _ = self.host_state.remove_task(self.index, self.task_handle);
        Err(ErrorKind::Other.into())
      }
    }
  }
}
