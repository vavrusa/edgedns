use crate::{GuestCallback, GuestStream, SharedState};
use cranelift_codegen::ir::types;
use cranelift_codegen::{ir, isa};
use cranelift_entity::PrimaryMap;
use cranelift_wasm::DefinedFuncIndex;
use domain_core::bits::*;
use guest;
use libedgedns::{forwarder, Scope};
use log::*;
use std::path::Path;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::{Duration, Instant};
use target_lexicon::HOST;
use tokio::prelude::*;
use tokio::net::UnixStream;
use tokio::timer::Delay;
use tokio::codec::*;
use wasmtime_environ::{translate_signature, Export, Module};
use wasmtime_runtime::{Imports, Instance, InstantiationError, VMContext, VMFunctionBody};

pub extern "C" fn debug(vmctx: *mut VMContext, ptr: i32, len: i32) {
  let state: &mut SharedState = vmctx.into();
  let current_index = state.current().index.unwrap();
  if let Ok(slice) = state.inspect_memory(ptr as usize, len as usize) {
    match std::str::from_utf8(slice) {
      Ok(s) => info!("[{}]: {}", current_index, s),
      Err(e) => info!("[{}]: {:?} (error: {})", current_index, slice, e),
    }
  }
}

pub extern "C" fn register_future(vmctx: *mut VMContext, data: i32, vtable_ptr: i32) -> i32 {
  let state: &mut SharedState = vmctx.into();
  let current_index = state.current().index.unwrap();
  let task_id = state.create_task(current_index);
  match state.get_tasks_mut(current_index).get_mut(task_id as usize) {
    Some(ref mut fut) => {
      trace!("[{}] registered #{} callback: {}/{}", current_index, task_id, data, vtable_ptr);
      fut.cb = GuestCallback{ptr: (data, vtable_ptr)};
      // Schedule the task for execution immediately
      state.inner.scheduled_queue.lock().push(task_id as usize);
      task_id as i32
    }
    None => {
      warn!("[{}] attempted to register invalid #{}", current_index, task_id);
      guest::Error::NotFound.into()
    }
  }
}

pub extern "C" fn register_on_message(vmctx: *mut VMContext, data: i32, vtable_ptr: i32) {
  let state: &mut SharedState = vmctx.into();

  // The callbacks are currently passed as fat pointers for `FnMut`,
  // this automatically expands to two pointers: data and vtable pointer.
  *state.inner.callback_message.write() = GuestCallback {
    ptr: (data, vtable_ptr),
  };
}

pub extern "C" fn timer_poll(vmctx: *mut VMContext, task_id: i32) -> i32 {
  let state: &mut SharedState = vmctx.into();
  let current_index = state.current().index.unwrap();
  match state.get_tasks(current_index).get(task_id as usize) {
    Some(fut) => {
      // Check if the task is complete
      if fut.data.is_none() {
        return guest::Async::NotReady.into();
      }
    }
    None => {
      warn!("[{}] polled #{} which does not exist", current_index, task_id);
      return guest::Async::Error(guest::Error::NotFound).into();
    }
  }

  // Complete the task
  drop(state.remove_task(current_index, task_id as usize));
  guest::Async::Ready(0.into()).into()
}

pub extern "C" fn timer_create(vmctx: *mut VMContext, ms: i32) -> i32 {
  // Check for invalid duration
  if ms <= 0 {
    return guest::Error::InvalidInput.into();
  }

  let state: &mut SharedState = vmctx.into();
  let current_index = state.current().index.unwrap();
  let task_id = state.create_task(current_index);

  // Spawn the future and notify when done
  let task = task::current();
  let when = Instant::now() + Duration::from_millis(ms as u64);
  tokio::spawn(Delay::new(when).then(move |res| {
    match res {
      Ok(_) => {
        trace!("[{}] timer fired for #{}", current_index, task_id);
        if let Some(ref mut task) = state.get_tasks_mut(current_index).get_mut(task_id) {
          task.data = Some(Vec::new());
        }
      }
      Err(e) => {
        error!("[{}] timer error for #{}, error: {:?}", current_index, task_id, e);
        drop(state.remove_task(current_index, task_id));
      }
    };
    task.notify();
    Ok(())
  }));

  guest::from_result(Ok(task_id as i32))
}

fn parse_addr_from_slice(addr_bytes: &[u8]) -> Result<SocketAddr, guest::Error> {
  let s = std::str::from_utf8(addr_bytes).map_err(|_| guest::Error::InvalidInput)?;
  s.parse::<SocketAddr>().map_err(|_| guest::Error::InvalidInput)
}

pub fn forward_create(
  vmctx: *mut VMContext,
  request: i32,
  upstream_ptr: i32,
  upstream_len: i32,
  msg_ptr: i32,
  msg_len: i32,
) -> i32 {
  let state: &mut SharedState = vmctx.into();

  // Parse the upstream address from guest first, it's passed as a pointer to guest memory.
  let upstream = match state.inspect_memory(upstream_ptr as usize, upstream_len as usize) {
    Ok(s) => match parse_addr_from_slice(s) {
      Ok(addr) => addr,
      Err(e) => return e.into(),
    }
    Err(_) => return guest::Error::InvalidInput.into(),
  };

  // Use current query, or parse query from the guest
  let current_index = state.current().index.unwrap();
  let (msg, scope) = if msg_len == 0 {
    // Forward current query if no message is given
    if let Some((ref scope, ..)) = state.get_requests(current_index).get(request as usize) {
      (scope.query.as_bytes().clone(), scope.clone())
    } else {
      return guest::Error::NotFound.into();
    }
  } else {
    // Forward message from guest memory
    match state.inspect_memory(msg_ptr as usize, msg_len as usize) {
      Ok(msg) => {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let local_scope =
          Scope::new(state.inner.context.clone(), msg.into(), local_addr).expect("scope");
        (msg.into(), local_scope)
      }
      Err(e) => {
        warn!(
          "[{}] invalid memory for forward: {}/{}, error: {:?}",
          current_index, msg_ptr, msg_len, e
        );
        return guest::Error::InvalidInput.into();
      }
    }
  };

  // Create a new guest task for the forwarding
  let task_id = state.create_task(current_index);
  trace!("[{}] forwarding msg to {:?} ({} bytes)", current_index, upstream, msg.len());

  // Spawn a new host task, and notify guest when the query is resolved
  let waiting = task::current();
  tokio::spawn(
    forwarder::Builder::new()
      .with_upstream_servers(vec![upstream])
      .build()
      .resolve(&scope)
      .then(move |res| {
        match res {
          // Copy upstream response back to guest memory
          Ok(msg) => {
            trace!("[{}] response for #{} ({} bytes)", current_index, task_id, msg.len());
            if let Some(ref mut task) = state.get_tasks_mut(current_index).get_mut(task_id) {
              // TODO: keep a reference to guest memory to avoid double-copy
              task.data = Some(msg.to_vec())
            }
          }
          Err(e) => {
            error!("[{}] when forwarding #{}, error: {:?}", current_index, task_id, e);
            drop(state.remove_task(current_index, task_id));
          }
        };

        // Reschedule waiting task
        waiting.notify();
        Ok(())
      }),
  );

  guest::from_result(Ok(task_id as i32))
}

pub fn forward_poll(vmctx: *mut VMContext, task_id: i32, msg_ptr: i32, msg_max_len: i32) -> i32 {
  let state: &mut SharedState = vmctx.into();
  let current_index = state.current().index.unwrap();

  // Check if the upstream provided a message
  let msg_len = match state.get_tasks(current_index).get(task_id as usize) {
    Some(fut) => {
      match fut.data {
        Some(ref data) => data.len() as u16,
        None => return guest::Async::NotReady.into(),
      }
    }
    None => {
      // No such task exists
      warn!("[{}] polled #{} which does not exist", current_index, task_id);
      return guest::Async::Error(guest::Error::NotFound).into();
    }
  };

  // Complete the task on the guest side
  let completed_task = state.remove_task(current_index, task_id as usize);
  if msg_len > msg_max_len as u16 {
    trace!(
      "[{}] response ({}B) larger than guest buffer ({}B)",
      current_index,
      msg_len,
      msg_max_len
    );
    return guest::Async::Error(guest::Error::TooBig).into();
  }

  // Copy response message to guest memory
  match state.inspect_memory_mut(msg_ptr as usize, msg_len as usize) {
    Ok(s) => {
      trace!("[{}] forward done ({} bytes)", current_index, msg_len);
      if let Some(ref data) = completed_task.data {
        s.copy_from_slice(&data);  
      }
      guest::Async::Ready(msg_len.into()).into()
    }
    Err(_) => guest::Async::Error(guest::Error::InvalidInput).into(),
  }
}

pub fn request_query_name(vmctx: *mut VMContext, request: i32, ptr: i32, max_len: i32) -> i32 {
  let state: &mut SharedState = vmctx.into();
  let current_index = state.current().index.unwrap();
  if let Some((ref scope, ..)) = state.get_requests(current_index).get(request as usize) {

    // Check if the query name fits in the guest provided buffer
    let qname = scope.question.qname();
    let qname_len = qname.len();
    if qname_len as i32 > max_len {
      return guest::Error::TooBig.into();
    }

    // Copy the query name
    match state.inspect_memory_mut(ptr as usize, max_len as usize) {
      Ok(s) => {
        s[..qname_len].copy_from_slice(qname.as_flat_slice().expect("domain"));
        guest::from_result(Ok(qname_len as i32))
      }
      Err(_e) => guest::Error::InvalidInput.into(),
    }
  } else {
    // Request with given id does not exist
    guest::Error::NotFound.into()
  }
}

pub fn request_query_type(vmctx: *mut VMContext, request: i32) -> i32 {
  let state: &mut SharedState = vmctx.into();
  let current_index = state.current().index.unwrap();
  if let Some((ref scope, ..)) = state.get_requests(current_index).get(request as usize) {
    i32::from(scope.question.qtype().to_int())
  } else {
    // Request with given id does not exist
    guest::Error::NotFound.into()
  }
}

pub fn request_set_response(vmctx: *mut VMContext, request: i32, ptr: i32, len: i32) -> i32 {
  let state: &mut SharedState = vmctx.into();
  let current_index = state.current().index.unwrap();
  let s = match state.inspect_memory(ptr as usize, len as usize) {
    Ok(s) => s,
    Err(_) => return guest::Error::InvalidInput.into(),
  };

  if let Some((_, ref mut answer)) = state.get_requests_mut(current_index).get_mut(request as usize) {
    trace!("[{}] setting response for {} ({} bytes)", current_index, request, s.len());
    answer.clear();
    answer.extend_from_slice(s);
    return 0;
  }

  guest::Error::NotFound.into()
}

pub fn local_socket_open(vmctx: *mut VMContext, ptr: i32, len: i32) -> i32 {
	let state: &mut SharedState = vmctx.into();
	let current_index = state.current().index.unwrap();

  // Parse path from the guest
  let path = match state.inspect_memory(ptr as usize, len as usize) {
    Ok(slice) => match std::str::from_utf8(slice) {
      Ok(path) => Path::new(path).to_path_buf(),
      Err(_) => return guest::Error::InvalidInput.into(),
    }
    Err(_) => return guest::Error::InvalidInput.into(),
  };

  // Check if the local file exists
  if !path.exists() {
    trace!("[{}] local stream {:?}, doesn't exist", current_index, path);
    return guest::Error::NotFound.into();
  }

  // Create an empty buffer
  let task_id = state.create_task(current_index);
  if let Some(ref mut task) = state.get_tasks_mut(current_index).get_mut(task_id) {
    task.data = Some(Vec::with_capacity(8192));
  }

  // Create a new task if not reconnecting
  trace!("[{}] connecting local stream {:?}", current_index, path);
  let src = GuestStream{host_state: state.clone(), index: current_index, task_handle: task_id};

  // Open connection to local socket, and connect guest stream to sink
  tokio::spawn(UnixStream::connect(&path)
    .and_then(move |stream| {
      let (sink, _) = Framed::new(stream, BytesCodec::new()).split();
      src.forward(sink)
    })
    .then(move |res| {
      // Log stream closure
      match res {
        Ok(_) => trace!("[{}] local stream {:?}, closed", current_index, task_id),
        Err(e) => warn!("[{}] error in stream #{}: {:?}, closed", current_index, task_id, e),
      };
      Ok(())
    })
  );
  
  task_id as i32
}

pub fn local_socket_send(vmctx: *mut VMContext, task_id: i32, ptr: i32, len: i32) -> i32 {
  let state: &mut SharedState = vmctx.into();
  let current_index = state.current().index.unwrap();

  // Check arguments
  if len < 0 {
    return guest::Error::InvalidInput.into();
  }

  // If host passed an empty message, flush
  if len == 0 {
    if let Some(task) = state.get_tasks_mut(current_index).get_mut(task_id as usize) {
      // Refuse sends after close
      if task.closed {
        return guest::Error::PermissionDenied.into();
      }
      // Wake up task blocked on the stream to poll again
      if let Some(waiting) = task.waiting.take() {
        trace!("[{}] local stream #{}, flushed", current_index, task_id);
        waiting.notify();
      }

      return 0;
    }

    return guest::Error::NotFound.into();
  }

  // Buffer message from the host
  let s = match state.inspect_memory_mut(ptr as usize, len as usize) {
    Ok(s) => s,
    Err(_) => return guest::Error::InvalidInput.into(),
  };

  match state.get_tasks_mut(current_index).get_mut(task_id as usize) {
    Some(task) => {
      // Check if the task has closed the buffer
      let data = match task.data {
        Some(ref mut data) => data,
        None => return guest::Error::PermissionDenied.into(),
      };
      // Flush when buffered enough data
      if data.len() >= 8192 {
        if let Some(waiting) = task.waiting.take() {
          waiting.notify();
        }
        // If there's too much data buffered, return NotReady to the guest and park it.
        // The current task will be rescheduled when the buffer is flushed again
        if data.len() >= 65536 {
          task.waiting.replace(task::current());
          return 0;
        }
      }

      data.extend_from_slice(s);
      len
    },
    // Task doesn't exist
    None => return guest::Error::NotFound.into(),
  }
}

pub fn local_socket_recv(vmctx: *mut VMContext, task_id: i32, ptr: i32, len: i32) -> i32 {
  unimplemented!()
}

pub fn local_socket_close(vmctx: *mut VMContext, task_id: i32) -> i32 {
  let state: &mut SharedState = vmctx.into();
  let current_index = state.current().index.unwrap();

  // Set the closed flag to initiate teardown
  trace!("[{}] local stream #{}, closing", current_index, task_id);
  if let Some(task) = state.get_tasks_mut(current_index).get_mut(task_id as usize) {
    task.closed = true;
    if let Some(waiting) = task.waiting.take() {
      waiting.notify();
    }
  }

  0
}

pub fn instantiate(state: SharedState) -> Result<Instance, InstantiationError> {
  let call_conv = isa::CallConv::triple_default(&HOST);
  let pointer_type = types::Type::triple_pointer_type(&HOST);
  let mut module = Module::new();
  let mut finished_functions: PrimaryMap<DefinedFuncIndex, *const VMFunctionBody> =
    PrimaryMap::new();

  let sig = module.signatures.push(translate_signature(
    ir::Signature {
      params: vec![ir::AbiParam::new(types::I32), ir::AbiParam::new(types::I32)],
      returns: vec![],
      call_conv,
    },
    pointer_type,
  ));
  let func = module.functions.push(sig);
  module
    .exports
    .insert("debug".to_owned(), Export::Function(func));
  finished_functions.push(debug as *const VMFunctionBody);

  let sig = module.signatures.push(translate_signature(
    ir::Signature {
      params: vec![ir::AbiParam::new(types::I32)],
      returns: vec![ir::AbiParam::new(types::I32)],
      call_conv,
    },
    pointer_type,
  ));
  let func = module.functions.push(sig);
  module
    .exports
    .insert("timer_create".to_owned(), Export::Function(func));
  finished_functions.push(timer_create as *const VMFunctionBody);

  let sig = module.signatures.push(translate_signature(
    ir::Signature {
      params: vec![ir::AbiParam::new(types::I32)],
      returns: vec![ir::AbiParam::new(types::I32)],
      call_conv,
    },
    pointer_type,
  ));
  let func = module.functions.push(sig);
  module
    .exports
    .insert("timer_poll".to_owned(), Export::Function(func));
  finished_functions.push(timer_poll as *const VMFunctionBody);

  let sig = module.signatures.push(translate_signature(
    ir::Signature {
      params: vec![
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
      ],
      returns: vec![ir::AbiParam::new(types::I32)],
      call_conv,
    },
    pointer_type,
  ));
  let func = module.functions.push(sig);
  module
    .exports
    .insert("forward_create".to_owned(), Export::Function(func));
  finished_functions.push(forward_create as *const VMFunctionBody);

  let sig = module.signatures.push(translate_signature(
    ir::Signature {
      params: vec![
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
      ],
      returns: vec![ir::AbiParam::new(types::I32)],
      call_conv,
    },
    pointer_type,
  ));
  let func = module.functions.push(sig);
  module
    .exports
    .insert("forward_poll".to_owned(), Export::Function(func));
  finished_functions.push(forward_poll as *const VMFunctionBody);

  let sig = module.signatures.push(translate_signature(
    ir::Signature {
      params: vec![
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
      ],
      returns: vec![ir::AbiParam::new(types::I32)],
      call_conv,
    },
    pointer_type,
  ));
  let func = module.functions.push(sig);
  module
    .exports
    .insert("register_future".to_owned(), Export::Function(func));
  finished_functions.push(register_future as *const VMFunctionBody);

  let sig = module.signatures.push(translate_signature(
    ir::Signature {
      params: vec![ir::AbiParam::new(types::I32), ir::AbiParam::new(types::I32)],
      returns: vec![],
      call_conv,
    },
    pointer_type,
  ));
  let func = module.functions.push(sig);
  module
    .exports
    .insert("register_on_message".to_owned(), Export::Function(func));
  finished_functions.push(register_on_message as *const VMFunctionBody);

  let sig = module.signatures.push(translate_signature(
    ir::Signature {
      params: vec![
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
      ],
      returns: vec![ir::AbiParam::new(types::I32)],
      call_conv,
    },
    pointer_type,
  ));
  let func = module.functions.push(sig);
  module
    .exports
    .insert("request_query_name".to_owned(), Export::Function(func));
  finished_functions.push(request_query_name as *const VMFunctionBody);

  let sig = module.signatures.push(translate_signature(
    ir::Signature {
      params: vec![ir::AbiParam::new(types::I32)],
      returns: vec![ir::AbiParam::new(types::I32)],
      call_conv,
    },
    pointer_type,
  ));
  let func = module.functions.push(sig);
  module
    .exports
    .insert("request_query_type".to_owned(), Export::Function(func));
  finished_functions.push(request_query_type as *const VMFunctionBody);

  let sig = module.signatures.push(translate_signature(
    ir::Signature {
      params: vec![
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
      ],
      returns: vec![ir::AbiParam::new(types::I32)],
      call_conv,
    },
    pointer_type,
  ));
  let func = module.functions.push(sig);
  module
    .exports
    .insert("request_set_response".to_owned(), Export::Function(func));
  finished_functions.push(request_set_response as *const VMFunctionBody);

  let sig = module.signatures.push(translate_signature(
    ir::Signature {
      params: vec![
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
      ],
      returns: vec![ir::AbiParam::new(types::I32)],
      call_conv,
    },
    pointer_type,
  ));
  let func = module.functions.push(sig);
  module
    .exports
    .insert("local_socket_open".to_owned(), Export::Function(func));
  finished_functions.push(local_socket_open as *const VMFunctionBody);

  let sig = module.signatures.push(translate_signature(
    ir::Signature {
      params: vec![
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
      ],
      returns: vec![ir::AbiParam::new(types::I32)],
      call_conv,
    },
    pointer_type,
  ));
  let func = module.functions.push(sig);
  module
    .exports
    .insert("local_socket_send".to_owned(), Export::Function(func));
  finished_functions.push(local_socket_send as *const VMFunctionBody);

  let sig = module.signatures.push(translate_signature(
    ir::Signature {
      params: vec![
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
        ir::AbiParam::new(types::I32),
      ],
      returns: vec![ir::AbiParam::new(types::I32)],
      call_conv,
    },
    pointer_type,
  ));
  let func = module.functions.push(sig);
  module
    .exports
    .insert("local_socket_recv".to_owned(), Export::Function(func));
  finished_functions.push(local_socket_recv as *const VMFunctionBody);

  let sig = module.signatures.push(translate_signature(
    ir::Signature {
      params: vec![
        ir::AbiParam::new(types::I32),
      ],
      returns: vec![ir::AbiParam::new(types::I32)],
      call_conv,
    },
    pointer_type,
  ));
  let func = module.functions.push(sig);
  module
    .exports
    .insert("local_socket_close".to_owned(), Export::Function(func));
  finished_functions.push(local_socket_close as *const VMFunctionBody);

  let imports = Imports::none();
  let data_initializers = Vec::new();
  let signatures = PrimaryMap::new();

  Instance::new(
    Rc::new(module),
    Rc::new(RefCell::new(HashMap::new())),
    finished_functions.into_boxed_slice(),
    imports,
    &data_initializers,
    signatures.into_boxed_slice(),
    Box::new(state),
  )
}
