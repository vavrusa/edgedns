use super::{from_context, GuestCallback, GuestStream};
use crate::{forwarder, Scope};
use guest;
use log::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::codec::*;
use tokio::net::UnixStream;
use tokio::prelude::*;
use tokio::timer::Delay;

use wasmer_runtime::{imports, Ctx, ImportObject};

pub fn import_objects() -> ImportObject {
    imports! {
        "env" => {
            "debug" => debug<[u32, u32] -> []>,
            "register_future" => register_future<[i32, i32] -> [i32]>,
            "register_on_message" => register_on_message<[i32, i32] -> []>,
            "timer_poll" => timer_poll<[i32] -> [i32]>,
            "timer_create" => timer_create<[i32] -> [i32]>,
            "forward_create" => forward_create<[i32, i32, i32, i32, i32] -> [i32]>,
            "forward_poll" => forward_poll<[i32, i32, i32] -> [i32]>,
            "request_query_name" => request_query_name<[i32, i32, i32] -> [i32]>,
            "request_query_type" => request_query_type<[i32] -> [i32]>,
            "request_set_response" => request_set_response<[i32, i32, i32] -> [i32]>,
            "local_socket_open" => local_socket_open<[i32, i32] -> [i32]>,
            "local_socket_send" => local_socket_send<[i32, i32, i32] -> [i32]>,
            "local_socket_recv" => local_socket_recv<[i32, i32, i32] -> [i32]>,
            "local_socket_close" => local_socket_close<[i32] -> [i32]>,
        },
    }
}

extern "C" fn debug(ptr: u32, len: u32, ctx: &mut Ctx) {
    let instance = from_context(ctx);
    let memory = ctx.memory(0);
    let slice = &memory[ptr as usize..(ptr + len) as usize];
    match std::str::from_utf8(slice) {
        Ok(s) => info!("[{}]: {}", instance, s),
        Err(e) => info!("[{}]: {:?} (error: {})", instance, slice, e),
    }
}

extern "C" fn register_future(data: i32, vtable_ptr: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    let task_id = instance.create_task();
    match instance.get_tasks_mut().get_mut(task_id as usize) {
        Some(ref mut fut) => {
            trace!(
                "[{}] registered #{} callback: {}/{}",
                instance,
                task_id,
                data,
                vtable_ptr
            );
            fut.cb = GuestCallback {
                ptr: (data, vtable_ptr),
            };
            // Schedule the task for execution immediately
            instance
                .clone()
                .scheduled_queue
                .lock()
                .push(task_id as usize);
            task_id as i32
        }
        None => {
            warn!("[{}] attempted to register invalid #{}", instance, task_id);
            guest::Error::NotFound.into()
        }
    }
}

extern "C" fn register_on_message(data: i32, vtable_ptr: i32, ctx: &mut Ctx) {
    let instance = from_context(ctx);

    // The callbacks are currently passed as fat pointers for `FnMut`,
    // this automatically expands to two pointers: data and vtable pointer.
    *instance.callback_message.write() = GuestCallback {
        ptr: (data, vtable_ptr),
    };
}

extern "C" fn timer_poll(task_id: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    match instance.get_tasks().get(task_id as usize) {
        Some(fut) => {
            // Check if the task is complete
            if fut.data.is_none() {
                return guest::Async::NotReady.into();
            }
        }
        None => {
            warn!("[{}] polled #{} which does not exist", instance, task_id);
            return guest::Async::Error(guest::Error::NotFound).into();
        }
    }

    // Complete the task
    drop(instance.remove_task(task_id as usize));
    guest::Async::Ready(0.into()).into()
}

extern "C" fn timer_create(ms: i32, ctx: &mut Ctx) -> i32 {
    // Check for invalid duration
    if ms <= 0 {
        return guest::Error::InvalidInput.into();
    }

    let instance = from_context(ctx);
    let task_id = instance.create_task();

    // Spawn the future and notify when done
    let task = task::current();
    let when = Instant::now() + Duration::from_millis(ms as u64);
    tokio::spawn(Delay::new(when).then(move |res| {
        match res {
            Ok(_) => {
                trace!("[{}] timer fired for #{}", instance, task_id);
                if let Some(ref mut task) = instance.get_tasks_mut().get_mut(task_id) {
                    task.data = Some(Vec::new());
                }
            }
            Err(e) => {
                error!(
                    "[{}] timer error for #{}, error: {:?}",
                    instance, task_id, e
                );
                drop(instance.remove_task(task_id));
            }
        };
        task.notify();
        Ok(())
    }));

    guest::from_result(Ok(task_id as i32))
}

fn parse_addr_from_slice(addr_bytes: &[u8]) -> Result<SocketAddr, guest::Error> {
    let s = std::str::from_utf8(addr_bytes).map_err(|_| guest::Error::InvalidInput)?;
    s.parse::<SocketAddr>()
        .map_err(|_| guest::Error::InvalidInput)
}

extern "C" fn forward_create(
    request: i32,
    upstream_ptr: i32,
    upstream_len: i32,
    msg_ptr: i32,
    msg_len: i32,
    ctx: &mut Ctx,
) -> i32 {
    let instance = from_context(ctx);

    // Parse the upstream address from guest first, it's passed as a pointer to guest memory.
    //let upstream = match state.inspect_memory(upstream_ptr as usize, upstream_len as usize) {
    let memory = ctx.memory(0);
    let slice = &memory[upstream_ptr as usize..(upstream_ptr + upstream_len) as usize];
    let upstream = match parse_addr_from_slice(&slice) {
        Ok(addr) => addr,
        Err(e) => return e.into(),
    };

    // Use current query, or parse query from the guest
    let (msg, scope) = if msg_len == 0 {
        // Forward current query if no message is given
        if let Some((ref scope, ..)) = instance.get_requests().get(request as usize) {
            (scope.query.as_bytes().clone(), scope.clone())
        } else {
            return guest::Error::NotFound.into();
        }
    } else {
        // Forward message from guest memory
        let msg = &memory[msg_ptr as usize..(msg_ptr + msg_len) as usize];

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let local_scope = Scope::new(msg.into(), local_addr).expect("scope");
        (msg.into(), local_scope)
    };

    // Create a new guest task for the forwarding
    let task_id = instance.create_task();
    trace!(
        "[{}] forwarding msg to {:?} ({} bytes)",
        instance,
        upstream,
        msg.len()
    );

    // Spawn a new host task, and notify guest when the query is resolved
    let waiting = task::current();
    tokio::spawn(
        forwarder::Builder::new()
            .with_upstream_servers(vec![upstream])
            .build()
            .resolve(&instance.context, &scope)
            .then(move |res| {
                match res {
                    // Copy upstream response back to guest memory
                    Ok(msg) => {
                        trace!(
                            "[{}] response for #{} ({} bytes)",
                            instance,
                            task_id,
                            msg.len()
                        );
                        if let Some(ref mut task) = instance.get_tasks_mut().get_mut(task_id) {
                            // TODO: keep a reference to guest memory to avoid double-copy
                            task.data = Some(msg.to_vec())
                        }
                    }
                    Err(e) => {
                        error!(
                            "[{}] when forwarding #{}, error: {:?}",
                            instance, task_id, e
                        );
                        drop(instance.remove_task(task_id));
                    }
                };

                // Reschedule waiting task
                waiting.notify();
                Ok(())
            }),
    );

    guest::from_result(Ok(task_id as i32))
}

extern "C" fn forward_poll(task_id: i32, msg_ptr: i32, msg_max_len: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);

    // Check if the upstream provided a message
    let msg_len = match instance.get_tasks().get(task_id as usize) {
        Some(fut) => match fut.data {
            Some(ref data) => data.len() as u16,
            None => return guest::Async::NotReady.into(),
        },
        None => {
            // No such task exists
            warn!("[{}] polled #{} which does not exist", instance, task_id);
            return guest::Async::Error(guest::Error::NotFound).into();
        }
    };

    // Complete the task on the guest side
    let completed_task = instance.remove_task(task_id as usize);
    if msg_len > msg_max_len as u16 {
        trace!(
            "[{}] response ({}B) larger than guest buffer ({}B)",
            instance,
            msg_len,
            msg_max_len
        );
        return guest::Async::Error(guest::Error::TooBig).into();
    }

    // Copy response message to guest memory
    let memory = ctx.memory_mut(0);
    let slice = &mut memory[msg_ptr as usize..(msg_ptr + msg_len as i32) as usize];

    trace!("[{}] forward done ({} bytes)", instance, msg_len);
    if let Some(ref data) = completed_task.data {
        slice.copy_from_slice(&data);
    }
    guest::Async::Ready(msg_len.into()).into()
}

extern "C" fn request_query_name(request: i32, ptr: i32, max_len: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    if let Some((ref scope, ..)) = instance.get_requests().get(request as usize) {
        // Check if the query name fits in the guest provided buffer
        let qname = scope.question.qname();
        let qname_len = qname.len();
        if qname_len as i32 > max_len {
            return guest::Error::TooBig.into();
        }

        // Copy the query name
        let memory = ctx.memory_mut(0);
        let slice = &mut memory[ptr as usize..(ptr + max_len) as usize];

        slice[..qname_len].copy_from_slice(&qname.clone().into_bytes());
        guest::from_result(Ok(qname_len as i32))
    } else {
        // Request with given id does not exist
        guest::Error::NotFound.into()
    }
}

extern "C" fn request_query_type(request: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    if let Some((ref scope, ..)) = instance.get_requests().get(request as usize) {
        i32::from(scope.question.qtype().to_int())
    } else {
        // Request with given id does not exist
        guest::Error::NotFound.into()
    }
}

extern "C" fn request_set_response(request: i32, ptr: i32, len: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    let memory = ctx.memory(0);
    let slice = &memory[ptr as usize..(ptr + len) as usize];

    if let Some((_, ref mut answer)) = instance.get_requests_mut().get_mut(request as usize) {
        trace!(
            "[{}] setting response for {} ({} bytes)",
            instance,
            request,
            slice.len()
        );
        answer.clear();
        answer.extend_from_slice(slice);
        return 0;
    }

    guest::Error::NotFound.into()
}

extern "C" fn local_socket_open(ptr: i32, len: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    let memory = ctx.memory(0);
    let slice = &memory[ptr as usize..(ptr + len) as usize];

    // Parse path from the guest
    let path = match std::str::from_utf8(slice) {
        Ok(path) => Path::new(path).to_path_buf(),
        Err(_) => return guest::Error::InvalidInput.into(),
    };

    // Check if the local file exists
    if !path.exists() {
        trace!("[{}] local stream {:?}, doesn't exist", instance, path);
        return guest::Error::NotFound.into();
    }

    // Create an empty buffer
    let task_id = instance.create_task();
    if let Some(ref mut task) = instance.get_tasks_mut().get_mut(task_id) {
        task.data = Some(Vec::with_capacity(8192));
    }

    // Create a new task if not reconnecting
    trace!("[{}] connecting local stream {:?}", instance, path);
    let src = GuestStream::new(instance.clone(), task_id);

    // Open connection to local socket, and connect guest stream to sink
    tokio::spawn(
        UnixStream::connect(&path)
            .and_then(move |stream| {
                let (sink, _) = Framed::new(stream, BytesCodec::new()).split();
                src.forward(sink)
            })
            .then(move |res| {
                // Log stream closure
                match res {
                    Ok(_) => trace!("[{}] local stream {:?}, closed", instance, task_id),
                    Err(e) => warn!(
                        "[{}] error in stream #{}: {:?}, closed",
                        instance, task_id, e
                    ),
                };
                Ok(())
            }),
    );

    task_id as i32
}

extern "C" fn local_socket_send(task_id: i32, ptr: i32, len: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);

    // Check arguments
    if len < 0 {
        return guest::Error::InvalidInput.into();
    }

    // If host passed an empty message, flush
    if len == 0 {
        if let Some(task) = instance.get_tasks_mut().get_mut(task_id as usize) {
            // Refuse sends after close
            if task.closed {
                return guest::Error::PermissionDenied.into();
            }
            // Wake up task blocked on the stream to poll again
            if let Some(waiting) = task.waiting.take() {
                trace!("[{}] local stream #{}, flushed", instance, task_id);
                waiting.notify();
            }

            return 0;
        }

        return guest::Error::NotFound.into();
    }

    // Buffer message from the host
    let memory = ctx.memory_mut(0);
    let slice = &mut memory[ptr as usize..(ptr + len) as usize];
    match instance.get_tasks_mut().get_mut(task_id as usize) {
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

            data.extend_from_slice(slice);
            len
        }
        // Task doesn't exist
        None => return guest::Error::NotFound.into(),
    }
}

extern "C" fn local_socket_recv(_task_id: i32, _ptr: i32, _len: i32, _ctx: &mut Ctx) -> i32 {
    unimplemented!()
}

extern "C" fn local_socket_close(task_id: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);

    // Set the closed flag to initiate teardown
    trace!("[{}] local stream #{}, closing", instance, task_id);
    if let Some(task) = instance.get_tasks_mut().get_mut(task_id as usize) {
        task.closed = true;
        if let Some(waiting) = task.waiting.take() {
            waiting.notify();
        }
    }

    0
}
