use super::{from_context, GuestCallback, HostFuture};
use crate::{forwarder, Scope};
use bytes::{BufMut, BytesMut};
use guest_types as guest;
use log::*;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UnixStream;
use tokio::prelude::*;
use tokio::timer::Delay;

use wasmer_runtime::{imports, Ctx, ImportObject};

const STREAM_BUF_CAPACITY: usize = 8 * 1024;

pub fn import_objects() -> ImportObject {
    imports! {
        "env" => {
            "debug" => debug<[u32, u32] -> []>,
            "timestamp" => timestamp<[i32, i32] -> [i32]>,
            "register_future" => register_future<[i32, i32] -> [i32]>,
            "register_on_message" => register_on_message<[i32, i32, i32] -> [i32]>,
            "timer_poll" => timer_poll<[i32] -> [i32]>,
            "timer_create" => timer_create<[i32] -> [i32]>,
            "forward_create" => forward_create<[i32, i32, i32, i32, i32] -> [i32]>,
            "forward_poll" => forward_poll<[i32, i32, i32] -> [i32]>,
            "request_query_name" => request_query_name<[i32, i32, i32] -> [i32]>,
            "request_query_type" => request_query_type<[i32] -> [i32]>,
            "request_set_response" => request_set_response<[i32, i32, i32] -> [i32]>,
            "request_get_response" => request_get_response<[i32, i32, i32] -> [i32]>,
            "request_local_addr" => request_local_addr<[i32, i32, i32] -> [i32]>,
            "request_remote_addr" => request_remote_addr<[i32, i32, i32] -> [i32]>,
            "request_protocol" => request_protocol<[i32] -> [i32]>,
            "request_from_cache" => request_from_cache<[i32] -> [i32]>,
            "request_elapsed" => request_elapsed<[i32, i32, i32] -> [i32]>,
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

// wasmer 0.1.2 doesn't support multiple return value
extern "C" fn timestamp(secs_ptr: i32, nsecs_ptr: i32, ctx: &mut Ctx) -> i32 {
    let now = SystemTime::now();
    let duration = match now.duration_since(UNIX_EPOCH) {
        Ok(d) => d,
        Err(_) => return guest::Error::Unknown.into(),
    };

    send_duration(duration, secs_ptr as usize, nsecs_ptr as usize, ctx)
}

fn send_duration(duration: Duration, secs_ptr: usize, nsecs_ptr: usize, ctx: &mut Ctx) -> i32 {
    let memory = ctx.memory_mut(0);

    if secs_ptr != 0 {
        let slice = &mut memory[secs_ptr..secs_ptr + 8];
        slice.copy_from_slice(&duration.as_secs().to_be_bytes());
    }

    if nsecs_ptr != 0 {
        let slice = &mut memory[nsecs_ptr..nsecs_ptr + 4];
        slice.copy_from_slice(&duration.subsec_nanos().to_be_bytes());
    }

    return guest::Error::Ok.into();
}

extern "C" fn register_future(data: i32, vtable_ptr: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    let task_id = instance.create_task();
    match instance.get_tasks_mut().get_mut(task_id as usize) {
        Some(ref mut fut) => {
            trace!(
                "[{}] callback #{} created {}/{}",
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

extern "C" fn register_on_message(phase: i32, data: i32, vtable_ptr: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);

    let phase = guest::Phase::from(phase);
    if phase == guest::Phase::Invalid {
        return guest::Error::InvalidInput.into();
    }

    // The callbacks are currently passed as fat pointers for `FnMut`,
    // this automatically expands to two pointers: data and vtable pointer.
    instance.callback_message.write().insert(
        phase,
        GuestCallback {
            ptr: (data, vtable_ptr),
        },
    );
    return guest::Error::Ok.into();
}

extern "C" fn timer_poll(task_id: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    let res = match instance.get_tasks_mut().get_mut(task_id as usize) {
        Some(ref mut task) => {
            // Check if the task is complete
            match task.host_future {
                HostFuture::Delay(ref mut delay) => match delay.poll() {
                    Ok(Async::Ready(_)) => {
                        trace!("[{}] delay #{} fired", instance, task_id);
                        guest::Async::Ready(0.into())
                    }
                    Ok(Async::NotReady) => guest::Async::NotReady,
                    Err(e) => {
                        warn!("[{}] delay #{} error: {:?}", instance, task_id, e);
                        guest::Async::Error(guest::Error::Other(e.to_string()))
                    }
                },
                _ => guest::Async::Error(guest::Error::InvalidInput),
            }
        }
        None => {
            warn!("[{}] delay #{} which does not exist", instance, task_id);
            guest::Async::Error(guest::Error::NotFound)
        }
    };

    // Complete the task
    if res.is_ready() {
        drop(instance.remove_task(task_id as usize));
    }

    res.into()
}

extern "C" fn timer_create(ms: i32, ctx: &mut Ctx) -> i32 {
    // Check for invalid duration
    if ms <= 0 {
        return guest::Error::InvalidInput.into();
    }

    let instance = from_context(ctx);
    let task_id = instance.create_task();

    // Spawn the future and notify when done
    let when = Instant::now() + Duration::from_millis(ms as u64);
    if let Some(ref mut task) = instance.get_tasks_mut().get_mut(task_id) {
        trace!("[{}] delay #{} started", instance, task_id);
        task.host_future = HostFuture::Delay(Delay::new(when));
        guest::from_result(Ok(task_id as i32))
    } else {
        guest::Error::Unknown.into()
    }
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
    trace!("[{}] forward to {:?} ({}B)", instance, upstream, msg.len());

    // Spawn the future and notify when done
    if let Some(ref mut task) = instance.get_tasks_mut().get_mut(task_id) {
        let request = forwarder::Builder::new()
            .with_upstream_servers(vec![upstream])
            .build()
            .resolve(&instance.context, &scope);
        task.host_future = HostFuture::Resolve(Box::new(request));
        guest::from_result(Ok(task_id as i32))
    } else {
        guest::Error::Unknown.into()
    }
}

extern "C" fn forward_poll(task_id: i32, msg_ptr: i32, msg_max_len: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);

    // Check arguments
    if msg_max_len <= 0 || msg_max_len > i32::from(u16::max_value()) {
        trace!("[{}] forward #{}, invalid buffer", instance, task_id);
        return guest::Async::Error(guest::Error::InvalidInput).into();
    }

    // Buffer message from the host
    let memory = ctx.memory_mut(0);
    let slice = &mut memory[msg_ptr as usize..(msg_ptr + msg_max_len) as usize];
    match instance.get_tasks_mut().get_mut(task_id as usize) {
        Some(task) => {
            // Check if the task has closed the buffer
            let resolve = match task.host_future {
                HostFuture::Resolve(ref mut x) => x,
                _ => return guest::Async::Error(guest::Error::InvalidInput).into(),
            };
            match resolve.poll() {
                Ok(Async::NotReady) => guest::Async::NotReady.into(),
                Ok(Async::Ready(item)) => {
                    let len = item.len();
                    if len > msg_max_len as usize {
                        trace!("[{}] forward #{}, item too large", instance, task_id);
                        return guest::Async::Error(guest::Error::TooBig).into();
                    }

                    slice[..len].copy_from_slice(&item);
                    guest::Async::Ready((len as u16).into()).into()
                }
                Err(e) => {
                    trace!("[{}] forward #{}, poll: {:?}", instance, task_id, e);
                    guest::Async::Error(guest::Error::InvalidInput).into()
                }
            }
        }
        // Task doesn't exist
        None => guest::Async::Error(guest::Error::NotFound).into(),
    }
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

fn request_addr(addr: IpAddr, ptr: i32, max_len: i32, ctx: &mut Ctx) -> i32 {
    let memory = ctx.memory_mut(0);
    let slice = &mut memory[ptr as usize..(ptr + max_len) as usize];
    // Require the buffer to hold at least an IPv6 address
    if slice.len() < 16 {
        return guest::Error::TooBig.into();
    }
    // Convert the IP address to slice
    match addr {
        IpAddr::V4(x) => {
            let x = x.octets();
            slice[..x.len()].copy_from_slice(&x);
            x.len() as i32
        }
        IpAddr::V6(x) => {
            let x = x.octets();
            slice[..x.len()].copy_from_slice(&x);
            x.len() as i32
        }
    }
}

extern "C" fn request_local_addr(request: i32, ptr: i32, max_len: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    let requests = instance.get_requests();

    let addr = match requests.get(request as usize) {
        Some((ref scope, ..)) => scope.local_addr,
        // Request with given id does not exist
        None => return guest::Error::NotFound.into(),
    };

    let ip = match addr {
        Some(addr) => addr.ip(),
        None => return guest::Error::NotFound.into(),
    };

    request_addr(ip, ptr, max_len, ctx)
}

extern "C" fn request_remote_addr(request: i32, ptr: i32, max_len: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    let requests = instance.get_requests();

    let ip = match requests.get(request as usize) {
        Some((ref scope, ..)) => scope.peer_addr.ip(),
        // Request with given id does not exist
        None => return guest::Error::NotFound.into(),
    };
    request_addr(ip, ptr, max_len, ctx)
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

extern "C" fn request_get_response(request: i32, ptr: i32, max_len: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    if let Some((.., ref answer)) = instance.get_requests().get(request as usize) {
        let (ptr, max_len) = (ptr as usize, max_len as usize);

        // Check if the buffer provided by guest is large enough
        let len = answer.len();

        if len > max_len {
            return guest::Error::TooBig.into();
        }

        // Copy the whole data
        let memory = ctx.memory_mut(0);
        let slice = &mut memory[ptr..(ptr + len)];
        slice.copy_from_slice(&answer);

        guest::from_result(Ok(len as i32))
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

extern "C" fn request_protocol(request: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    if let Some((ref scope, ..)) = instance.get_requests().get(request as usize) {
        scope.protocol as i32
    } else {
        // Request with given id does not exist
        guest::Error::NotFound.into()
    }
}

extern "C" fn request_from_cache(request: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    if let Some((ref scope, ..)) = instance.get_requests().get(request as usize) {
        match scope.from_cache {
            true => 1,
            false => 0,
        }
    } else {
        // Request with given id does not exist
        guest::Error::NotFound.into()
    }
}

extern "C" fn request_elapsed(request: i32, secs_ptr: i32, nsecs_ptr: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    let requests = instance.get_requests();

    let duration = match requests.get(request as usize) {
        Some((ref scope, ..)) => scope.start_time.elapsed(),
        // Request with given id does not exist
        None => return guest::Error::NotFound.into(),
    };

    send_duration(duration, secs_ptr as usize, nsecs_ptr as usize, ctx)
}

extern "C" fn local_socket_open(ptr: i32, len: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    let memory = ctx.memory(0);
    let slice = &memory[ptr as usize..(ptr + len) as usize];

    // Parse path from the guest
    // TODO: ensure it's in preconfigured chroot
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

    // Open connection to local socket, and connect guest stream to sink
    trace!("[{}] connecting local stream {:?}", instance, path);
    let instance_clone = instance.clone();
    tokio::spawn(UnixStream::connect(&path).then(move |res| match res {
        Ok(stream) => {
            if let Some(ref mut task) = instance_clone.get_tasks_mut().get_mut(task_id) {
                task.host_future =
                    HostFuture::LocalStream((stream, BytesMut::with_capacity(STREAM_BUF_CAPACITY)));
            }
            Ok(())
        }
        Err(e) => {
            warn!(
                "[{}] error in stream #{}: {:?}, closed",
                instance, task_id, e
            );
            Ok(())
        }
    }));

    task_id as i32
}

/// Write the remaining buffered data to stream and flush.
fn local_socket_flush(io: &mut UnixStream, buf: &mut BytesMut) -> Poll<(), io::Error> {
    // Try to flush the buffered data
    while !buf.is_empty() {
        let len = futures::try_ready!(io.poll_write(&buf));
        if len == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        // Advance the buffer to skip over written data
        drop(buf.split_to(len));
        if buf.is_empty() {
            buf.reserve(STREAM_BUF_CAPACITY);
        }
    }

    // Try to flush the writer
    io.poll_flush()
}

extern "C" fn local_socket_send(task_id: i32, ptr: i32, len: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);

    // Check arguments
    if len < 0 || len > u16::max_value() as i32 {
        trace!("[{}] local stream {}, buflen {}", instance, task_id, len);
        return guest::Async::Error(guest::Error::InvalidInput).into();
    }

    // Buffer message from the host
    let memory = ctx.memory_mut(0);
    let slice = &memory[ptr as usize..(ptr + len) as usize];
    match instance.get_tasks_mut().get_mut(task_id as usize) {
        Some(task) => {
            let (io, buf) = match task.host_future {
                HostFuture::LocalStream(ref mut data) => data,
                _ => return guest::Async::Error(guest::Error::InvalidInput).into(),
            };
            // If host passed an empty message or if the buffer is full, flush
            if len == 0 || buf.remaining_mut() < slice.len() {
                match local_socket_flush(io, buf) {
                    Ok(Async::NotReady) => return guest::Async::NotReady.into(),
                    Err(e) => {
                        trace!("[{}] local stream {}, flush: {:?}", instance, task_id, e);
                        return guest::Async::Error(guest::Error::Unknown).into();
                    }
                    _ => {}
                }
            }
            // Buffer the data
            buf.extend_from_slice(slice);
            guest::Async::Ready((len as u16).into()).into()
        }
        // Task doesn't exist
        None => return guest::Async::Error(guest::Error::NotFound).into(),
    }
}

extern "C" fn local_socket_recv(task_id: i32, ptr: i32, len: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);
    // Check arguments
    if len < 0 || len > u16::max_value() as i32 {
        trace!("[{}] local stream {}, buflen {}", instance, task_id, len);
        return guest::Async::Error(guest::Error::InvalidInput).into();
    }

    // Buffer message from the host
    let memory = ctx.memory_mut(0);
    let slice = &mut memory[ptr as usize..(ptr + len) as usize];
    match instance.get_tasks_mut().get_mut(task_id as usize) {
        Some(task) => {
            // Poll the local stream for data
            let io = match task.host_future {
                HostFuture::LocalStream((ref mut io, ..)) => io,
                _ => return guest::Async::Error(guest::Error::InvalidInput).into(),
            };
            match io.poll_read(slice) {
                Ok(Async::NotReady) => guest::Async::NotReady.into(),
                Ok(Async::Ready(len)) => guest::Async::Ready((len as u16).into()).into(),
                Err(e) => {
                    trace!("[{}] local stream {}, poll: {:?}", instance, task_id, e);
                    guest::Async::Error(guest::Error::InvalidInput).into()
                }
            }
        }
        // Task doesn't exist
        None => guest::Async::Error(guest::Error::NotFound).into(),
    }
}

extern "C" fn local_socket_close(task_id: i32, ctx: &mut Ctx) -> i32 {
    let instance = from_context(ctx);

    // Set the closed flag to initiate teardown
    if instance.get_tasks().contains(task_id as usize) {
        trace!("[{}] local stream {}, closing", instance, task_id);
        drop(instance.remove_task(task_id as usize));
        guest::from_result(Ok(0))
    } else {
        guest::Error::NotFound.into()
    }
}
