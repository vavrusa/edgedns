use crate::{host_calls, to_result, Action, Async, AsyncState, AsyncValue, Error};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::rc::Rc;
use core::fmt::Write;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicI32, Ordering};
use futures::prelude::Future;
use futures::task::{LocalWaker, Poll, UnsafeWake, Waker};

/// Client request handle.
pub struct Request {
    id: i32,
    buf: Vec<u8>,
}

impl Request {
    /// Return client request query name in RFC1035 wire format.
    pub fn query_name(&mut self) -> Result<&[u8], Error> {
        let mut buf_size = 16;

        loop {
            // Reserve enough space for qname in the buffer
            self.buf.resize(buf_size, 0);

            // Fetch query name
            let res = unsafe {
                host_calls::request_query_name(self.id, self.buf.as_mut_ptr(), self.buf.len() as i32)
            };

            match to_result(res) {
                Ok(len) => return Ok(&self.buf[..len as usize]),
                Err(e) => match e {
                    // Try increase the buffer size
                    Error::TooBig => {
                        // Maximum size reached
                        if buf_size >= 255 {
                            return Err(e);
                        }

                        buf_size += 16;
                    }
                    _ => return Err(e),
                }
            }
        }
    }

    /// Return client request query type in numeric format, e.g. 28 = AAAA.
    pub fn query_type(&self) -> u16 {
        unsafe { host_calls::request_query_type(self.id) }
    }

    /// Rewrite response bytes to given slice.
    pub fn set_response(&self, message: &[u8]) -> Result<(), Error> {
        let res = unsafe {
            host_calls::request_set_response(self.id, message.as_ptr(), message.len() as i32)
        };
        if res < 0 {
            Err(Error::Unknown)
        } else {
            Ok(())
        }
    }
}

/// Prints formatted message on host (if enabled).
#[macro_export]
macro_rules! debug {
    ($fmt:expr) => ({
        $crate::debug_str($fmt);
    });
    ($($arg:tt)*) => ({
        $crate::debug_fmt(format_args!($($arg)*));
    })
}

/// Print string on host.
#[inline]
pub fn debug_str(line: &str) {
    unsafe { host_calls::debug(line.as_ptr() as i32, line.len() as i32) }
}

/// Print string on host.
pub fn debug_fmt(fmt: core::fmt::Arguments) {
    let mut line = String::new();
    drop(write!(&mut line, "{}", fmt));
    unsafe { host_calls::debug(line.as_ptr() as i32, line.len() as i32) }
}

/// Future implementing a delay.
pub struct Delay {
    task_id: Option<i32>,
    duration_ms: i32,
}

impl Delay {
    pub fn from_millis(millis: i32) -> Self {
        Self {
            task_id: None,
            duration_ms: millis,
        }
    }
}

impl Future for Delay {
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, _lw: &LocalWaker) -> Poll<Self::Output> {
        // Create task if it doesn't exist
        if self.task_id.is_none() {
            self.task_id = match to_result(unsafe { host_calls::timer_create(self.duration_ms) }) {
                Ok(v) => Some(v),
                Err(e) => return Poll::Ready(Err(e)),
            };
        }

        // Continue polling
        let res = Async::from(unsafe { host_calls::timer_poll(self.task_id.unwrap()) });
        match res {
            Async::Ready(_) => Poll::Ready(Ok(())),
            Async::NotReady => Poll::Pending,
            Async::Error(_) => Poll::Ready(Err(Error::Unknown)),
        }
    }
}

// Future implementing a forward request.
pub struct Forward<'a> {
    request: i32,
    task_id: i32,
    upstream: &'a str,
    response_buf: Vec<u8>,
}

impl<'a> Forward<'a> {
    pub fn new(upstream: &'a str) -> Self {
        Self {
            upstream,
            request: -1,
            task_id: -1,
            response_buf: Vec::with_capacity(1452),
        }
    }

    pub fn with_request(req: &Request, upstream: &'a str) -> Self {
        Self {
            upstream,
            request: req.id,
            task_id: -1,
            response_buf: Vec::with_capacity(1452),
        }
    }
}

impl<'a> Future for Forward<'a> {
    type Output = Result<Vec<u8>, Error>;

    fn poll(mut self: Pin<&mut Self>, _lw: &LocalWaker) -> Poll<Self::Output> {
        if self.task_id < 0 {
            self.task_id = unsafe {
                host_calls::forward_create(
                    self.request,
                    self.upstream.as_ptr(),
                    self.upstream.len() as u16,
                    core::ptr::null(),
                    0,
                )
            };
            if self.task_id < 0 {
                return Poll::Ready(Err(Error::Unknown));
            }
        }

        let capacity = self.response_buf.capacity();
        self.response_buf.resize(capacity, 0);
        let res = Async::from(unsafe {
            host_calls::forward_poll(
                self.task_id,
                self.response_buf.as_mut_ptr(),
                self.response_buf.len() as u16,
            )
        });

        match res {
            Async::Ready(len) => {
                let len = u16::from(len);
                if len == 0 || len as usize > self.response_buf.capacity() {
                    Poll::Ready(Err(Error::Unknown))
                } else {
                    let msg = self.response_buf[..len as usize].to_vec();
                    Poll::Ready(Ok(msg))
                }
            }
            Async::NotReady => Poll::Pending,
            Async::Error(_) => Poll::Ready(Err(Error::Unknown)),
        }
    }
}

/// Stream connected to a local endpoint (e.g. local socket).
#[derive(Clone)]
pub struct LocalStream {
    task_id: Rc<AtomicI32>,
}

impl LocalStream {
    /// Create an unconnected stream.
    pub fn new() -> Self {
        Self {
            task_id: Rc::new(AtomicI32::new(-1))
        }
    }

    /// Check if the local stream is connected.
    pub fn is_connected(&self) -> bool {
        self.task_id.load(Ordering::Relaxed) >= 0
    }

    /// Ask host for a connected stream to local endpoint.
    pub fn connect(path: &str) -> Result<LocalStream, Error> {
        match to_result(unsafe { host_calls::privileged::local_socket_open(path.as_ptr(), path.len() as i32) }) {
            Ok(task_id) => Ok(Self{task_id: Rc::new(AtomicI32::new(task_id))}),
            Err(e) => Err(e),
        }
    }

    /// Attempt to reconnect the stream.
    pub fn reconnect(&mut self, path: &str) -> Result<(), Error> {
        let new_task_id = match to_result(unsafe { host_calls::privileged::local_socket_open(path.as_ptr(), path.len() as i32) }) {
            Ok(task_id) => task_id,
            Err(e) => return Err(e),
        };

        // Swap and close old task if sensible
        let old_task_id = self.task_id.swap(new_task_id, Ordering::Relaxed);
        if old_task_id >= 0 {
            unsafe { host_calls::privileged::local_socket_close(old_task_id); }
        }

        Ok(())
    }

    /// Poll state of the local stream.
    pub fn poll_state(&self) -> Result<(), Error> {
        let task_id = self.task_id.load(Ordering::Relaxed);
        match to_result(unsafe { host_calls::privileged::local_socket_send(task_id, core::ptr::null(), 0) }) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Shutdown current stream, it will not be readable or writeable anymore.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        let task_id = self.task_id.swap(-1, Ordering::Relaxed);
        if task_id < 0 {
            return Err(Error::NotFound);
        }
        match to_result(unsafe { host_calls::privileged::local_socket_close(task_id) }) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(feature = "std")]
use futures::io::{self, AsyncWrite};

#[cfg(feature = "std")]
impl AsyncWrite for LocalStream {
    fn poll_write(&mut self, _lw: &LocalWaker, buf: &[u8]) -> Poll<io::Result<usize>> {
        let task_id = self.task_id.load(Ordering::Relaxed);
        // TODO: split buffer into maximum chunks of 64K as only u16 can be transferred at a time
        match to_result(unsafe { host_calls::privileged::local_socket_send(task_id, buf.as_ptr(), buf.len() as i32) }) {
            Ok(v) => {
                if v == 0 {
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(v as usize))    
                }
            },
            Err(e) => Poll::Ready(Err(io::ErrorKind::Other.into())),
        }
    }

    fn poll_flush(&mut self, _lw: &LocalWaker) -> Poll<io::Result<()>> {
        Poll::Ready(self.poll_state().map_err(move |e| io::ErrorKind::Other.into()))
    }

    fn poll_close(&mut self, _lw: &LocalWaker) -> Poll<io::Result<()>> {
        Poll::Ready(self.shutdown().map_err(move |e| io::ErrorKind::Other.into()))
    }
}

fn poll_future<I: Into<AsyncValue> + 'static, F: Future<Output = Result<I, Error>>>(
    future: &mut F,
) -> Async {
    let local_waker = unsafe { LocalWaker::new(NoopWaker::get()) };
    let mut future = unsafe { Pin::new_unchecked(future) };
    match future.as_mut().poll(&local_waker) {
        Poll::Pending => Async::NotReady,
        Poll::Ready(value) => match value {
            Ok(value) => {
                // TODO: figure out if we need futures that return complex types
                // let value_size = core::mem::size_of::<I>() as i32;
                // if value_size > 0 {
                //   let value_ref = &value as *const I;
                //   unsafe { host_calls::fulfill_future(self.task_id, value_ref as *const _, value_size) };
                // }
                Async::Ready(value.into())
            }
            Err(e) => {
                debug!(e.as_str());
                Async::Error(e)
            }
        },
    }
}

fn schedule_future<I: Into<AsyncValue> + 'static>(
    mut future: impl Future<Output = Result<I, Error>> + 'static,
) -> Async {

    // Try poll to see if the future can complete early.
    match poll_future(&mut future) {
        Async::Ready(v) => return Async::Ready(v),
        Async::Error(e) => return Async::Error(e),
        _ => {}
    }

    let task_id = match to_result(unsafe { host_calls::create_future() }) {
        Ok(task_id) => task_id,
        Err(e) => return Async::Error(e),
    };

    let closure = Box::new(move || poll_future(&mut future).into());
    match to_result(unsafe { host_calls::register_future(task_id, Box::into_raw(closure)) }) {
        Ok(_) => Async::NotReady,
        Err(e) => Async::Error(e),
    }
}

#[inline]
pub fn spawn<I: Into<AsyncValue> + 'static>(
    f: impl Future<Output = Result<I, Error>> + 'static,
) -> Result<(), Error> {
    if let Async::Error(e) = schedule_future(f) {
        Err(e)
    } else {
        Ok(())
    }
}

#[inline]
pub fn for_each_message<F>(mut closure: impl FnMut(Request) -> F + 'static)
where
    F: Future<Output = Result<Action, Error>> + 'static,
{
    let wrapped_closure = Box::new(move |request_id| {
        let req = Request {
            id: request_id,
            buf: Vec::new(),
        };
        schedule_future(closure(req)).into()
    });
    unsafe { host_calls::register_on_message(Box::into_raw(wrapped_closure)) };
}

/// No-op waker for task notifications.
struct NoopWaker {}
static WAKER: NoopWaker = NoopWaker {};

impl NoopWaker {
    #[inline]
    pub fn get() -> NonNull<NoopWaker> {
        NonNull::from(&WAKER)
    }
}

unsafe impl UnsafeWake for NoopWaker {
    unsafe fn clone_raw(&self) -> Waker {
        Waker::new(NoopWaker::get())
    }

    unsafe fn drop_raw(&self) {}
    unsafe fn wake(&self) {}
}

// Trampoline for exported closures
#[no_mangle]
pub unsafe extern "C" fn __closure_trampoline(closure: *mut FnMut() -> i32) -> i32 {
    let res = (*closure)();

    // Drop the closure when it's finished. Caller must not call it again, or it will trap.
    match AsyncState::from(res) {
        AsyncState::Ready | AsyncState::Error => {
            Box::from_raw(closure);
        }
        _ => {}
    }

    res
}

// Trampoline to instantiate a future for given hook
#[no_mangle]
pub unsafe extern "C" fn __hook_trampoline(arg: i32, closure: *mut FnMut(i32) -> i32) -> i32 {
    (*closure)(arg)
}
