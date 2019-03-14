use crate::{host_calls, to_result};
use crate::{Action, Async, AsyncState, AsyncValue, Error, Phase, Protocol};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use core::pin::Pin;
use futures::io::{self, AsyncRead, AsyncReadExt, AsyncWrite};
use futures::prelude::Future;
use futures::task::noop_waker_ref;
use futures::task::{Poll, Waker};
use std::net::IpAddr;
use std::time::Duration;

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
                host_calls::request_query_name(
                    self.id,
                    self.buf.as_mut_ptr(),
                    self.buf.len() as i32,
                )
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
                },
            }
        }
    }

    /// Return client request query type in numeric format, e.g. 28 = AAAA.
    pub fn query_type(&self) -> u16 {
        unsafe { host_calls::request_query_type(self.id) }
    }

    /// Returns the local address for the request.
    pub fn local_addr(&self) -> Option<IpAddr> {
        let mut buf = [0u8; 16];
        let res = to_result(unsafe {
            host_calls::request_local_addr(self.id, buf.as_mut_ptr(), buf.len() as i32)
        });

        match res.ok() {
            Some(4) => {
                let mut b = [0u8; 4];
                b.copy_from_slice(&buf[..4]);
                Some(b.into())
            }
            Some(16) => Some(IpAddr::from(buf)),
            _ => None,
        }
    }

    /// Returns the remote address for the request.
    pub fn remote_addr(&self) -> Option<IpAddr> {
        let mut buf = [0u8; 16];
        let res = to_result(unsafe {
            host_calls::request_remote_addr(self.id, buf.as_mut_ptr(), buf.len() as i32)
        });

        match res.ok() {
            Some(4) => {
                let mut b = [0u8; 4];
                b.copy_from_slice(&buf[..4]);
                Some(b.into())
            }
            Some(16) => Some(IpAddr::from(buf)),
            _ => None,
        }
    }

    /// Get response for current request.
    pub fn get_response(&mut self) -> Result<&[u8], Error> {
        let mut buf_size = 512;
        let (step, max) = (512, 4096);

        loop {
            // Reserve enough space for answer in the buffer
            self.buf.resize(buf_size, 0);

            // Fetch data
            let rc = unsafe {
                host_calls::request_get_response(
                    self.id,
                    self.buf.as_mut_ptr(),
                    self.buf.len() as i32,
                )
            };

            match to_result(rc) {
                Ok(len) => {
                    return Ok(&self.buf[..len as usize]);
                }
                Err(e) => match e {
                    // Try increase the buffer size
                    Error::TooBig => {
                        // Maximum size reached
                        if buf_size >= max {
                            return Err(e);
                        }

                        buf_size += step;
                    }
                    _ => return Err(e),
                },
            }
        }
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

    /// Return the protocol client used to query
    pub fn protocol(&self) -> Result<Protocol, Error> {
        let r = to_result(unsafe { host_calls::request_protocol(self.id) })?;
        Ok(Protocol::from(r))
    }

    /// Return whether the request is resolved from cache
    pub fn from_cache(&self) -> Result<bool, Error> {
        let r = to_result(unsafe { host_calls::request_from_cache(self.id) })?;
        Ok(r == 1)
    }

    pub fn elapsed(&self) -> Result<Duration, Error> {
        let (mut sec, mut nsec) = ([0u8; 8], [0u8; 4]);
        to_result(unsafe {
            host_calls::request_elapsed(self.id, sec.as_mut_ptr(), nsec.as_mut_ptr())
        })?;
        Ok(Duration::new(
            u64::from_be_bytes(sec),
            u32::from_be_bytes(nsec),
        ))
    }
}

/// get current unix timestamp as Duration
#[inline]
pub fn timestamp() -> Result<Duration, Error> {
    let (mut sec, mut nsec) = ([0u8; 8], [0u8; 4]);
    to_result(unsafe { host_calls::timestamp(sec.as_mut_ptr(), nsec.as_mut_ptr()) })?;
    Ok(Duration::new(
        u64::from_be_bytes(sec),
        u32::from_be_bytes(nsec),
    ))
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

    fn poll(mut self: Pin<&mut Self>, _lw: &Waker) -> Poll<Self::Output> {
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

    fn poll(mut self: Pin<&mut Self>, _lw: &Waker) -> Poll<Self::Output> {
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

/// Typed task handle for stream.
struct StreamHandle(i32);

impl StreamHandle {
    /// Ask host for a connected stream to local endpoint.
    pub fn new(path: &str) -> Result<Self, Error> {
        match to_result(unsafe {
            host_calls::privileged::local_socket_open(path.as_ptr(), path.len() as i32)
        }) {
            Ok(fd) => Ok(Self(fd)),
            Err(e) => Err(e),
        }
    }
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        unsafe {
            host_calls::privileged::local_socket_close(self.0);
        }
    }
}

/// Stream connected to a local endpoint (e.g. local socket).
pub struct LocalStream(StreamHandle);

impl LocalStream {
    /// Ask host for a connected stream to local endpoint.
    pub fn connect(path: &str) -> Result<Self, Error> {
        match StreamHandle::new(path) {
            Ok(task) => Ok(Self(task)),
            Err(e) => Err(e),
        }
    }

    /// Returns inner handle descriptor.
    fn handle(&self) -> i32 {
        (self.0).0
    }
}

impl AsyncWrite for LocalStream {
    fn poll_write(&mut self, _lw: &Waker, buf: &[u8]) -> Poll<io::Result<usize>> {
        // TODO: split buffer into maximum chunks of 64K as only u16 can be transferred at a time
        match Async::from(unsafe {
            host_calls::privileged::local_socket_send(self.handle(), buf.as_ptr(), buf.len() as i32)
        }) {
            Async::Ready(v) => Poll::Ready(Ok(u16::from(v) as usize)),
            Async::NotReady => Poll::Pending,
            Async::Error(_) => Poll::Ready(Err(io::ErrorKind::Other.into())),
        }
    }

    fn poll_flush(&mut self, _lw: &Waker) -> Poll<io::Result<()>> {
        match Async::from(unsafe {
            host_calls::privileged::local_socket_send(self.handle(), core::ptr::null(), 0)
        }) {
            Async::Ready(_) => Poll::Ready(Ok(())),
            Async::NotReady => Poll::Pending,
            Async::Error(_) => Poll::Ready(Err(io::ErrorKind::Other.into())),
        }
    }

    fn poll_close(&mut self, _lw: &Waker) -> Poll<io::Result<()>> {
        let state =
            match to_result(unsafe { host_calls::privileged::local_socket_close(self.handle()) }) {
                Ok(_) => Ok(()),
                Err(_) => Err(io::ErrorKind::Other.into()),
            };

        Poll::Ready(state)
    }
}

impl AsyncRead for LocalStream {
    fn poll_read(&mut self, _lw: &Waker, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match Async::from(unsafe {
            host_calls::privileged::local_socket_recv(
                self.handle(),
                buf.as_mut_ptr(),
                buf.len() as i32,
            )
        }) {
            Async::Ready(v) => Poll::Ready(Ok(u16::from(v) as usize)),
            Async::NotReady => Poll::Pending,
            Async::Error(_) => Poll::Ready(Err(io::ErrorKind::Other.into())),
        }
    }
}

/// Buffered AsyncRead implementation that follows [BufRead](https://doc.rust-lang.org/std/io/trait.BufRead.html).
/// This is generally useful for reading delimiter-separated stream.
pub struct BufferedStream {
    io: LocalStream,
    buf: Vec<u8>,
    pos: usize,
}

impl BufferedStream {
    async fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.buf.is_empty() {
            self.buf.resize(self.buf.capacity(), 0);
            let n = await!(self.io.read(&mut self.buf))?;
            self.buf.resize(n, 0);
            self.pos = 0;
        }
        Ok(&self.buf[self.pos..])
    }

    fn consume(&mut self, amt: usize) {
        self.pos += amt;
        if self.pos == self.buf.len() {
            self.pos = 0;
            self.buf.clear();
        }
    }

    pub async fn read_until(&mut self, delim: u8, mut buf: Vec<u8>) -> io::Result<Vec<u8>> {
        loop {
            let (done, used) = {
                let available = match await!(self.fill_buf()) {
                    Ok(n) => n,
                    Err(e) => return Err(e),
                };
                match core::slice::memchr::memchr(delim, available) {
                    Some(i) => {
                        buf.extend_from_slice(&available[..=i]);
                        (true, i + 1)
                    }
                    None => {
                        buf.extend_from_slice(available);
                        (false, available.len())
                    }
                }
            };
            self.consume(used);
            if done || used == 0 {
                return Ok(buf);
            }
        }
    }
}

impl AsyncRead for BufferedStream {
    fn poll_read(&mut self, lw: &Waker, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        // Drain the buffered data and continue with unbuffered reading to avoid copies
        if !self.buf.is_empty() {
            let inner = &self.buf[self.pos..];
            let len = std::cmp::min(inner.len(), buf.len());
            buf[..len].copy_from_slice(&inner[..len]);
            self.consume(len);
            Poll::Ready(Ok(len))
        } else {
            self.io.poll_read(lw, buf)
        }
    }
}

impl AsyncWrite for BufferedStream {
    fn poll_write(&mut self, lw: &Waker, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.io.poll_write(lw, buf)
    }

    fn poll_flush(&mut self, lw: &Waker) -> Poll<io::Result<()>> {
        self.io.poll_flush(lw)
    }

    fn poll_close(&mut self, lw: &Waker) -> Poll<io::Result<()>> {
        self.io.poll_close(lw)
    }
}

impl From<LocalStream> for BufferedStream {
    fn from(io: LocalStream) -> BufferedStream {
        BufferedStream {
            io,
            buf: Vec::with_capacity(512),
            pos: 0,
        }
    }
}

fn poll_future<I: Into<AsyncValue> + 'static, F: Future<Output = Result<I, Error>>>(
    future: &mut F,
) -> Async {
    let local_waker = noop_waker_ref();
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

    let closure = Box::into_raw(Box::new(move || poll_future(&mut future).into()));
    match to_result(unsafe { host_calls::register_future(closure) }) {
        Ok(_) => Async::NotReady,
        Err(e) => {
            // Free the unregistered closure
            let _ = unsafe { Box::from_raw(closure) };
            Async::Error(e)
        }
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
    unsafe {
        host_calls::register_on_message(Phase::PreCache as i32, Box::into_raw(wrapped_closure))
    };
}

#[inline]
pub fn for_each_message_precache<F>(closure: impl FnMut(Request) -> F + 'static)
where
    F: Future<Output = Result<Action, Error>> + 'static,
{
    for_each_message_phase(Phase::PreCache, closure)
}

#[inline]
pub fn for_each_message_finish<F>(closure: impl FnMut(Request) -> F + 'static)
where
    F: Future<Output = Result<Action, Error>> + 'static,
{
    for_each_message_phase(Phase::Finish, closure)
}

fn for_each_message_phase<F>(phase: Phase, mut closure: impl FnMut(Request) -> F + 'static)
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
    unsafe { host_calls::register_on_message(phase as i32, Box::into_raw(wrapped_closure)) };
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
