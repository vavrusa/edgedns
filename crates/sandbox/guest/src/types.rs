use alloc::string::String;
use core::fmt;

/// Result type used between host and guest.
/// The encoding follows C ABIs and uses negative half for error codes, and positive half for values.
pub type Result = core::result::Result<i32, Error>;

/// Error type for host calls.
pub enum Error {
    Ok,
    Unknown,
    Other(String),
    NotFound,
    PermissionDenied,
    InvalidInput,
    TooBig,
}

impl From<Error> for i32 {
    fn from(e: Error) -> i32 {
        match e {
            Error::Ok => 0,
            Error::Unknown => -1,
            Error::Other(_) => -2,
            Error::NotFound => -3,
            Error::PermissionDenied => -4,
            Error::InvalidInput => -5,
            Error::TooBig => -6,
        }
    }
}

impl From<i32> for Error {
    fn from(raw: i32) -> Error {
        match raw {
            -2 => Error::Other("".into()),
            -3 => Error::NotFound,
            -4 => Error::PermissionDenied,
            -5 => Error::InvalidInput,
            -6 => Error::TooBig,
            _ => Error::Unknown,
        }
    }
}

/// Implement string conversion for debugging.
impl Error {
    pub fn as_str(&self) -> &str {
        match self {
            Error::Ok => "ok",
            Error::Unknown => "unknown",
            Error::Other(s) => s.as_str(),
            Error::NotFound => "not found",
            Error::PermissionDenied => "permission denied",
            Error::InvalidInput => "invalid input",
            Error::TooBig => "result size exceeded",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error({})", self.as_str())
    }
}

/// Asynchronous result type;
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum AsyncState {
    Error = 0,
    NotReady = 1,
    Ready = 2,
}

/// Optional value of an asynchronous result.
#[derive(Debug)]
pub struct AsyncValue(u16);

impl From<u16> for AsyncValue {
    fn from(v: u16) -> AsyncValue {
        AsyncValue(v)
    }
}

impl From<()> for AsyncValue {
    fn from(_: ()) -> AsyncValue {
        AsyncValue(0)
    }
}

impl From<AsyncValue> for u16 {
    fn from(v: AsyncValue) -> u16 {
        v.0 as u16
    }
}

/// Asynchronous result from guest.
/// The value is serialized as i32 for host calls.
#[derive(Debug)]
pub enum Async {
    Error(Error),
    NotReady,
    Ready(AsyncValue),
}

impl Async {
    /// Returns true if the Async value is ready.
    pub fn is_ready(&self) -> bool {
        match self {
            Async::NotReady => false,
            _ => true,
        }
    }
}

/// Convert enum to i32.
impl From<Async> for i32 {
    fn from(v: Async) -> i32 {
        match v {
            Async::Error(arg) => AsyncState::Error as i32 | -i32::from(arg) << 16,
            Async::NotReady => AsyncState::NotReady as i32,
            Async::Ready(arg) => AsyncState::Ready as i32 | i32::from(u16::from(arg)) << 16,
        }
    }
}

/// Convert from an i32.
impl From<i32> for AsyncState {
    fn from(id: i32) -> Self {
        match id as u16 {
            1 => AsyncState::NotReady,
            2 => AsyncState::Ready,
            _ => AsyncState::Error,
        }
    }
}

/// Convert from an i32.
impl From<i32> for Async {
    fn from(id: i32) -> Self {
        let code = id as u16;
        match code {
            1 => Async::NotReady,
            2 => Async::Ready(AsyncValue::from((id >> 16) as u16)),
            _ => Async::Error(Error::from(-(id >> 16))),
        }
    }
}

/// Next action in the processing pipeline.
/// The guest returns the action at the end of the task for request processing,
/// to signalize what's the desired processing state.
/// e.g. If the hook answers request completely, it might want to stop further processing
//       and deliver the result back to client.
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum Action {
    Pass = 0,
    Deliver = 1,
    // Purge = 2,
    Drop = 3,
    // UseStale = 4,
    // Trace = 5,
}

/// Convert enum to asynchronous value.
impl From<Action> for AsyncValue {
    fn from(v: Action) -> AsyncValue {
        match v {
            Action::Pass => AsyncValue(0),
            Action::Deliver => AsyncValue(1),
            Action::Drop => AsyncValue(3),
        }
    }
}

/// Convert from an asynchronous value.
impl From<AsyncValue> for Action {
    fn from(v: AsyncValue) -> Action {
        match v.0 {
            0 => Action::Pass,
            1 => Action::Deliver,
            // 2 => Action::Purge,
            3 => Action::Drop,
            // 4 => Action::UseStale,
            // 5 => Action::Trace,
            _ => Action::Pass,
        }
    }
}

/// Places where guest can register for a callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Phase {
    Invalid = 0,
    PreCache = 1,
    PostCache = 2,
}

impl From<i32> for Phase {
    fn from(n: i32) -> Phase {
        match n {
            1 => Phase::PreCache,
            2 => Phase::PostCache,
            _ => Phase::Invalid,
        }
    }
}

/// Convert host call `Result` into the encoded result (`i32`).
pub fn from_result(res: Result) -> i32 {
    match res {
        Ok(v) => v,
        Err(e) => e.into(),
    }
}
