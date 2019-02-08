/// Functions and types relating to error handling.
/// It uses https://github.com/rust-lang/rfcs/pull/2504 traits (from Rust 1.30)

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::net;
use std::result;
use tokio::timer;
// use futures::sync::mpsc;
// use domain_core::bits;

/// A specialized `Result` type
///
/// All functions with a recoverable failure condition will return this type.
/// You can either use it directly, or wrap it in your own error type.
pub type Result<T = ()> = result::Result<T, Error>;

/// Represents the types of error that can occur.
///
/// Note that if you `match` on this enum, you will be forced to add a wildcard arm by the compiler.
/// This is so that if a new error type is added later on, it will not break your code.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// An error that occurred while performing an I/O operation (e.g. while reading from a socket).
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Io(e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<io::ErrorKind> for Error {
    fn from(e: io::ErrorKind) -> Error {
        Error::Io(io::Error::new(e, ""))
    }
}

impl From<net::AddrParseError> for Error {
    fn from(e: net::AddrParseError) -> Error {
        Error::Io(io::Error::new(io::ErrorKind::AddrNotAvailable, e.description()))
    }
}

impl <T: StdError> From<timer::timeout::Error<T>> for Error {
    fn from(e: timer::timeout::Error<T>) -> Error {
        if e.is_elapsed() {
        	Error::from(io::ErrorKind::TimedOut)
        } else {
        	Error::from(io::Error::new(io::ErrorKind::Other, e.description()))
        }
    }
}

// impl <T> From<mpsc::SendError<T>> for Error {
//     fn from(e: mpsc::SendError<T>) -> Error {
//         io::ErrorKind::BrokenPipe.into()
//     }
// }

// impl From<bits::ShortBuf> for Error {
//     fn from(e: bits::ShortBuf) -> Error {
//         io::ErrorKind::BrokenPipe.into()
//     }
// }