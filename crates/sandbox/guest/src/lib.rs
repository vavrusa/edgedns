#![feature(
    integer_atomics,
    alloc,
    format_args_nl,
    alloc_error_handler,
    core_intrinsics,
    proc_macro_hygiene,
    slice_internals
)]
#![cfg_attr(
    all(feature = "futures"),
    feature(async_await, await_macro, futures_api, generators)
)]

extern crate alloc;

#[cfg(feature = "futures")]
mod guest_futures;
#[cfg(feature = "futures")]
pub use crate::guest_futures::*;

pub mod host_calls;

mod types;
pub use types::*;

/// Convert host call encoded result (`i32`) into `Result`.
pub fn to_result(raw: i32) -> Result {
    match raw >= 0 {
        true => Ok(raw),
        false => Err(Error::from(raw)),
    }
}
