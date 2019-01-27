#![cfg_attr(not(feature = "std"), no_std)]
#![feature(
  async_await,
  futures_api,
  generators,
  integer_atomics,
  alloc,
  format_args_nl,
  alloc_error_handler,
  core_intrinsics,
  proc_macro_hygiene,
)]

extern crate alloc;

#[cfg(feature = "futures")]
mod guest_futures;
#[cfg(feature = "futures")]
pub use crate::guest_futures::*;

pub mod host_calls;

mod types;
pub use types::*;

// TODO: https://github.com/rust-lang/rust/issues/56974
#[cfg(feature = "futures")]
pub use embrio_async::{async_block, await};

/// Convert host call encoded result (`i32`) into `Result`.
pub fn to_result(raw: i32) -> Result {
  match raw >= 0 {
    true => Ok(raw),
    false => Err(Error::from(raw)),
  }
}

/// Convert host call `Result` into the encoded result (`i32`).
pub fn from_result(res: Result) -> i32 {
  match res {
    Ok(v) => v,
    Err(e) => e.into(),
  }
}
