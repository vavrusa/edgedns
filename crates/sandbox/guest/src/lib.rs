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
use std::panic;

// Futures abstractions
#[cfg(feature = "futures")]
mod guest_futures;
#[cfg(feature = "futures")]
pub use crate::guest_futures::*;

// Types used by guest
pub use guest_types::*;

// Host calls ABI
pub mod host_calls;

/// Install the default panic handler.
pub fn default_panic_handler() {
    panic::set_hook(Box::new(|info| {
        let payload = info.payload().downcast_ref::<&str>().unwrap();
        if let Some(location) = info.location() {
            debug!(
                "panic occured {}:{}: {}",
                location.file(),
                location.line(),
                payload
            );
        } else {
            debug!("panic occured: {}", payload);
        }
    }));
}
