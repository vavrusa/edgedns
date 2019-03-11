#![no_std]
#![feature(
    async_await,
    futures_api,
    generators,
    alloc_error_handler,
    core_intrinsics,
    proc_macro_hygiene
)]

// Use `wee_alloc` as the global allocator.
#[cfg(feature = "wee_alloc")]
use wee_alloc;
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use futures::future::{self, TryFutureExt};
use guest::{self, Action, Delay, Forward};
use embrio_async::{async_block, await};

#[no_mangle]
pub extern "C" fn run() {
    guest::debug!("hello from guest");

    // Spawn a future from guest
    guest::spawn(Delay::from_millis(1000).and_then(|_| {
        guest::debug!("guest timer has fired (futures)");
        future::ok(())
    }))
    .unwrap();

    // Spawn an async from guest
    guest::spawn(async_block! {
        drop(await!(Delay::from_millis(2000)));
        guest::debug!("guest timer has fired (async)");
        Ok(())
    })
    .unwrap();

    // Spawn for each message (async)
    guest::for_each_message(|req| {
        async_block! {
            match req.query_type() {
            1 | 28 => {
                let res = await!(Forward::with_request(&req, "1.1.1.1:53"));
                if let Ok(msg) = res {
                    req.set_response(&msg);
                }
                Ok(Action::Deliver)
            },
            _ => Ok(Action::Pass),
            }
        }
    });
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::intrinsics::abort();
    }
}

#[alloc_error_handler]
fn oom(_: core::alloc::Layout) -> ! {
    unsafe {
        core::intrinsics::abort();
    }
}
