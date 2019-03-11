#![feature(async_await, await_macro, futures_api)]

// Use `wee_alloc` as the global allocator.
#[cfg(feature = "wee_alloc")]
use wee_alloc;
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use futures::future::{self, TryFutureExt};
use guest::{self, Action, Delay, Forward};

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
    guest::spawn(async move {
        drop(await!(Delay::from_millis(2000)));
        guest::debug!("guest timer has fired (async)");
        Ok(())
    })
    .unwrap();

    // Spawn for each message (async)
    guest::for_each_message(|req| async move {
        match req.query_type() {
        1 | 28 => {
            let res = await!(Forward::with_request(&req, "1.1.1.1:53"));
            if let Ok(msg) = res {
                drop(req.set_response(&msg));
            }
            Ok(Action::Deliver)
        },
        _ => Ok(Action::Pass),
        }
    });
}
