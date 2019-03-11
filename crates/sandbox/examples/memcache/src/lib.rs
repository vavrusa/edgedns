#![feature(async_await, futures_api, await_macro)]
/// A dynamic forwarder that routes the messages to upstream based on mapping stored in memcache.
///
/// Example configuration:
///
/// ```bash
/// $ memcached -s memcache.sock
/// $ echo -ne "set 127.0.0.1 0 0 11\r\n1.1.1.1:853\r\n" | nc -U memcache.sock
/// # kdig @127.0.0.1 example.com
/// ```

// Use `wee_alloc` as the global allocator.
#[cfg(feature = "wee_alloc")]
use wee_alloc;
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use guest::{self, Action, Delay, Error, Forward, LocalStream};
use std::rc::Rc;
use std::sync::Mutex;
mod memcache;

#[no_mangle]
pub extern "C" fn run() {
    let kv = Rc::new(Mutex::new(None));

    // Reconnect to local memcache socket
    drop(guest::spawn(watch_local_socket(kv.clone())));

    // Forward to dynamic upstream based on local address
    guest::for_each_message(move |req| {
        let kv = kv.clone();
        async move {
            // Get mutable reference to memcache
            let mut guard = match kv.lock() {
                Ok(x) => x,
                Err(_) => return Ok(Action::Pass),
            };

            let kv = match &mut *guard {
                Some(ref mut x) => x,
                None => return Ok(Action::Pass),
            };

            // Get local address
            let local_addr = match req.local_addr() {
                Some(a) => a,
                None => return Ok(Action::Pass),
            };

            // Forward to selected upstream
            if let Ok(upstream) = await!(kv.get(&local_addr)) {
                guest::debug!("decoding to upstream: {:?}", upstream);
                if let Ok(upstream) = String::from_utf8(upstream) {
                    guest::debug!("forwarding to upstream: {}", upstream);
                    if let Ok(msg) = await!(Forward::with_request(&req, &upstream)) {
                        drop(req.set_response(&msg));
                        return Ok(Action::Deliver);
                    }
                }
            }

            Ok(Action::Pass)
        }
    });
}

async fn watch_local_socket(kv: Rc<Mutex<Option<memcache::AsciiProtocol>>>) -> Result<(), Error> {
    while await!(Delay::from_millis(5_000)).is_ok() {
        let mut guard = match kv.lock() {
            Ok(x) => x,
            Err(_) => continue,
        };

        if guard.is_none() {
            match LocalStream::connect("memcache.sock") {
                Ok(stream) => {
                    let stream = memcache::AsciiProtocol::new(stream.into());
                    drop(guard.replace(stream));
                }
                Err(_e) => {}
            }
        }
    }

    Ok(())
}
