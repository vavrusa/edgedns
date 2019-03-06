use guest::{self, Action};
use futures::future::ok;

#[no_mangle]
pub extern "C" fn run() {
    // Spawn a future from guest
    guest::spawn(ok(())).expect("future spawned");

    // Spawn for each message
    guest::for_each_message(|req| ok(Action::Pass));
}