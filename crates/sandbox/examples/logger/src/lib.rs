#![feature(async_await, futures_api, generators, proc_macro_hygiene)]

// Use `wee_alloc` as the global allocator.
use wee_alloc;
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use futures::io::AsyncWriteExt;
use guest::{self, async_block, await, Action, Delay, LocalStream};
use std::rc::Rc;
use std::sync::Mutex;

// Include generated schema bindings
use byteorder::{ByteOrder, LittleEndian};
use capnp::message;

#[allow(dead_code)]
mod schema_capnp {
    include!(concat!(env!("OUT_DIR"), "/schema_capnp.rs"));
}

#[no_mangle]
pub extern "C" fn run() {
    let stream = Rc::new(Mutex::new(None));

    // Watch the open connection
    drop(watch_local_socket(stream.clone()));

    // Serialize log for each message and write it to the stream
    guest::for_each_message(move |mut req| {
        let stream = stream.clone();
        async_block! {
            let mut guard = stream.lock().unwrap();
            let stream = match &mut *guard {
                Some(ref mut stream) => stream,
                None => return Ok(Action::Pass),
            };

            let msg = build_message(&mut req);

            // Serialize segment table
            let segments = &*msg.get_segments_for_output();
            let res = match segments.len() {
                1 => {
                    let mut buf = [0; 8];
                    LittleEndian::write_u32(&mut buf[4..8], segments[0].len() as u32);
                    await!(stream.write_all(&buf))
                },
                _ => {
                    let buf = construct_segment_table(segments);
                    await!(stream.write_all(&buf))
                }
            };

            // Serialize segments
            match res {
                Ok(_) => {
                    for i in 0..segments.len() {
                        let buf = capnp::Word::words_to_bytes(segments[i]);
                        drop(await!(stream.write_all(buf)));
                    }
                },
                Err(_) => {
                    // Close on write error
                    *guard = None;
                }
            }

            Ok(Action::Pass)
        }
    });
}

fn watch_local_socket(stream: Rc<Mutex<Option<LocalStream>>>) -> Result<(), guest::Error> {
    guest::spawn(async_block! {
        while await!(Delay::from_millis(5_000)).is_ok() {
            // Attempt to reconnect if errored out
            let mut guard = stream.lock().unwrap();
            if guard.is_none() {
                match LocalStream::new("test.sock") {
                    Ok(stream) => { guard.replace(stream); },
                    Err(e) => {},
                }
            }
        }
        Ok(())
    })
}

// Helper to build log messages
fn build_message(req: &mut guest::Request) -> message::Builder<message::HeapAllocator> {
    let allocator = message::HeapAllocator::new()
        .allocation_strategy(message::AllocationStrategy::FixedSize)
        .first_segment_words(32); // N * 8B

    let mut message = message::Builder::new(allocator);
    {
        // Fill the log message fields
        let mut root = message.init_root::<schema_capnp::message::Builder>();
        root.set_query_name(req.query_name().unwrap_or(b""));
        root.set_query_type(req.query_type());
        root.set_protocol(schema_capnp::Protocol::Udp);
    }

    message
}

// Helper to build preface for serialized message
fn construct_segment_table(segments: &[&[capnp::Word]]) -> Vec<u8> {
    let mut buf = vec![0u8; ((segments.len() + 2) & !1) * 4];
    LittleEndian::write_u32(&mut buf[0..4], segments.len() as u32 - 1);
    for idx in 0..segments.len() {
        LittleEndian::write_u32(
            &mut buf[(idx + 1) * 4..(idx + 2) * 4],
            segments[idx].len() as u32,
        );
    }
    buf
}