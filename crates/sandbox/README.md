# WebAssembly sandbox for EdgeDNS

There's two libraries:
* `guest` implementing guest-side host calls and abstractions with std::future
* `runtime` implementing host-side runtime library and dev server for guest apps

## Development

There's a demo app in `example-app`, you can compile it inside it's directory:

```bash
$ cd crates/sandbox/example-app
$ cargo build --release
```

You can now load it in a test runtime:

```bash
$ export RUST_LOG=libedgedns_sandbox,edgedns_sandbox_runtime=trace
$ export WASM_FILE=crates/sandbox/example-app/target/wasm32-unknown-unknown/release/example.wasm
$ cargo run --bin edgedns-sandbox-runtime -- -f ${WASM_FILE} -l 127.0.0.1:5354
```

The runtime will automatically reload the `${WASM_FILE}` when it changes. You can now query it:

```bash
$ kdig @127.0.0.1 -p 5354 example.com A
;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 11541
;; Flags: qr rd; QUERY: 1; ANSWER: 0; AUTHORITY: 0; ADDITIONAL: 0

;; QUESTION SECTION:
;; example.com.        		IN	A

;; Received 29 B
;; Time 2019-02-01 10:51:30 PST
;; From 127.0.0.1@5354(UDP) in 1.2 ms
```