extern crate capnpc;

fn main() {
    ::capnpc::CompilerCommand::new()
        .file("schema.capnp")
        .edition(capnpc::RustEdition::Rust2018)
        .run()
        .expect("compiled schema");
}
