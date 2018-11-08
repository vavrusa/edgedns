use futures::{Future, Stream};
use crate::hooks::Hooks;
use parking_lot::RwLock;
use prost;
use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use std::thread;
use tokio::prelude::*;
use tokio::runtime::Runtime;
use tokio::io::{read_to_end, write_all};
use tokio::net::{UnixListener, UnixStream};
use prost::*;
#[macro_use] use prost_derive::*;

pub mod cli {
    include!(concat!(env!("OUT_DIR"), "/edgedns.cli.rs"));
}

pub struct CLIListener {
    socket_path: String,
    hooks_arc: Arc<RwLock<Hooks>>,
}

impl CLIListener {
    pub fn new(socket_path: String, hooks_arc: Arc<RwLock<Hooks>>) -> Self {
        CLIListener {
            socket_path,
            hooks_arc,
        }
    }

    fn client_action(
        action: Option<cli::command::Action>,
        hooks_arc: &Arc<RwLock<Hooks>>,
    ) -> Result<(), &'static str> {
        match action {
            Some(cli::command::Action::ServiceLoad(service_load)) => {
                match hooks_arc.write().load_library_for_service_id(
                    &service_load.library_path,
                    service_load.service_id.as_bytes(),
                ) {
                    Err(e) => Err(e),
                    _ => Ok(()),
                }
            }
            Some(cli::command::Action::ServiceUnload(service_unload)) => match hooks_arc
                .write()
                .unregister_service(service_unload.service_id.as_bytes())
            {
                Err(e) => Err(e),
                _ => Ok(()),
            },
            _ => Err("Unsupported action"),
        }
    }

    fn client_process(&self, socket: UnixStream) {
        let hooks_arc = Arc::clone(&self.hooks_arc);
        let buf = Vec::new();
        let reader = read_to_end(socket, buf)
            .map(move |(socket, serialized)| {
                let res = match cli::Command::decode(&mut Cursor::new(serialized)) {
                    Err(_) => Err("Invalid serialized command received from the CLI"),
                    Ok(command) => Self::client_action(command.action, &hooks_arc),
                };
                (res, socket)
            })
            .and_then(move |(_res, mut socket)| {
                let _ = socket.write_all(b"DONE\n");
                Ok(())
            })
            .then(|_| Ok(()));

        tokio::spawn(reader);
    }

    pub fn spawn(self, rt: &mut Runtime) {
        let listener = match UnixListener::bind(&self.socket_path) {
            Ok(m) => m,
            Err(_) => {
                let _ = fs::remove_file(&self.socket_path);
                UnixListener::bind(&self.socket_path).expect(&format!(
                    "Unable to create a unix socket named [{}]",
                    self.socket_path
                ))
            }
        };

        let task = listener.incoming()
        .map_err(|e| eprintln!("accept failed = {:?}", e))
        .for_each(move |socket| {
            self.client_process(socket);
            Ok(())
        });

        rt.spawn(task);
    }
}
