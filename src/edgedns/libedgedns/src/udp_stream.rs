//! A streaming interface to tokio-io UDP sockets.
//!
//! This provides a consistent interface with TCP sockets.

use super::DNS_MAX_UDP_SIZE;
use failure;
use futures::{Async, Poll, Stream, try_ready};
use std::net::SocketAddr;
use std::io;
use std::net;
use std::rc::Rc;
use tokio::prelude::*;
use tokio::reactor::Handle;
use tokio::net::UdpSocket;

pub struct UdpStream {
    udp_socket: UdpSocket,
    buf: Vec<u8>,
}

impl UdpStream {
    pub fn from_socket(udp_socket: UdpSocket) -> Result<Self, io::Error> {
        let buf = vec![0; DNS_MAX_UDP_SIZE];
        Ok(UdpStream { udp_socket, buf })
    }

    pub fn from_std(
        net_udp_socket: net::UdpSocket,
    ) -> Result<Self, io::Error> {
        let udp_socket = UdpSocket::from_std(net_udp_socket, &Handle::default())?;
        Self::from_socket(udp_socket)
    }
}

impl Stream for UdpStream {
    type Item = (Vec<u8>, SocketAddr);
    type Error = failure::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let client_ip = {
            let mut bufw = &mut self.buf;
            let capacity = bufw.capacity();
            unsafe { bufw.set_len(capacity) };
            let (count, client_ip) = try_ready!(self.udp_socket.poll_recv_from(&mut bufw));
            unsafe { bufw.set_len(count) };
            client_ip
        };
        Ok(Async::Ready(Some((self.buf.clone(), client_ip))))
    }
}
