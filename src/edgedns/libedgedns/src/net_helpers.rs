//! Unix-specific helpers to create sockets with specific options

use super::{TCP_BACKLOG, UDP_BUFFER_SIZE};
use bpf;
use nix::fcntl::{fcntl, O_NONBLOCK};
use nix::fcntl::FcntlArg::F_SETFL;
use nix::sys::socket::{bind, listen, setsockopt, socket, sockopt, AddressFamily, InetAddr,
                       SockAddr, SockFlag, SockLevel, SockType};
use socket_priority;
use std::io;
use std::net::{self, SocketAddr, UdpSocket};
use std::os::unix::io::{FromRawFd, RawFd};
use std::str::FromStr;

#[inline]
pub fn socket_tcp_v4() -> io::Result<RawFd> {
    let socket_fd = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        SockLevel::Tcp as i32,
    )?;
    Ok(socket_fd)
}

#[inline]
pub fn socket_tcp_v6() -> io::Result<RawFd> {
    let socket_fd = socket(
        AddressFamily::Inet6,
        SockType::Stream,
        SockFlag::empty(),
        SockLevel::Tcp as i32,
    )?;
    Ok(socket_fd)
}

pub fn socket_tcp_bound(addr: &str) -> io::Result<net::TcpListener> {
    let actual: SocketAddr = FromStr::from_str(addr).expect("Invalid address");
    let nix_addr = SockAddr::Inet(InetAddr::from_std(&actual));
    let socket_fd = match actual {
        SocketAddr::V4(_) => socket_tcp_v4()?,
        SocketAddr::V6(_) => socket_tcp_v6()?,
    };
    let _ = setsockopt(socket_fd, sockopt::ReuseAddr, &true);
    let _ = setsockopt(socket_fd, sockopt::ReusePort, &true);
    let _ = setsockopt(socket_fd, sockopt::TcpNoDelay, &true);
    let _ = socket_priority::set_priority(socket_fd, socket_priority::Priority::Interactive);
    bind(socket_fd, &nix_addr).expect("Unable to bind a TCP socket");
    listen(socket_fd, TCP_BACKLOG).expect("Unable to listen to the TCP socket");
    let socket = unsafe { net::TcpListener::from_raw_fd(socket_fd) };
    Ok(socket)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn socket_udp_set_buffer_size(socket_fd: RawFd) {
    let _ = setsockopt(socket_fd, sockopt::SndBufForce, &UDP_BUFFER_SIZE);
    let _ = setsockopt(socket_fd, sockopt::RcvBufForce, &UDP_BUFFER_SIZE);
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn socket_udp_set_buffer_size(socket_fd: RawFd) {
    let _ = setsockopt(socket_fd, sockopt::SndBuf, &UDP_BUFFER_SIZE);
    let _ = setsockopt(socket_fd, sockopt::RcvBuf, &UDP_BUFFER_SIZE);
}

#[inline]
pub fn socket_udp_v4() -> io::Result<RawFd> {
    let socket_fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        SockLevel::Udp as i32,
    )?;
    Ok(socket_fd)
}

#[inline]
pub fn socket_udp_v6() -> io::Result<RawFd> {
    let socket_fd = socket(
        AddressFamily::Inet6,
        SockType::Datagram,
        SockFlag::empty(),
        SockLevel::Udp as i32,
    )?;
    Ok(socket_fd)
}

pub fn socket_udp_bound(addr: &str) -> io::Result<UdpSocket> {
    let actual: SocketAddr = FromStr::from_str(addr).expect("Invalid address");
    let nix_addr = SockAddr::Inet(InetAddr::from_std(&actual));
    let socket_fd = match actual {
        SocketAddr::V4(_) => socket_udp_v4()?,
        SocketAddr::V6(_) => socket_udp_v6()?,
    };
    let _ = setsockopt(socket_fd, sockopt::ReuseAddr, &true);
    let _ = setsockopt(socket_fd, sockopt::ReusePort, &true);
    let _ = set_bpf_udp_dns(socket_fd);
    let _ = socket_priority::set_priority(socket_fd, socket_priority::Priority::Interactive);
    socket_udp_set_buffer_size(socket_fd);
    bind(socket_fd, &nix_addr).expect("Unable to bind a UDP socket");
    let socket = unsafe { UdpSocket::from_raw_fd(socket_fd) };
    Ok(socket)
}

pub fn set_bpf_udp_dns(socket_fd: RawFd) -> io::Result<()> {
    let filter =
        bpf::bpfprog!(8,72 0 0 4,53 0 5 17,72 0 0 12,21 0 3 1,72 0 0 18,37 1 0 1,6 0 0 262144,6 0 0 0);
    bpf::attach_filter(socket_fd, filter)
}

#[inline]
pub fn set_nonblock(sock: RawFd) -> io::Result<()> {
    fcntl(sock, F_SETFL(O_NONBLOCK))?;
    Ok(())
}
