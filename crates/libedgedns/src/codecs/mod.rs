use bytes::{Bytes, BytesMut};
use futures::{prelude::*, try_ready};
use guest_types::Protocol;
use crate::error::Result;
use std::net::{IpAddr, SocketAddr};
use std::io::{Error, ErrorKind};
use tokio::prelude::*;
use tokio::codec::length_delimited::*;
use tokio::codec::*;
use tokio::net::tcp::TcpStream;
use tokio::net::udp::{UdpFramed, UdpSocket};
use tokio_tls::TlsStream;
use tokio::await;

/// Wrapper for any kind of DNS message stream.
pub enum FramedStream {
    Udp(UdpFramed<BytesCodec>),
    Tcp((Framed<TcpStream, LengthDelimitedCodec>, SocketAddr)),
    Tls(
        (
            Framed<TlsStream<TcpStream>, LengthDelimitedCodec>,
            SocketAddr,
        ),
    ),
}

impl FramedStream {
    /// Returns the peer address of the stream (if connected).
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            FramedStream::Udp(ref _inner) => None,
            FramedStream::Tcp(ref inner) => Some(inner.1),
            FramedStream::Tls(ref inner) => Some(inner.1),
        }
    }

    /// Returns the local address of the stream (if bound).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            FramedStream::Udp(ref inner) => inner.get_ref().local_addr().ok(),
            FramedStream::Tcp(ref inner) => inner.0.get_ref().local_addr().ok(),
            FramedStream::Tls(ref inner) => inner.0.get_ref().get_ref().get_ref().local_addr().ok(),
        }
    }

    /// Returns the stream protocol.
    pub fn protocol(&self) -> Protocol {
        match self {
            FramedStream::Udp(..) => Protocol::Udp,
            FramedStream::Tcp(..) => Protocol::Tcp,
            FramedStream::Tls(..) => Protocol::Tls,
        }
    }
}

impl Stream for FramedStream {
    type Item = (BytesMut, SocketAddr);
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self {
            FramedStream::Udp(ref mut inner) => inner.poll(),
            FramedStream::Tcp(ref mut inner) => {
                let r = try_ready!(inner.0.poll());
                Ok(Async::Ready(r.map(|r| (r, inner.1))))
            }
            FramedStream::Tls(ref mut inner) => {
                let r = try_ready!(inner.0.poll());
                Ok(Async::Ready(r.map(|r| (r, inner.1))))
            }
        }
    }
}

impl Sink for FramedStream {
    type SinkItem = (Bytes, SocketAddr);
    type SinkError = Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        let (msg, peer_addr) = item;
        match self {
            FramedStream::Udp(ref mut inner) => inner.start_send((msg, peer_addr)),
            FramedStream::Tcp(ref mut inner) => {
                inner.0.start_send(msg).map(|r| r.map(|i| (i, peer_addr)))
            }
            FramedStream::Tls(ref mut inner) => {
                inner.0.start_send(msg).map(|r| r.map(|i| (i, peer_addr)))
            }
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        match self {
            FramedStream::Udp(ref mut inner) => inner.poll_complete(),
            FramedStream::Tcp(ref mut inner) => inner.0.poll_complete(),
            FramedStream::Tls(ref mut inner) => inner.0.poll_complete(),
        }
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        match self {
            FramedStream::Udp(ref mut inner) => inner.close(),
            FramedStream::Tcp(ref mut inner) => inner.0.close(),
            FramedStream::Tls(ref mut inner) => inner.0.close(),
        }
    }
}

impl From<UdpSocket> for FramedStream {
    fn from(s: UdpSocket) -> FramedStream {
        FramedStream::Udp(UdpFramed::new(s, BytesCodec::new()))
    }
}

impl From<TcpStream> for FramedStream {
    fn from(s: TcpStream) -> FramedStream {
        let codec = Builder::new().length_field_length(2).new_codec();
        let peer = s.peer_addr().expect("connected socket");
        FramedStream::Tcp((Framed::new(s, codec), peer))
    }
}

impl From<TlsStream<TcpStream>> for FramedStream {
    fn from(s: TlsStream<TcpStream>) -> FramedStream {
        let codec = Builder::new().length_field_length(2).new_codec();
        let peer = s.get_ref().get_ref().peer_addr().expect("connected socket");
        FramedStream::Tls((Framed::new(s, codec), peer))
    }
}

impl From<(TcpStream, SocketAddr)> for FramedStream {
    fn from(v: (TcpStream, SocketAddr)) -> FramedStream {
        let codec = Builder::new().length_field_length(2).new_codec();
        FramedStream::Tcp((Framed::new(v.0, codec), v.1))
    }
}

impl From<(TlsStream<TcpStream>, SocketAddr)> for FramedStream {
    fn from(v: (TlsStream<TcpStream>, SocketAddr)) -> FramedStream {
        let codec = Builder::new().length_field_length(2).new_codec();
        FramedStream::Tls((Framed::new(v.0, codec), v.1))
    }
}

/// Creates FramedStream with [Proxy Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) preface.
pub async fn read_proxy_preface<T>(stream: T) -> Result<(T, SocketAddr, SocketAddr)> where T: AsyncRead + AsyncWrite + Unpin {
    // Proxy protocol version 1 (PROXY ... \r\n) 
    // 2.1. Human-readable header format (Version 1)
    let mut lines = Framed::new(stream, LinesCodec::new_with_max_length(108));
    let (peer_addr, local_addr) = match await!(lines.next()) {
        Some(Ok(line)) => {
            // Parse header
            let mut it = line.split(' ');
            if it.next() != Some("PROXY") {
                return Err(ErrorKind::InvalidData.into());
            }
            // Skip address family
            it.next();
            // Parse address pair
            let peer_addr: IpAddr = it.next().ok_or(ErrorKind::InvalidData)?.parse()?;
            let local_addr: IpAddr = it.next().ok_or(ErrorKind::InvalidData)?.parse()?;
            // Parse port pair
            let peer_port: u16 = it.next().ok_or(ErrorKind::InvalidData)?.parse()?;
            let local_port: u16 = it.next().ok_or(ErrorKind::InvalidData)?.parse()?;
            (SocketAddr::new(peer_addr, peer_port), SocketAddr::new(local_addr, local_port))

        },
        _ => return Err(ErrorKind::InvalidData.into()),
    };

    Ok((lines.into_inner(), peer_addr, local_addr))
}
