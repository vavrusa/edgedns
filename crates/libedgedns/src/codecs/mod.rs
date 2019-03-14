use bytes::{Bytes, BytesMut};
use futures::{prelude::*, try_ready};
use guest_types::Protocol;
use std::net::SocketAddr;
use tokio::codec::length_delimited::*;
use tokio::codec::*;
use tokio::net::tcp::TcpStream;
use tokio::net::udp::{UdpFramed, UdpSocket};
use tokio_tls::TlsStream;

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
    type Error = std::io::Error;

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
    type SinkError = std::io::Error;

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
