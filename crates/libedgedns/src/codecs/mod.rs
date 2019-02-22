use bytes::{Bytes, BytesMut};
use futures::prelude::*;
use tokio::codec::length_delimited::*;
use tokio::codec::*;
use tokio::net::tcp::TcpStream;
use tokio::net::udp::{UdpFramed, UdpSocket};
use tokio_tls::TlsStream;

pub fn tcp_framed_transport(io: TcpStream) -> FramedStream {
    let codec = Builder::new().length_field_length(2).new_codec();
    FramedStream::Tcp(Framed::new(io, codec))
}

pub fn tls_framed_transport(io: TlsStream<TcpStream>) -> FramedStream {
    let codec = Builder::new().length_field_length(2).new_codec();
    FramedStream::Tls(Framed::new(io, codec))
}

pub fn udp_framed_transport(io: UdpSocket) -> UdpFramed<BytesCodec> {
    UdpFramed::new(io, BytesCodec::new())
}

/// Wrapper for any kind of DNS message stream.
pub enum FramedStream {
    Tcp(Framed<TcpStream, LengthDelimitedCodec>),
    Tls(Framed<TlsStream<TcpStream>, LengthDelimitedCodec>),
}

impl Stream for FramedStream {
    type Item = BytesMut;
    type Error = std::io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self {
            FramedStream::Tcp(ref mut inner) => inner.poll(),
            FramedStream::Tls(ref mut inner) => inner.poll(),
        }
    }
}

impl Sink for FramedStream {
    type SinkItem = Bytes;
    type SinkError = std::io::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        match self {
            FramedStream::Tcp(ref mut inner) => inner.start_send(item),
            FramedStream::Tls(ref mut inner) => inner.start_send(item),
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        match self {
            FramedStream::Tcp(ref mut inner) => inner.poll_complete(),
            FramedStream::Tls(ref mut inner) => inner.poll_complete(),
        }
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        match self {
            FramedStream::Tcp(ref mut inner) => inner.close(),
            FramedStream::Tls(ref mut inner) => inner.close(),
        }
    }
}
