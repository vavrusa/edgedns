use tokio::codec::length_delimited::*;
use tokio::codec::*;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::tcp::TcpStream;
use tokio::net::udp::{UdpSocket, UdpFramed};

#[allow(dead_code)]
pub type FramedStream = Framed<TcpStream, LengthDelimitedCodec>;

pub fn tcp_framed_transport<T: AsyncRead + AsyncWrite>(io: T) -> Framed<T, LengthDelimitedCodec> {
    let codec = Builder::new().length_field_length(2).new_codec();

    Framed::new(io, codec)
}

pub fn udp_framed_transport(io: UdpSocket) -> UdpFramed<BytesCodec> {
    UdpFramed::new(io, BytesCodec::new())
}