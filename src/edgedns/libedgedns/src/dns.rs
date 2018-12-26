//! Helpers for parsing DNS packets, modifying properties, and building
//! common responses.

use dnssector::ParsedPacket;
use crate::errors::*;
use failure;
use rand::random;
use std::fmt;
use std::io::Write;
use std::net::SocketAddr;
use log::{info, warn};

use super::{DNS_UDP_NOEDNS0_MAX_SIZE, DNS_QUERY_MIN_SIZE, DNS_RESPONSE_MIN_SIZE};

pub const DNS_CLASS_CH: u16 = 3;
pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_HEADER_SIZE: usize = 12;
pub const DNS_MAX_HOSTNAME_LEN: usize = 256;
pub const DNS_MAX_PACKET_SIZE: usize = 65_535;
pub const DNS_OFFSET_EDNS_DO: usize = 6;
pub const DNS_OFFSET_EDNS_PAYLOAD_SIZE: usize = 2;
pub const DNS_OFFSET_EDNS_TYPE: usize = 0;
pub const DNS_OFFSET_QUESTION: usize = DNS_HEADER_SIZE;
pub const DNS_QTYPE_PLUS_QCLASS_LEN: usize = 4;
pub const DNS_RCODE_NOERROR: u8 = 0;
pub const DNS_RCODE_NXDOMAIN: u8 = 3;
pub const DNS_RCODE_REFUSED: u8 = 5;
pub const DNS_RCODE_SERVFAIL: u8 = 2;
pub const DNS_TYPE_ANY: u16 = 255;
pub const DNS_TYPE_HINFO: u16 = 13;
pub const DNS_TYPE_OPT: u16 = 41;
pub const DNS_TYPE_SOA: u16 = 6;
pub const DNS_TYPE_TXT: u16 = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedQuestion {
    pub qname_lc: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
    pub dnssec: bool,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct NormalizedQuestionKey {
    pub qname_lc: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
    pub dnssec: bool,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct UpstreamQuestion {
    pub qname_lc: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
    pub local_port: u16,
    pub tid: u16,
    pub server_addr: SocketAddr,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct LocalUpstreamQuestion {
    pub qname_lc: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
    pub dnssec: bool,
    pub custom_hash: (u64, u64),
    pub bypass_cache: bool,
}

impl NormalizedQuestionKey {
    pub fn from_normalized_question(
        normalized_question: &NormalizedQuestion,
    ) -> NormalizedQuestionKey {
        NormalizedQuestionKey {
            qname_lc: normalized_question.qname_lc.clone(),
            qtype: normalized_question.qtype,
            qclass: normalized_question.qclass,
            dnssec: normalized_question.dnssec,
        }
    }
}

impl UpstreamQuestion {
    pub fn from_packet(
        packet: &[u8],
        local_port: u16,
        server_addr: &SocketAddr,
    ) -> Result<UpstreamQuestion, DNSError> {
        if packet.len() < DNS_RESPONSE_MIN_SIZE {
            return Err(DNSError::InvalidPacket);
        }
        let question_rr = question(packet).map_err(|_| DNSError::InvalidPacket)?;
        let upstream_question = UpstreamQuestion {
            qname_lc: qname_lc(question_rr.qname),
            qtype: question_rr.qtype,
            qclass: question_rr.qclass,
            local_port,
            tid: tid(packet),
            server_addr: *server_addr,
        };
        Ok(upstream_question)
    }
}

#[inline]
pub fn tid(packet: &[u8]) -> u16 {
    ((u16::from(packet[0])) << 8) | u16::from(packet[1])
}

#[inline]
pub fn set_tid(packet: &mut [u8], value: u16) {
    packet[0] = (value >> 8) as u8;
    packet[1] = value as u8;
}

#[inline]
pub fn flags(packet: &[u8]) -> u16 {
    ((u16::from(packet[2])) << 8) | u16::from(packet[3])
}

#[allow(dead_code)]
#[inline]
pub fn rd(packet: &[u8]) -> bool {
    packet[2] & 0x1 != 0
}

#[inline]
pub fn set_rd(packet: &mut [u8], state: bool) {
    packet[2] |= state as u8;
}

#[allow(dead_code)]
#[inline]
pub fn tc(packet: &[u8]) -> bool {
    packet[2] & 0x2 != 0
}

#[inline]
pub fn set_tc(packet: &mut [u8], state: bool) {
    packet[2] |= 0x2 * (state as u8);
}

#[allow(dead_code)]
#[inline]
pub fn aa(packet: &[u8]) -> bool {
    packet[2] & 0x4 != 0
}

#[inline]
pub fn set_aa(packet: &mut [u8], state: bool) {
    packet[2] |= 0x4 * (state as u8);
}

#[allow(dead_code)]
#[inline]
pub fn opcode(packet: &[u8]) -> u8 {
    (packet[2] & 0x78) >> 3
}

#[inline]
pub fn qr(packet: &[u8]) -> bool {
    packet[2] & 0x80 != 0
}

#[inline]
pub fn set_qr(packet: &mut [u8], state: bool) {
    packet[2] |= 0x80 * (state as u8);
}

#[inline]
pub fn rcode(packet: &[u8]) -> u8 {
    packet[3] & 0xf
}

#[inline]
pub fn set_rcode(packet: &mut [u8], value: u8) {
    debug_assert!(value <= 0xf);
    packet[3] &= !0xf;
    packet[3] |= value & 0xf;
}

#[allow(dead_code)]
#[inline]
pub fn cd(packet: &[u8]) -> bool {
    packet[3] & 0x10 != 0
}

#[allow(dead_code)]
#[inline]
pub fn ad(packet: &[u8]) -> bool {
    packet[3] & 0x20 != 0
}

#[allow(dead_code)]
#[inline]
pub fn z(packet: &[u8]) -> bool {
    packet[3] & 0x40 != 0
}

#[allow(dead_code)]
#[inline]
pub fn ra(packet: &[u8]) -> bool {
    packet[3] & 0x80 != 0
}

#[inline]
pub fn qdcount(packet: &[u8]) -> u16 {
    (u16::from(packet[4]) << 8) | u16::from(packet[5])
}

#[inline]
pub fn set_qdcount(packet: &mut [u8], value: u16) {
    packet[4] = (value >> 8) as u8;
    packet[5] = value as u8;
}

#[inline]
pub fn ancount(packet: &[u8]) -> u16 {
    (u16::from(packet[6]) << 8) | u16::from(packet[7])
}

#[inline]
pub fn set_ancount(packet: &mut [u8], value: u16) {
    packet[6] = (value >> 8) as u8;
    packet[7] = value as u8;
}

#[inline]
pub fn nscount(packet: &[u8]) -> u16 {
    (u16::from(packet[8]) << 8) | u16::from(packet[9])
}

#[allow(dead_code)]
#[inline]
pub fn set_nscount(packet: &mut [u8], value: u16) {
    packet[8] = (value >> 8) as u8;
    packet[9] = value as u8;
}

#[inline]
pub fn arcount(packet: &[u8]) -> u16 {
    (u16::from(packet[10]) << 8) | u16::from(packet[11])
}

#[inline]
pub fn set_arcount(packet: &mut [u8], value: u16) {
    packet[10] = (value >> 8) as u8;
    packet[11] = value as u8;
}

pub fn overwrite_qname(packet: &mut [u8], qname: &[u8]) -> Result<(), failure::Error> {
    let packet_len = packet.len();
    debug_assert!(packet_len >= DNS_OFFSET_QUESTION);
    if packet_len <= DNS_OFFSET_QUESTION {
        return Err(DNSError::InvalidPacket.into());
    }
    debug_assert_eq!(qdcount(packet), 1);
    if qdcount(packet) < 1 {
        return Err(DNSError::InternalError.into());
    }
    let qname_len = qname.len();
    if packet_len <= DNS_OFFSET_QUESTION {
        return Err(DNSError::InternalError.into());
    }
    let mut to = &mut packet[DNS_OFFSET_QUESTION..];
    if to.len() <= qname_len {
        return Err(DNSError::InternalError.into());
    }
    assert_eq!(to[qname_len], 0);
    let _ = to.write(qname).unwrap();
    Ok(())
}

pub struct QuestionRR<'t> {
    qname: &'t [u8],
    qtype: u16,
    qclass: u16,
    labels_count: u16,
}

pub fn question(packet: &[u8]) -> Result<QuestionRR, &'static str> {
    let packet_len = packet.len();
    if packet_len <= DNS_OFFSET_QUESTION {
        return Err("Short packet");
    }
    let (offset, labels_count) = match skip_name(packet, DNS_OFFSET_QUESTION) {
        Ok(offset_and_labels) => offset_and_labels,
        Err(e) => return Err(e),
    };
    assert!(offset > DNS_OFFSET_QUESTION);
    let qname = &packet[DNS_OFFSET_QUESTION..offset - 1];
    if 4 > packet_len - offset {
        return Err("Short packet");
    }
    let qtype = u16::from(packet[offset]) << 8 | u16::from(packet[offset + 1]);
    let qclass = u16::from(packet[offset + 2]) << 8 | u16::from(packet[offset + 3]);
    let question_rr = QuestionRR {
        qname,
        qtype,
        qclass,
        labels_count,
    };
    Ok(question_rr)
}

fn skip_name(packet: &[u8], offset: usize) -> Result<(usize, u16), &'static str> {
    let packet_len = packet.len();
    if offset >= packet_len - 1 {
        return Err("Short packet");
    }
    let mut name_len: usize = 0;
    let mut offset = offset;
    let mut labels_count = 0u16;
    loop {
        let label_len = match packet[offset] {
            len if len & 0xc0 == 0xc0 => {
                if 2 > packet_len - offset {
                    return Err("Incomplete offset");
                }
                offset += 2;
                break;
            }
            len if len > 0x3f => return Err("Label too long"),
            len => len,
        } as usize;
        if label_len >= packet_len - offset - 1 {
            return Err("Malformed packet with an out-of-bounds name");
        }
        name_len += label_len + 1;
        if name_len > DNS_MAX_HOSTNAME_LEN {
            info!(
                "Name too long: {} bytes > {}",
                name_len, DNS_MAX_HOSTNAME_LEN
            );
            return Err("Name too long");
        }
        offset += label_len + 1;
        if label_len == 0 {
            break;
        }
        labels_count += 1;
    }
    Ok((offset, labels_count))
}

#[derive(Debug, Copy, Clone)]
pub struct EDNS0 {
    pub payload_size: u16,
    pub dnssec: bool,
}

pub fn parse_edns0_question(packet: &[u8]) -> Option<EDNS0> {
    debug_assert_eq!(qdcount(packet), 1);
    debug_assert_eq!(ancount(packet), 0);
    debug_assert_eq!(nscount(packet), 0);
    if arcount(packet) != 1 {
        return None;
    }
    let packet_len = packet.len();
    let mut offset = match skip_name(packet, DNS_OFFSET_QUESTION) {
        Ok(offset) => offset.0,
        Err(_) => return None,
    };
    if offset >= packet_len - DNS_QTYPE_PLUS_QCLASS_LEN {
        return None;
    }
    offset += DNS_QTYPE_PLUS_QCLASS_LEN;
    offset = match skip_name(packet, offset) {
        Ok(offset) => offset.0,
        Err(_) => return None,
    };
    if offset >= packet_len - DNS_OFFSET_EDNS_PAYLOAD_SIZE - 2 {
        return None;
    }
    debug_assert!(DNS_OFFSET_EDNS_PAYLOAD_SIZE > DNS_OFFSET_EDNS_TYPE);
    if packet[offset + DNS_OFFSET_EDNS_TYPE] != (DNS_TYPE_OPT >> 8) as u8
        || packet[offset + DNS_OFFSET_EDNS_TYPE + 1] != DNS_TYPE_OPT as u8
    {
        return None;
    }
    let mut payload_size = (u16::from(packet[offset + DNS_OFFSET_EDNS_PAYLOAD_SIZE]) << 8)
        | u16::from(packet[offset + DNS_OFFSET_EDNS_PAYLOAD_SIZE + 1]);
    if offset >= packet_len - DNS_OFFSET_EDNS_DO {
        return None;
    }
    let dnssec = packet[offset + DNS_OFFSET_EDNS_DO] & 0x80 == 0x80;
    if payload_size < DNS_UDP_NOEDNS0_MAX_SIZE {
        payload_size = DNS_UDP_NOEDNS0_MAX_SIZE;
    }
    Some(EDNS0 {
        payload_size,
        dnssec,
    })
}

impl fmt::Display for NormalizedQuestion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let qname_lc = &self.qname_lc;
        let qname_lc_len = qname_lc.len();
        let mut res = Vec::with_capacity(qname_lc_len);
        let mut offset: usize = 0;
        while offset < qname_lc_len {
            let label_len = qname_lc[offset] as usize;
            assert_eq!(label_len, 0);
            if label_len & 0xc0 == 0xc0 {
                res.push(b'&');
                offset += 2;
                continue;
            }
            offset += 1;
            res.extend_from_slice(&qname_lc[offset..offset + label_len]);
            res.push(b'.');
            offset += label_len;
        }
        let qname_str = String::from_utf8_lossy(&res);
        write!(f, "[{}]\t{} {}", qname_str, self.qtype, self.qclass)
    }
}

impl NormalizedQuestion {
    pub fn from_parsed_packet(
        parsed_packet: &mut ParsedPacket,
    ) -> Result<NormalizedQuestion, failure::Error> {
        let (qname_lc, qtype, qclass) = match parsed_packet.question_raw() {
            None => return Err(DNSError::InvalidPacket.into()),
            Some((qname, qtype, qclass)) => (qname_lc(qname), qtype, qclass),
        };
        Ok(NormalizedQuestion {
            qname_lc,
            qtype,
            qclass,
            dnssec: parsed_packet.dnssec(),
        })
    }

    pub fn key(&self) -> NormalizedQuestionKey {
        let dnssec = if self.qname_lc.is_empty() {
            true
        } else {
            self.dnssec
        };
        NormalizedQuestionKey {
            dnssec,
            qname_lc: self.qname_lc.clone(),
            qtype: self.qtype,
            qclass: self.qclass,
        }
    }
}

pub fn strip_trailing_zero(qname: &[u8]) -> &[u8] {
    let qname_len = qname.len();
    if qname_len > 0 && qname[qname_len - 1] == 0 {
        &qname[..qname_len - 1]
    } else {
        qname
    }
}

pub fn qname_lc(qname: &[u8]) -> Vec<u8> {
    let qname_len = qname.len();
    let mut res = vec![0u8; qname_len];
    let mut offset: usize = 0;
    while offset < qname_len {
        res[offset] = qname[offset];
        let label_len = qname[offset] as usize;
        assert_ne!(label_len, 0);
        if label_len & 0xc0 == 0xc0 {
            offset += 2;
            continue;
        }
        offset += 1;
        for i in 0..label_len {
            res[offset + i] = match qname[offset + i] {
                c @ 0x41...0x5a => c | 0x20,
                c => c,
            };
        }
        offset += label_len;
    }
    res
}

pub fn qname_shift(qname: &[u8]) -> Option<&[u8]> {
    let qname_len = qname.len();
    if qname_len < 2 {
        return None;
    }
    let label_len = qname[0];
    if label_len == 0 || label_len & 0xc0 == 0xc0 || 2 + label_len as usize > qname_len {
        return None;
    }
    Some(&qname[1 + label_len as usize..])
}

pub fn min_ttl(
    packet: &[u8],
    min_ttl: u32,
    max_ttl: u32,
    failure_ttl: u32,
) -> Result<u32, &'static str> {
    if qdcount(packet) != 1 {
        return Err("Unsupported number of questions");
    }
    let packet_len = packet.len();
    if packet_len <= DNS_OFFSET_QUESTION {
        return Err("Short packet");
    }
    let mut offset = match skip_name(packet, DNS_OFFSET_QUESTION) {
        Ok(offset) => offset.0,
        Err(e) => return Err(e),
    };
    assert!(offset > DNS_OFFSET_QUESTION);
    if 4 > packet_len - offset {
        return Err("Short packet");
    }
    let qclass = u16::from(packet[offset + 2]) << 8 | u16::from(packet[offset + 3]);
    if qclass != DNS_CLASS_IN {
        return Err("Unsupported query class");
    }
    offset += 4;
    let ancount = ancount(packet);
    let nscount = nscount(packet);
    let arcount = arcount(packet);
    let rrcount = ancount + nscount + arcount;
    let mut found_min_ttl = if rrcount > 0 { max_ttl } else { failure_ttl };
    for _ in 0..rrcount {
        offset = match skip_name(packet, offset) {
            Ok(offset) => offset.0,
            Err(e) => return Err(e),
        };
        if 10 > packet_len - offset {
            return Err("Short packet");
        }
        let qtype = u16::from(packet[offset]) << 8 | u16::from(packet[offset + 1]);
        let qclass = u16::from(packet[offset + 2]) << 8 | u16::from(packet[offset + 3]);
        let ttl = u32::from(packet[offset + 4]) << 24 | u32::from(packet[offset + 5]) << 16
            | u32::from(packet[offset + 6]) << 8 | u32::from(packet[offset + 7]);
        let rdlen = (u16::from(packet[offset + 8]) << 8 | u16::from(packet[offset + 9])) as usize;
        offset += 10;
        if qtype != DNS_TYPE_OPT {
            if qclass != DNS_CLASS_IN {
                warn!("Unexpected rdata class: {}", qclass);
            }
            if ttl < found_min_ttl {
                found_min_ttl = ttl;
            }
        }
        if rdlen > packet_len - offset {
            return Err("Record length would exceed packet length");
        }
        offset += rdlen;
    }
    if found_min_ttl < min_ttl {
        found_min_ttl = min_ttl;
    }
    if offset != packet_len {
        return Err("Garbage after packet");
    }
    Ok(found_min_ttl)
}

pub fn set_ttl(packet: &mut [u8], ttl: u32) -> Result<(), &'static str> {
    if qdcount(packet) != 1 {
        return Err("Unsupported number of questions");
    }
    let packet_len = packet.len();
    if packet_len <= DNS_OFFSET_QUESTION {
        return Err("Short packet");
    }
    let mut offset = match skip_name(packet, DNS_OFFSET_QUESTION) {
        Ok(offset) => offset.0,
        Err(e) => return Err(e),
    };
    assert!(offset > DNS_OFFSET_QUESTION);
    if 4 > packet_len - offset {
        return Err("Short packet");
    }
    let qclass = u16::from(packet[offset + 2]) << 8 | u16::from(packet[offset + 3]);
    if qclass != DNS_CLASS_IN {
        return Err("Unsupported query class");
    }
    offset += 4;
    let ancount = ancount(packet);
    let nscount = nscount(packet);
    let arcount = arcount(packet);
    for _ in 0..(ancount + nscount + arcount) {
        offset = match skip_name(packet, offset) {
            Ok(offset) => offset.0,
            Err(e) => return Err(e),
        };
        if 10 > packet_len - offset {
            return Err("Short packet");
        }
        let qtype = u16::from(packet[offset]) << 8 | u16::from(packet[offset + 1]);
        let qclass = u16::from(packet[offset + 2]) << 8 | u16::from(packet[offset + 3]);
        if qtype != DNS_TYPE_OPT || qclass != DNS_CLASS_IN {
            packet[offset + 4] = (ttl >> 24) as u8;
            packet[offset + 5] = (ttl >> 16) as u8;
            packet[offset + 6] = (ttl >> 8) as u8;
            packet[offset + 7] = ttl as u8;
        }
        let rdlen = (u16::from(packet[offset + 8]) << 8 | u16::from(packet[offset + 9])) as usize;
        offset += 10;
        if rdlen > packet_len - offset {
            return Err("Record length would exceed packet length");
        }
        offset += rdlen;
    }
    if offset != packet_len {
        return Err("Garbage after packet");
    }
    Ok(())
}

pub fn build_tc_packet(
    qname: &[u8],
    qtype: u16,
    qclass: u16,
    tid: u16,
) -> Result<Vec<u8>, failure::Error> {
    let capacity = DNS_HEADER_SIZE + qname.len() + 1;
    let mut packet = Vec::with_capacity(capacity);
    packet.extend_from_slice(&[0u8; DNS_HEADER_SIZE]);
    set_tid(&mut packet, tid);
    set_aa(&mut packet, true);
    set_qr(&mut packet, true);
    set_tc(&mut packet, true);
    set_qdcount(&mut packet, 1);
    packet.extend_from_slice(qname);
    packet.push(0);

    packet.push((qtype >> 8) as u8);
    packet.push(qtype as u8);
    packet.push((qclass >> 8) as u8);
    packet.push(qclass as u8);
    Ok(packet)
}

pub fn build_servfail_packet(
    qname: &[u8],
    qtype: u16,
    qclass: u16,
    tid: u16,
) -> Result<Vec<u8>, failure::Error> {
    let capacity = DNS_HEADER_SIZE + qname.len() + 1;
    let mut packet = Vec::with_capacity(capacity);
    packet.extend_from_slice(&[0u8; DNS_HEADER_SIZE]);
    set_rcode(&mut packet, DNS_RCODE_SERVFAIL);
    set_tid(&mut packet, tid);
    set_aa(&mut packet, true);
    set_qr(&mut packet, true);
    set_qdcount(&mut packet, 1);
    packet.extend_from_slice(qname);
    packet.push(0);

    packet.push((qtype >> 8) as u8);
    packet.push(qtype as u8);
    packet.push((qclass >> 8) as u8);
    packet.push(qclass as u8);
    Ok(packet)
}

pub fn build_refused_packet(
    qname: &[u8],
    qtype: u16,
    qclass: u16,
    tid: u16,
) -> Result<Vec<u8>, failure::Error> {
    let capacity = DNS_HEADER_SIZE + qname.len() + 1;
    let mut packet = Vec::with_capacity(capacity);
    packet.extend_from_slice(&[0u8; DNS_HEADER_SIZE]);
    set_rcode(&mut packet, DNS_RCODE_REFUSED);
    set_tid(&mut packet, tid);
    set_aa(&mut packet, true);
    set_qr(&mut packet, true);
    set_qdcount(&mut packet, 1);
    packet.extend_from_slice(qname);
    packet.push(0);

    packet.push((qtype >> 8) as u8);
    packet.push(qtype as u8);
    packet.push((qclass >> 8) as u8);
    packet.push(qclass as u8);
    Ok(packet)
}

pub fn build_nxdomain_packet(
    qname: &[u8],
    qtype: u16,
    qclass: u16,
) -> Result<Vec<u8>, failure::Error> {
    let capacity = DNS_HEADER_SIZE + qname.len() + 1;
    let mut packet = Vec::with_capacity(capacity);
    packet.extend_from_slice(&[0u8; DNS_HEADER_SIZE]);
    set_rcode(&mut packet, DNS_RCODE_NXDOMAIN);
    set_aa(&mut packet, true);
    set_qr(&mut packet, true);
    set_qdcount(&mut packet, 1);
    packet.extend_from_slice(qname);
    packet.push(0);

    packet.push((qtype >> 8) as u8);
    packet.push(qtype as u8);
    packet.push((qclass >> 8) as u8);
    packet.push(qclass as u8);
    Ok(packet)
}

pub fn build_any_packet(
    qname: &[u8],
    qtype: u16,
    qclass: u16,
    tid: u16,
    ttl: u32,
) -> Result<Vec<u8>, failure::Error> {
    let hinfo_cpu = b"draft-ietf-dnsop-refuse-any";
    let hinfo_rdata = b"";
    let rdata_len = 1 + hinfo_cpu.len() + 1 + hinfo_rdata.len();
    let capacity = DNS_HEADER_SIZE + qname.len() + 1;
    let mut packet = Vec::with_capacity(capacity);
    packet.extend_from_slice(&[0u8; DNS_HEADER_SIZE]);
    set_tid(&mut packet, tid);
    set_aa(&mut packet, true);
    set_qr(&mut packet, true);
    set_qdcount(&mut packet, 1);
    set_ancount(&mut packet, 1);
    packet.extend_from_slice(qname);
    packet.push(0);

    packet.push((qtype >> 8) as u8);
    packet.push(qtype as u8);
    packet.push((qclass >> 8) as u8);
    packet.push(qclass as u8);

    packet.push(0xc0 + (DNS_HEADER_SIZE >> 8) as u8);
    packet.push(DNS_HEADER_SIZE as u8);

    packet.push((DNS_TYPE_HINFO >> 8) as u8);
    packet.push(DNS_TYPE_HINFO as u8);

    packet.push((qclass >> 8) as u8);
    packet.push(qclass as u8);

    packet.push((ttl >> 24) as u8);
    packet.push((ttl >> 16) as u8);
    packet.push((ttl >> 8) as u8);
    packet.push(ttl as u8);

    packet.push((rdata_len >> 8) as u8);
    packet.push(rdata_len as u8);

    packet.push(hinfo_cpu.len() as u8);
    packet.extend_from_slice(hinfo_cpu);
    packet.push(hinfo_rdata.len() as u8);
    packet.extend_from_slice(hinfo_rdata);

    Ok(packet)
}

pub fn build_version_packet(
    qname: &[u8],
    qtype: u16,
    qclass: u16,
    tid: u16,
    ttl: u32,
) -> Result<Vec<u8>, failure::Error> {
    let txt = b"EdgeDNS";
    let rdata_len = 1 + txt.len();
    let capacity = DNS_HEADER_SIZE + qname.len() + 1;
    let mut packet = Vec::with_capacity(capacity);
    packet.extend_from_slice(&[0u8; DNS_HEADER_SIZE]);
    set_tid(&mut packet, tid);
    set_aa(&mut packet, true);
    set_qr(&mut packet, true);
    set_qdcount(&mut packet, 1);
    set_ancount(&mut packet, 1);
    packet.extend_from_slice(qname);
    packet.push(0);

    debug_assert_eq!(qtype, DNS_TYPE_TXT);
    debug_assert_eq!(qclass, DNS_CLASS_CH);
    packet.push((DNS_TYPE_TXT >> 8) as u8);
    packet.push(DNS_TYPE_TXT as u8);
    packet.push((DNS_CLASS_CH >> 8) as u8);
    packet.push(DNS_CLASS_CH as u8);

    packet.push(0xc0 + (DNS_HEADER_SIZE >> 8) as u8);
    packet.push(DNS_HEADER_SIZE as u8);

    packet.push((DNS_TYPE_TXT >> 8) as u8);
    packet.push(DNS_TYPE_TXT as u8);
    packet.push((DNS_CLASS_CH >> 8) as u8);
    packet.push(DNS_CLASS_CH as u8);

    packet.push((ttl >> 24) as u8);
    packet.push((ttl >> 16) as u8);
    packet.push((ttl >> 8) as u8);
    packet.push(ttl as u8);

    packet.push((rdata_len >> 8) as u8);
    packet.push(rdata_len as u8);

    packet.push(txt.len() as u8);
    packet.extend_from_slice(txt);

    Ok(packet)
}

pub fn build_probe_packet(qname: &[u8]) -> Result<Vec<u8>, failure::Error> {
    let capacity = DNS_HEADER_SIZE + qname.len() + 1;
    let mut packet = Vec::with_capacity(capacity);
    packet.extend_from_slice(&[0u8; DNS_HEADER_SIZE]);
    set_tid(&mut packet, random());
    set_rd(&mut packet, true);
    set_qdcount(&mut packet, 1);
    packet.extend_from_slice(qname);
    let qtype = DNS_TYPE_SOA;
    let qclass = DNS_CLASS_IN;
    packet.push((qtype >> 8) as u8);
    packet.push(qtype as u8);
    packet.push((qclass >> 8) as u8);
    packet.push(qclass as u8);
    Ok(packet)
}

pub fn build_query_packet(
    normalized_question: &NormalizedQuestion,
    tid: u16,
    force_dnssec: bool,
) -> Result<Vec<u8>, DNSError> {
    let mut qname = normalized_question.qname_lc.clone();
    let qname_len = qname.len();
    let force_dnssec = if qname_len == 0 { true } else { force_dnssec };
    if force_dnssec || normalized_question.dnssec {
        if qname_len > 0 {
            qname[qname_len - 1] &= !0x20;
        }
    }
    let capacity = DNS_HEADER_SIZE + qname_len + 1 + 15;
    let mut packet = Vec::with_capacity(capacity);
    packet.extend_from_slice(&[0u8; DNS_HEADER_SIZE]);
    set_tid(&mut packet, tid);
    set_rd(&mut packet, true);
    set_qdcount(&mut packet, 1);
    set_arcount(&mut packet, 1);
    packet.extend_from_slice(&qname);
    packet.push(0);

    packet.push((normalized_question.qtype >> 8) as u8);
    packet.push(normalized_question.qtype as u8);
    packet.push((normalized_question.qclass >> 8) as u8);
    packet.push(normalized_question.qclass as u8);

    packet.push(0); // EDNS name
    packet.push((DNS_TYPE_OPT >> 8) as u8);
    packet.push(DNS_TYPE_OPT as u8);
    packet.push((DNS_MAX_PACKET_SIZE >> 8) as u8);
    packet.push(DNS_MAX_PACKET_SIZE as u8);

    let edns_rcode_rdlen = if force_dnssec || normalized_question.dnssec {
        [0u8, 0u8, 0x80u8, 0u8, 0u8, 0u8]
    } else {
        [0u8; 6]
    };
    packet.extend_from_slice(&edns_rcode_rdlen); // EDNS rcode + rdlen
    Ok(packet)
}

pub fn qname_encode(name: &str) -> Result<Vec<u8>, &'static str> {
    let mut encoded = Vec::with_capacity(name.len() + 1);
    let mut final_dot = false;
    for part in name.split('.') {
        if final_dot {
            return Err("Invalid name: unexpected dots");
        }
        let len = part.len();
        if len > 0x3f {
            return Err("Invalid name: label too long (> 63 characters)");
        } else if len == 0 {
            if name.len() == 1 {
                break;
            }
            final_dot = true;
        }
        encoded.push(len as u8);
        encoded.extend_from_slice(part.as_bytes());
    }
    if !final_dot {
        encoded.push(0);
    }
    Ok(encoded)
}
