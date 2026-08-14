//! sing `Socksaddr` stream addressing (client side of sing-mux streams).
//!
//! The full per-stream request prefix is
//! `[flags u16 BE][type u8][address][port u16 BE]` — flags 0 for TCP —
//! matching sing-mux's `EncodeStreamRequest` (protocol.go).  Socksaddr type
//! bytes: 0x01=IPv4, 0x04=IPv6, 0x03=FQDN (u8 length-prefixed).  Matches
//! `M.SocksaddrSerializer` in sagernet/sing.

use bytes::{BufMut, BytesMut};
use std::net::IpAddr;

const TYPE_IPV4: u8 = 0x01;
const TYPE_IPV6: u8 = 0x04;
const TYPE_FQDN: u8 = 0x03;

/// Encode the full TCP stream request: `[flags u16 = 0][socksaddr]`.
pub fn encode_stream_request(host: &str, port: u16) -> Vec<u8> {
    let mut out = BytesMut::new();
    // StreamRequest flags — 0 = TCP (sing-mux flagUDP is 1).
    out.put_u16(0);
    out.put_slice(&encode_address(host, port));
    out.to_vec()
}

/// Encode a destination Socksaddr (without the stream-request flags).
///
/// FQDN payloads use a 1-byte length; hosts longer than 255 bytes (invalid
/// as DNS names anyway) are clamped with a debug assertion rather than
/// silently corrupting the frame via truncation.
pub fn encode_address(host: &str, port: u16) -> Vec<u8> {
    let mut out = BytesMut::new();
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            out.put_u8(TYPE_IPV4);
            out.put_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            out.put_u8(TYPE_IPV6);
            out.put_slice(&ip.octets());
        }
        Err(_) => {
            debug_assert!(
                host.len() <= u8::MAX as usize,
                "mux address fqdn exceeds 255 bytes: {host:?}"
            );
            let len = host.len().min(u8::MAX as usize);
            out.put_u8(TYPE_FQDN);
            out.put_u8(len as u8);
            out.put_slice(&host.as_bytes()[..len]);
        }
    }
    out.put_u16(port);
    out.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn ipv4_encoding_matches_sing_layout() {
        let bytes = encode_address("10.0.2.2", 18081);
        assert_eq!(bytes, [0x01, 10, 0, 2, 2, 0x46, 0xa1]);
    }

    #[test]
    fn stream_request_tcp_flags_then_socksaddr() {
        let bytes = encode_stream_request("10.0.2.2", 18081);
        assert_eq!(bytes, [0x00, 0x00, 0x01, 10, 0, 2, 2, 0x46, 0xa1]);
    }

    #[test]
    fn ipv6_encoding() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let bytes = encode_address("2001:db8::1", 443);
        assert_eq!(bytes[0], TYPE_IPV6);
        assert_eq!(&bytes[1..17], &ip.octets());
        assert_eq!(u16::from_be_bytes([bytes[17], bytes[18]]), 443);
    }

    #[test]
    fn fqdn_encoding() {
        let bytes = encode_address("sp.mux.sing-box.arpa", 444);
        assert_eq!(bytes[0], TYPE_FQDN);
        assert_eq!(bytes[1] as usize, "sp.mux.sing-box.arpa".len());
        assert_eq!(
            &bytes[2..2 + "sp.mux.sing-box.arpa".len()],
            b"sp.mux.sing-box.arpa"
        );
        let port_off = 2 + "sp.mux.sing-box.arpa".len();
        assert_eq!(
            u16::from_be_bytes([bytes[port_off], bytes[port_off + 1]]),
            444
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_takes_ipv6_type() {
        // ::ffff:10.0.2.2 parses as an IPv6 literal and must encode as such.
        let bytes = encode_address("::ffff:10.0.2.2", 80);
        assert_eq!(bytes[0], TYPE_IPV6);
        assert_eq!(bytes.len(), 1 + 16 + 2);
    }
}
