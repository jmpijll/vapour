//! Raw IP decoder shared by the native app capture path.
use std::net::{Ipv4Addr,Ipv6Addr};
pub struct PacketInfo {
    pub version: u8,
    pub protocol: u8,
    pub src: String,
    pub sport: u16,
    pub dst: String,
    pub dport: u16,
    pub flags: u8,
    pub payload_bytes: usize,
    pub tcp_sequence: Option<u32>,
    pub tcp_acknowledgment: Option<u32>,
}
pub fn parse_packet(packet: &[u8]) -> Option<PacketInfo> {
    if packet.is_empty() {
        return None;
    }
    let version = packet[0] >> 4;
    let (version, protocol, src, dst, transport_start, end) = match version {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let header_len = (packet[0] & 0x0f) as usize * 4;
            let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            let fragments = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff;
            if header_len < 20 || total_len < header_len || total_len > packet.len() || fragments != 0
            {
                return None;
            }
            (
                4,
                packet[9],
                Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).to_string(),
                Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).to_string(),
                header_len,
                total_len,
            )
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            let total_len = 40 + payload_len;
            if total_len > packet.len() {
                return None;
            }
            let mut src_bytes = [0_u8; 16];
            let mut dst_bytes = [0_u8; 16];
            src_bytes.copy_from_slice(&packet[8..24]);
            dst_bytes.copy_from_slice(&packet[24..40]);
            let mut next = packet[6];
            let mut position = 40;
            for _ in 0..8 {
                if !matches!(next, 0 | 43 | 60 | 51) {
                    break;
                }
                if position + 2 > total_len {
                    return None;
                }
                let extension_len = if next == 51 {
                    (packet[position + 1] as usize + 2) * 4
                } else {
                    (packet[position + 1] as usize + 1) * 8
                };
                if extension_len < 8 || position + extension_len > total_len {
                    return None;
                }
                next = packet[position];
                position += extension_len;
            }
            if next == 44 {
                return None;
            }
            (
                6,
                next,
                Ipv6Addr::from(src_bytes).to_string(),
                Ipv6Addr::from(dst_bytes).to_string(),
                position,
                total_len,
            )
        }
        _ => return None,
    };
    if protocol != 6 && protocol != 17 {
        return None;
    }
    let minimum_transport = if protocol == 6 { 20 } else { 8 };
    if transport_start + minimum_transport > end {
        return None;
    }
    let sport = u16::from_be_bytes([packet[transport_start], packet[transport_start + 1]]);
    let dport = u16::from_be_bytes([packet[transport_start + 2], packet[transport_start + 3]]);
    let (flags, payload_bytes) = if protocol == 6 {
        let header_len = (packet[transport_start + 12] >> 4) as usize * 4;
        if header_len < 20 || transport_start + header_len > end {
            return None;
        }
        (
            packet[transport_start + 13],
            end - transport_start - header_len,
        )
    } else {
        let udp_len = u16::from_be_bytes([packet[transport_start + 4], packet[transport_start + 5]])
            as usize;
        if udp_len < 8 || transport_start + udp_len != end {
            return None;
        }
        (0, udp_len - 8)
    };
    Some(PacketInfo {
        version,
        protocol,
        src,
        sport,
        dst,
        dport,
        flags,
        payload_bytes,
        tcp_sequence: (protocol == 6).then(|| u32::from_be_bytes(packet[transport_start + 4..transport_start + 8].try_into().unwrap())),
        tcp_acknowledgment: (protocol == 6).then(|| u32::from_be_bytes(packet[transport_start + 8..transport_start + 12].try_into().unwrap())),
    })
}

#[cfg(test)] mod tests {use super::*;
    #[test]
    fn parses_raw_ipv4_tcp_syn_ack() {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(40_u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[127, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[127, 0, 0, 1]);
        packet[20..22].copy_from_slice(&(12345_u16).to_be_bytes());
        packet[22..24].copy_from_slice(&(443_u16).to_be_bytes());
        packet[24..28].copy_from_slice(&u32::MAX.to_be_bytes());
        packet[28..32].copy_from_slice(&0x80000001_u32.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x12;
        let info = parse_packet(&packet).expect("TCP packet");
        assert_eq!(info.protocol, 6);
        assert_eq!(info.sport, 12345);
        assert_eq!(info.dport, 443);
        assert_eq!(info.flags, 0x12);
        assert_eq!(info.tcp_sequence, Some(u32::MAX));
        assert_eq!(info.tcp_acknowledgment, Some(0x80000001));
    }

    #[test]
    fn parses_raw_ipv6_udp_payload() {
        let payload = b"probe";
        let mut packet = vec![0_u8; 40 + 8 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[6] = 17;
        packet[8] = 0xfd;
        packet[24] = 0xfd;
        packet[40..42].copy_from_slice(&(1000_u16).to_be_bytes());
        packet[42..44].copy_from_slice(&(2000_u16).to_be_bytes());
        packet[44..46].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[48..].copy_from_slice(payload);
        let info = parse_packet(&packet).expect("UDP packet");
        assert_eq!(info.version, 6);
        assert_eq!(info.protocol, 17);
        assert_eq!(info.payload_bytes, payload.len());
        assert_eq!(info.tcp_sequence, None);
        assert_eq!(info.tcp_acknowledgment, None);
    }

}
