use std::net::IpAddr;
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: u8,
}
impl Endpoint {
    /// Fail closed for fragments, IPv6 extensions and malformed/truncated headers.
    /// Pktmon's IP/port sets are unordered; enforce the directed pair here.
    pub fn matches(&self, kind: u16, bytes: &[u8]) -> bool {
        self.decode(kind, bytes).unwrap_or(false)
    }
    fn decode(&self, kind: u16, bytes: &[u8]) -> Option<bool> {
        let ip = match kind {
            3 => bytes,
            1 => {
                let mut off = 14;
                let mut ether = u16::from_be_bytes(bytes.get(12..14)?.try_into().ok()?);
                // At most two VLAN tags; unsupported encapsulations are excluded.
                for _ in 0..2 {
                    if matches!(ether, 0x8100 | 0x88a8) {
                        ether = u16::from_be_bytes(bytes.get(off + 2..off + 4)?.try_into().ok()?);
                        off += 4;
                    }
                }
                let data = bytes.get(off..)?;
                if !matches!((ether, data.first()? >> 4), (0x0800, 4) | (0x86dd, 6)) {
                    return None;
                }
                data
            }
            _ => return None,
        };
        let (src, dst, protocol, transport) = match ip.first()? >> 4 {
            4 => {
                let header = (ip[0] & 15) as usize * 4;
                if header < 20 {
                    return None;
                }
                let total = u16::from_be_bytes(ip.get(2..4)?.try_into().ok()?) as usize;
                let flags = u16::from_be_bytes(ip.get(6..8)?.try_into().ok()?);
                if flags & 0xbfff != 0 || total < header {
                    return None;
                }
                let packet = ip.get(..total)?;
                let s = std::net::Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(12..16)?).ok()?);
                let d = std::net::Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(16..20)?).ok()?);
                (
                    IpAddr::V4(s),
                    IpAddr::V4(d),
                    *packet.get(9)?,
                    packet.get(header..)?,
                )
            }
            6 => {
                let payload = u16::from_be_bytes(ip.get(4..6)?.try_into().ok()?) as usize;
                if payload == 0 {
                    return None;
                }
                let packet = ip.get(..40 + payload)?;
                let s = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
                let d = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
                (
                    IpAddr::V6(s),
                    IpAddr::V6(d),
                    *packet.get(6)?,
                    packet.get(40..)?,
                )
            }
            _ => return None,
        };
        if protocol != self.protocol {
            return None;
        }
        match protocol {
            6 => {
                let header = (*transport.get(12)? >> 4) as usize * 4;
                if header < 20 || transport.len() < header {
                    return None;
                }
            }
            17 => {
                let len = u16::from_be_bytes(transport.get(4..6)?.try_into().ok()?) as usize;
                if len < 8 || len != transport.len() {
                    return None;
                }
            }
            _ => return None,
        }
        let sp = u16::from_be_bytes(transport.get(..2)?.try_into().ok()?);
        let dp = u16::from_be_bytes(transport.get(2..4)?.try_into().ok()?);
        Some(
            (src == self.local_ip
                && dst == self.remote_ip
                && sp == self.local_port
                && dp == self.remote_port)
                || (src == self.remote_ip
                    && dst == self.local_ip
                    && sp == self.remote_port
                    && dp == self.local_port),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn target(v6: bool) -> Endpoint {
        Endpoint {
            local_ip: if v6 { "2001:db8::1" } else { "192.0.2.1" }
                .parse()
                .unwrap(),
            remote_ip: if v6 { "2001:db8::2" } else { "192.0.2.2" }
                .parse()
                .unwrap(),
            local_port: 12345,
            remote_port: 443,
            protocol: 6,
        }
    }
    fn frame(e: &Endpoint, reverse: bool) -> Vec<u8> {
        let (src, dst, sp, dp) = if reverse {
            (e.remote_ip, e.local_ip, e.remote_port, e.local_port)
        } else {
            (e.local_ip, e.remote_ip, e.local_port, e.remote_port)
        };
        let mut b = match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let mut b = vec![0; 40];
                b[0] = 0x45;
                b[2..4].copy_from_slice(&40u16.to_be_bytes());
                b[9] = e.protocol;
                b[12..16].copy_from_slice(&s.octets());
                b[16..20].copy_from_slice(&d.octets());
                b
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let mut b = vec![0; 60];
                b[0] = 0x60;
                b[4..6].copy_from_slice(&20u16.to_be_bytes());
                b[6] = e.protocol;
                b[8..24].copy_from_slice(&s.octets());
                b[24..40].copy_from_slice(&d.octets());
                b
            }
            _ => unreachable!(),
        };
        let off = b.len() - 20;
        b[off..off + 2].copy_from_slice(&sp.to_be_bytes());
        b[off + 2..off + 4].copy_from_slice(&dp.to_be_bytes());
        b[off + 12] = 0x50;
        b
    }
    #[test]
    fn exact_pair_both_directions_ipv4_ipv6() {
        for v6 in [false, true] {
            let e = target(v6);
            for rev in [false, true] {
                let b = frame(&e, rev);
                assert!(e.matches(3, &b));
                let mut eth = vec![0; 14];
                eth[12..14]
                    .copy_from_slice(&(if v6 { 0x86ddu16 } else { 0x0800u16 }).to_be_bytes());
                eth.extend(b);
                assert!(e.matches(1, &eth));
            }
        }
    }
    #[test]
    fn rejects_crossed_ports_and_other_ports() {
        for v6 in [false, true] {
            let e = target(v6);
            let mut b = frame(&e, false);
            let off = b.len() - 20;
            b[off..off + 2].copy_from_slice(&e.remote_port.to_be_bytes());
            b[off + 2..off + 4].copy_from_slice(&e.local_port.to_be_bytes());
            assert!(!e.matches(3, &b));
            b[off..off + 2].copy_from_slice(&999u16.to_be_bytes());
            assert!(!e.matches(3, &b));
        }
    }
    #[test]
    fn rejects_truncation_fragments_extensions_wrong_protocol() {
        for v6 in [false, true] {
            let e = target(v6);
            let b = frame(&e, false);
            for len in 0..b.len() {
                assert!(!e.matches(3, &b[..len]));
            }
            let mut b = b;
            if v6 {
                b[6] = 44;
            } else {
                b[6] = 0x20;
            }
            assert!(!e.matches(3, &b));
            let mut b = frame(&e, false);
            b[if v6 { 6 } else { 9 }] = 17;
            assert!(!e.matches(3, &b));
        }
    }
    #[test]
    fn udp_and_vlan_exact_pair() {
        for v6 in [false, true] {
            let mut e = target(v6);
            e.protocol = 17;
            for rev in [false, true] {
                let mut b = frame(&e, rev);
                let off = b.len() - 20;
                b.truncate(off + 8);
                b[off + 4..off + 6].copy_from_slice(&8u16.to_be_bytes());
                if v6 {
                    b[4..6].copy_from_slice(&8u16.to_be_bytes());
                } else {
                    b[2..4].copy_from_slice(&28u16.to_be_bytes());
                }
                assert!(e.matches(3, &b));
                let mut vlan = vec![0; 18];
                vlan[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
                vlan[16..18]
                    .copy_from_slice(&(if v6 { 0x86ddu16 } else { 0x0800u16 }).to_be_bytes());
                vlan.extend(&b);
                assert!(e.matches(1, &vlan));
                b[off + 4..off + 6].copy_from_slice(&9u16.to_be_bytes());
                assert!(!e.matches(3, &b));
            }
        }
    }
    #[test]
    fn rejects_wrong_address_and_tcp_header_length() {
        let e = target(false);
        let mut b = frame(&e, false);
        b[15] = 3;
        assert!(!e.matches(3, &b));
        let mut b = frame(&e, false);
        b[32] = 0xf0;
        assert!(!e.matches(3, &b));
    }
}
