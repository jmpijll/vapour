//! Pure IPv4/IPv6 DNS packet decoding and tuple rewriting.
//!
//! This module deliberately has no Windows, socket, WinDivert, or resolver
//! dependencies.  It is the packet codec used by the later transparent
//! forwarding path; interception and flow ownership stay outside this file.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Protocol {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PacketInfo {
    pub(crate) source: SocketAddr,
    pub(crate) destination: SocketAddr,
    pub(crate) protocol: Protocol,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketError {
    Truncated,
    InvalidLength,
    UnsupportedVersion,
    UnsupportedProtocol,
    UnsupportedExtension,
    Fragmented,
    FamilyMismatch,
    UnsupportedScope,
}

#[derive(Clone, Copy)]
struct PacketLayout {
    version: u8,
    ip_header_len: usize,
    transport_offset: usize,
    transport_len: usize,
    protocol: Protocol,
    source: SocketAddr,
    destination: SocketAddr,
}

pub(crate) fn decode(packet: &[u8]) -> Result<PacketInfo, PacketError> {
    let layout = parse_layout(packet)?;
    Ok(PacketInfo {
        source: layout.source,
        destination: layout.destination,
        protocol: layout.protocol,
    })
}

pub(crate) fn rewrite(
    packet: &[u8],
    source: SocketAddr,
    destination: SocketAddr,
) -> Result<Vec<u8>, PacketError> {
    let layout = parse_layout(packet)?;
    if has_nonzero_scope(source) || has_nonzero_scope(destination) {
        return Err(PacketError::UnsupportedScope);
    }
    if source.is_ipv4() != layout.source.is_ipv4()
        || destination.is_ipv4() != layout.destination.is_ipv4()
        || source.is_ipv4() != destination.is_ipv4()
    {
        return Err(PacketError::FamilyMismatch);
    }

    let mut rewritten = packet.to_vec();
    match layout.version {
        4 => {
            let source = match source.ip() {
                IpAddr::V4(address) => address.octets(),
                IpAddr::V6(_) => return Err(PacketError::FamilyMismatch),
            };
            let destination = match destination.ip() {
                IpAddr::V4(address) => address.octets(),
                IpAddr::V6(_) => return Err(PacketError::FamilyMismatch),
            };
            rewritten[12..16].copy_from_slice(&source);
            rewritten[16..20].copy_from_slice(&destination);
        }
        6 => {
            let source = match source.ip() {
                IpAddr::V6(address) => address.octets(),
                IpAddr::V4(_) => return Err(PacketError::FamilyMismatch),
            };
            let destination = match destination.ip() {
                IpAddr::V6(address) => address.octets(),
                IpAddr::V4(_) => return Err(PacketError::FamilyMismatch),
            };
            rewritten[8..24].copy_from_slice(&source);
            rewritten[24..40].copy_from_slice(&destination);
        }
        _ => return Err(PacketError::UnsupportedVersion),
    }

    let transport = layout.transport_offset;
    rewritten[transport..transport + 2].copy_from_slice(&source.port().to_be_bytes());
    rewritten[transport + 2..transport + 4].copy_from_slice(&destination.port().to_be_bytes());

    if layout.version == 4 {
        rewritten[10..12].fill(0);
        let checksum = internet_checksum(&rewritten[..layout.ip_header_len]);
        rewritten[10..12].copy_from_slice(&checksum.to_be_bytes());
    }

    let checksum_offset = match layout.protocol {
        Protocol::Udp => 6,
        Protocol::Tcp => 16,
    };
    rewritten[transport + checksum_offset..transport + checksum_offset + 2].fill(0);
    let checksum = transport_checksum(
        &rewritten,
        layout.version,
        layout.transport_offset,
        layout.transport_len,
        layout.protocol,
    );
    let checksum = if layout.protocol == Protocol::Udp && checksum == 0 {
        0xffff
    } else {
        checksum
    };
    rewritten[transport + checksum_offset..transport + checksum_offset + 2]
        .copy_from_slice(&checksum.to_be_bytes());

    Ok(rewritten)
}

fn has_nonzero_scope(address: SocketAddr) -> bool {
    match address {
        SocketAddr::V4(_) => false,
        SocketAddr::V6(address) => address.scope_id() != 0,
    }
}

fn parse_layout(packet: &[u8]) -> Result<PacketLayout, PacketError> {
    if packet.is_empty() {
        return Err(PacketError::Truncated);
    }
    match packet[0] >> 4 {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => Err(PacketError::UnsupportedVersion),
    }
}

fn parse_ipv4(packet: &[u8]) -> Result<PacketLayout, PacketError> {
    if packet.len() < 20 {
        return Err(PacketError::Truncated);
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 {
        return Err(PacketError::InvalidLength);
    }
    if packet.len() < header_len {
        return Err(PacketError::Truncated);
    }
    validate_ipv4_options(packet, header_len)?;

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len || total_len != packet.len() {
        return Err(PacketError::InvalidLength);
    }

    let flags_and_offset = u16::from_be_bytes([packet[6], packet[7]]);
    if flags_and_offset & 0x8000 != 0 {
        return Err(PacketError::Fragmented);
    }
    if flags_and_offset & 0x3fff != 0 {
        return Err(PacketError::Fragmented);
    }

    let protocol = match packet[9] {
        17 => Protocol::Udp,
        6 => Protocol::Tcp,
        _ => return Err(PacketError::UnsupportedProtocol),
    };
    let transport_len = total_len - header_len;
    validate_transport(packet, header_len, transport_len, protocol)?;

    let source = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        u16::from_be_bytes([packet[header_len], packet[header_len + 1]]),
    );
    let destination = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
        u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]),
    );
    Ok(PacketLayout {
        version: 4,
        ip_header_len: header_len,
        transport_offset: header_len,
        transport_len,
        protocol,
        source,
        destination,
    })
}

fn validate_ipv4_options(packet: &[u8], header_len: usize) -> Result<(), PacketError> {
    let mut offset = 20;
    while offset < header_len {
        let kind = packet[offset];
        match kind {
            // End of options. Remaining bytes are required to be zero padding.
            0 => {
                if packet[offset + 1..header_len].iter().any(|byte| *byte != 0) {
                    return Err(PacketError::InvalidLength);
                }
                return Ok(());
            }
            // No-op has no length byte.
            1 => offset += 1,
            // Loose and strict source-route options make the IP destination's
            // routing semantics differ from the ordinary header tuple.
            131 | 137 => return Err(PacketError::UnsupportedExtension),
            _ => {
                if offset + 1 >= header_len {
                    return Err(PacketError::InvalidLength);
                }
                let option_len = usize::from(packet[offset + 1]);
                if option_len < 2 || offset + option_len > header_len {
                    return Err(PacketError::InvalidLength);
                }
                offset += option_len;
            }
        }
    }
    Ok(())
}

fn parse_ipv6(packet: &[u8]) -> Result<PacketLayout, PacketError> {
    if packet.len() < 40 {
        return Err(PacketError::Truncated);
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if payload_len + 40 != packet.len() {
        return Err(PacketError::InvalidLength);
    }

    let protocol = match packet[6] {
        17 => Protocol::Udp,
        6 => Protocol::Tcp,
        _ => return Err(PacketError::UnsupportedExtension),
    };
    validate_transport(packet, 40, payload_len, protocol)?;

    let mut source_octets = [0; 16];
    source_octets.copy_from_slice(&packet[8..24]);
    let mut destination_octets = [0; 16];
    destination_octets.copy_from_slice(&packet[24..40]);
    let source = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::from(source_octets)),
        u16::from_be_bytes([packet[40], packet[41]]),
    );
    let destination = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::from(destination_octets)),
        u16::from_be_bytes([packet[42], packet[43]]),
    );
    Ok(PacketLayout {
        version: 6,
        ip_header_len: 40,
        transport_offset: 40,
        transport_len: payload_len,
        protocol,
        source,
        destination,
    })
}

fn validate_transport(
    packet: &[u8],
    transport_offset: usize,
    transport_len: usize,
    protocol: Protocol,
) -> Result<(), PacketError> {
    let transport_end = transport_offset
        .checked_add(transport_len)
        .ok_or(PacketError::InvalidLength)?;
    if transport_end > packet.len() {
        return Err(PacketError::Truncated);
    }
    match protocol {
        Protocol::Udp => {
            if transport_len < 8 {
                return Err(PacketError::InvalidLength);
            }
            let declared_len = usize::from(u16::from_be_bytes([
                packet[transport_offset + 4],
                packet[transport_offset + 5],
            ]));
            if declared_len < 8 || declared_len != transport_len {
                return Err(PacketError::InvalidLength);
            }
        }
        Protocol::Tcp => {
            if transport_len < 20 {
                return Err(PacketError::InvalidLength);
            }
            let data_offset = usize::from(packet[transport_offset + 12] >> 4) * 4;
            if data_offset < 20 || data_offset > transport_len {
                return Err(PacketError::InvalidLength);
            }
        }
    }
    Ok(())
}

fn transport_checksum(
    packet: &[u8],
    version: u8,
    transport_offset: usize,
    transport_len: usize,
    protocol: Protocol,
) -> u16 {
    let mut sum = 0u32;
    if version == 4 {
        sum = add_checksum_words(sum, &packet[12..16]);
        sum = add_checksum_words(sum, &packet[16..20]);
        sum = add_checksum_words(sum, &[0, protocol.number()]);
        sum = add_checksum_words(sum, &(transport_len as u16).to_be_bytes());
    } else {
        sum = add_checksum_words(sum, &packet[8..24]);
        sum = add_checksum_words(sum, &packet[24..40]);
        sum = add_checksum_words(sum, &(transport_len as u32).to_be_bytes());
        sum = add_checksum_words(sum, &[0, 0, 0, protocol.number()]);
    }
    sum = add_checksum_words(
        sum,
        &packet[transport_offset..transport_offset + transport_len],
    );
    !fold_checksum_sum_value(sum)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    !fold_checksum_sum(bytes)
}

fn fold_checksum_sum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = add_checksum_words(sum, bytes);
    fold_checksum_sum_value(sum)
}

fn add_checksum_words(mut sum: u32, bytes: &[u8]) -> u32 {
    for chunk in bytes.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
        sum += u32::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

fn fold_checksum_sum_value(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

impl Protocol {
    fn number(self) -> u8 {
        match self {
            Self::Udp => 17,
            Self::Tcp => 6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

    const V4_SOURCE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 53000);
    const V4_DESTINATION: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)), 53);
    const V4_REWRITTEN_SOURCE: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 22)), 43001);
    const V4_REWRITTEN_DESTINATION: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99)), 5353);
    const V6_SOURCE: SocketAddr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 10)),
        53000,
    );
    const V6_DESTINATION: SocketAddr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 53)),
        53,
    );
    const V6_REWRITTEN_SOURCE: SocketAddr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 22)),
        43001,
    );
    const V6_REWRITTEN_DESTINATION: SocketAddr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 3, 0, 0, 0, 99)),
        5353,
    );

    #[test]
    fn decodes_and_rewrites_all_four_family_protocol_combinations() {
        for (packet, source, destination, protocol, payload_offset) in [
            (
                valid_ipv4_udp(),
                V4_SOURCE,
                V4_DESTINATION,
                Protocol::Udp,
                32,
            ),
            (
                valid_ipv4_tcp(),
                V4_SOURCE,
                V4_DESTINATION,
                Protocol::Tcp,
                48,
            ),
            (
                valid_ipv6_udp(),
                V6_SOURCE,
                V6_DESTINATION,
                Protocol::Udp,
                48,
            ),
            (
                valid_ipv6_tcp(),
                V6_SOURCE,
                V6_DESTINATION,
                Protocol::Tcp,
                64,
            ),
        ] {
            let decoded = decode(&packet).expect("valid DNS transport packet");
            assert_eq!(decoded.source, source);
            assert_eq!(decoded.destination, destination);
            assert_eq!(decoded.protocol, protocol);

            let (rewritten_source, rewritten_destination) = if source.is_ipv4() {
                (V4_REWRITTEN_SOURCE, V4_REWRITTEN_DESTINATION)
            } else {
                (V6_REWRITTEN_SOURCE, V6_REWRITTEN_DESTINATION)
            };
            let rewritten = rewrite(&packet, rewritten_source, rewritten_destination)
                .expect("same-family tuple rewrite");
            let rewritten_info = decode(&rewritten).expect("rewritten packet remains valid");
            assert_eq!(rewritten_info.source, rewritten_source);
            assert_eq!(rewritten_info.destination, rewritten_destination);
            assert_eq!(rewritten_info.protocol, protocol);
            assert_eq!(&packet[payload_offset..], &rewritten[payload_offset..]);
            assert_non_tuple_bytes_preserved(&packet, &rewritten, protocol);
            assert_checksums_independently(&rewritten);

            let restored = rewrite(&rewritten, source, destination).expect("inverse rewrite");
            let restored_info = decode(&restored).expect("inverse packet remains valid");
            assert_eq!(restored_info.source, source);
            assert_eq!(restored_info.destination, destination);
            assert_eq!(restored_info.protocol, protocol);
            assert_eq!(&packet[payload_offset..], &restored[payload_offset..]);
            assert_checksums_independently(&restored);
        }
    }

    #[test]
    fn rewritten_packets_have_valid_checksums_independent_of_codec_helpers() {
        for packet in [
            valid_ipv4_udp(),
            valid_ipv4_tcp(),
            valid_ipv6_udp(),
            valid_ipv6_tcp(),
        ] {
            let (source, destination) = if packet[0] >> 4 == 4 {
                (V4_REWRITTEN_SOURCE, V4_REWRITTEN_DESTINATION)
            } else {
                (V6_REWRITTEN_SOURCE, V6_REWRITTEN_DESTINATION)
            };
            let rewritten = rewrite(&packet, source, destination).unwrap();
            assert_checksums_independently(&rewritten);
        }
    }

    #[test]
    fn zero_udp_checksum_is_materialized_as_a_real_checksum() {
        let mut packet = valid_ipv4_udp();
        packet[30..32].fill(0);
        let rewritten = rewrite(&packet, V4_SOURCE, V4_DESTINATION).unwrap();
        assert_ne!(&rewritten[30..32], &[0, 0]);
        assert_checksums_independently(&rewritten);
    }

    #[test]
    fn zero_calculated_udp_checksum_is_encoded_as_ffff() {
        let mut packet = valid_ipv4_udp();
        packet.truncate(34);
        packet[2..4].copy_from_slice(&34u16.to_be_bytes());
        packet[28..30].copy_from_slice(&10u16.to_be_bytes());
        packet[32..34].copy_from_slice(&0x4429u16.to_be_bytes());

        let rewritten = rewrite(&packet, V4_SOURCE, V4_DESTINATION).unwrap();
        assert_eq!(&rewritten[30..32], &[0xff, 0xff]);
        assert_checksums_independently(&rewritten);
    }

    #[test]
    fn truncating_any_valid_packet_prefix_is_rejected() {
        for packet in [
            valid_ipv4_udp(),
            valid_ipv4_tcp(),
            valid_ipv6_udp(),
            valid_ipv6_tcp(),
        ] {
            for length in 0..packet.len() {
                assert!(
                    decode(&packet[..length]).is_err(),
                    "accepted prefix of {length}"
                );
            }
        }
    }

    #[test]
    fn bytes_after_the_declared_ip_length_are_rejected() {
        for mut packet in [
            valid_ipv4_udp(),
            valid_ipv4_tcp(),
            valid_ipv6_udp(),
            valid_ipv6_tcp(),
        ] {
            packet.push(0);
            assert!(decode(&packet).is_err());
        }
    }

    #[test]
    fn malformed_ip_and_transport_lengths_are_rejected() {
        let mut ipv4_total_short = valid_ipv4_udp();
        ipv4_total_short[2..4].copy_from_slice(&20u16.to_be_bytes());
        assert!(decode(&ipv4_total_short).is_err());

        let mut ipv4_total_long = valid_ipv4_udp();
        let ipv4_total_long_len = ipv4_total_long.len() as u16 + 1;
        ipv4_total_long[2..4].copy_from_slice(&ipv4_total_long_len.to_be_bytes());
        assert!(decode(&ipv4_total_long).is_err());

        let mut udp_short = valid_ipv4_udp();
        udp_short[28..30].copy_from_slice(&7u16.to_be_bytes());
        assert!(decode(&udp_short).is_err());

        let mut udp_mismatch = valid_ipv6_udp();
        udp_mismatch[44..46].copy_from_slice(&8u16.to_be_bytes());
        assert!(decode(&udp_mismatch).is_err());

        let mut ipv6_payload_short = valid_ipv6_tcp();
        ipv6_payload_short[4..6].copy_from_slice(&1u16.to_be_bytes());
        assert!(decode(&ipv6_payload_short).is_err());

        let mut ipv6_payload_long = valid_ipv6_tcp();
        let ipv6_payload_long_len = (ipv6_payload_long.len() - 40 + 1) as u16;
        ipv6_payload_long[4..6].copy_from_slice(&ipv6_payload_long_len.to_be_bytes());
        assert!(decode(&ipv6_payload_long).is_err());
    }

    #[test]
    fn malformed_tcp_offsets_are_rejected() {
        let mut short_offset = valid_ipv4_tcp();
        short_offset[36] = 0x40;
        assert!(decode(&short_offset).is_err());

        let mut beyond_segment = valid_ipv6_tcp();
        beyond_segment[52] = 0xf0;
        assert!(decode(&beyond_segment).is_err());
    }

    #[test]
    fn fragments_reserved_flags_and_extensions_are_rejected() {
        let mut reserved = valid_ipv4_udp();
        reserved[6..8].copy_from_slice(&0x8000u16.to_be_bytes());
        assert!(decode(&reserved).is_err());

        let mut more_fragments = valid_ipv4_udp();
        more_fragments[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(decode(&more_fragments).is_err());

        let mut offset = valid_ipv4_udp();
        offset[6..8].copy_from_slice(&1u16.to_be_bytes());
        assert!(decode(&offset).is_err());

        let mut ipv6_fragment = valid_ipv6_udp();
        ipv6_fragment[6] = 44;
        assert!(decode(&ipv6_fragment).is_err());

        let mut ipv6_extension = valid_ipv6_udp();
        ipv6_extension[6] = 0;
        assert!(decode(&ipv6_extension).is_err());
    }

    #[test]
    fn ipv4_options_are_bounded_and_source_routes_are_rejected() {
        let mut malformed_length = valid_ipv4_udp();
        malformed_length[20..24].copy_from_slice(&[2, 5, 0, 0]);
        assert!(decode(&malformed_length).is_err());

        let mut malformed_trailing_eol = valid_ipv4_udp();
        malformed_trailing_eol[20..24].copy_from_slice(&[0, 0, 1, 0]);
        assert!(decode(&malformed_trailing_eol).is_err());

        for source_route_kind in [131, 137] {
            let mut source_route = valid_ipv4_udp();
            source_route[20..24].copy_from_slice(&[source_route_kind, 3, 0, 0]);
            assert!(decode(&source_route).is_err());
        }
    }

    #[test]
    fn unsupported_versions_protocols_and_families_are_rejected() {
        let mut version = valid_ipv4_udp();
        version[0] = 0x55;
        assert!(decode(&version).is_err());

        let mut protocol = valid_ipv4_udp();
        protocol[9] = 1;
        assert!(decode(&protocol).is_err());

        assert!(rewrite(
            &valid_ipv4_udp(),
            V6_REWRITTEN_SOURCE,
            V6_REWRITTEN_DESTINATION
        )
        .is_err());
        assert!(rewrite(
            &valid_ipv6_udp(),
            V4_REWRITTEN_SOURCE,
            V4_REWRITTEN_DESTINATION
        )
        .is_err());
        assert!(rewrite(
            &valid_ipv4_udp(),
            V4_REWRITTEN_SOURCE,
            V6_REWRITTEN_DESTINATION
        )
        .is_err());

        let scoped_source = SocketAddr::V6(SocketAddrV6::new(
            match V6_REWRITTEN_SOURCE.ip() {
                IpAddr::V6(address) => address,
                IpAddr::V4(_) => unreachable!(),
            },
            V6_REWRITTEN_SOURCE.port(),
            0,
            1,
        ));
        assert!(rewrite(&valid_ipv6_udp(), scoped_source, V6_REWRITTEN_DESTINATION).is_err());
    }

    fn valid_ipv4_udp() -> Vec<u8> {
        let payload = b"dns-v4-udp";
        let header_len = 24;
        let transport_len = 8 + payload.len();
        let mut packet = vec![0; header_len + transport_len];
        packet[0] = 0x46;
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 53]);
        packet[20..24].copy_from_slice(&[1, 1, 0, 0]);
        packet[24..26].copy_from_slice(&53000u16.to_be_bytes());
        packet[26..28].copy_from_slice(&53u16.to_be_bytes());
        packet[28..30].copy_from_slice(&(transport_len as u16).to_be_bytes());
        packet[32..].copy_from_slice(payload);
        packet
    }

    fn valid_ipv4_tcp() -> Vec<u8> {
        let payload = b"dns-v4-tcp";
        let header_len = 24;
        let tcp_header_len = 24;
        let mut packet = vec![0; header_len + tcp_header_len + payload.len()];
        packet[0] = 0x46;
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 53]);
        packet[20..24].copy_from_slice(&[1, 1, 0, 0]);
        packet[24..26].copy_from_slice(&53000u16.to_be_bytes());
        packet[26..28].copy_from_slice(&53u16.to_be_bytes());
        packet[28..32].copy_from_slice(&0x11223344u32.to_be_bytes());
        packet[32..36].copy_from_slice(&0x55667788u32.to_be_bytes());
        packet[36] = 0x60;
        packet[37] = 0x18;
        packet[38..40].copy_from_slice(&4096u16.to_be_bytes());
        packet[44..48].copy_from_slice(&[2, 4, 5, 180]);
        packet[48..].copy_from_slice(payload);
        packet
    }

    fn valid_ipv6_udp() -> Vec<u8> {
        let payload = b"dns-v6-udp";
        let transport_len = 8 + payload.len();
        let mut packet = vec![0; 40 + transport_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(transport_len as u16).to_be_bytes());
        packet[6] = 17;
        packet[8..24].copy_from_slice(&match V6_SOURCE.ip() {
            IpAddr::V6(address) => address.octets(),
            IpAddr::V4(_) => unreachable!(),
        });
        packet[24..40].copy_from_slice(&match V6_DESTINATION.ip() {
            IpAddr::V6(address) => address.octets(),
            IpAddr::V4(_) => unreachable!(),
        });
        packet[40..42].copy_from_slice(&53000u16.to_be_bytes());
        packet[42..44].copy_from_slice(&53u16.to_be_bytes());
        packet[44..46].copy_from_slice(&(transport_len as u16).to_be_bytes());
        packet[48..].copy_from_slice(payload);
        packet
    }

    fn valid_ipv6_tcp() -> Vec<u8> {
        let payload = b"dns-v6-tcp";
        let tcp_header_len = 24;
        let payload_len = tcp_header_len + payload.len();
        let mut packet = vec![0; 40 + payload_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[6] = 6;
        packet[8..24].copy_from_slice(&match V6_SOURCE.ip() {
            IpAddr::V6(address) => address.octets(),
            IpAddr::V4(_) => unreachable!(),
        });
        packet[24..40].copy_from_slice(&match V6_DESTINATION.ip() {
            IpAddr::V6(address) => address.octets(),
            IpAddr::V4(_) => unreachable!(),
        });
        packet[40..42].copy_from_slice(&53000u16.to_be_bytes());
        packet[42..44].copy_from_slice(&53u16.to_be_bytes());
        packet[44..48].copy_from_slice(&0x11223344u32.to_be_bytes());
        packet[48..52].copy_from_slice(&0x55667788u32.to_be_bytes());
        packet[52] = 0x60;
        packet[53] = 0x18;
        packet[54..56].copy_from_slice(&4096u16.to_be_bytes());
        packet[60..64].copy_from_slice(&[2, 4, 5, 180]);
        packet[64..].copy_from_slice(payload);
        packet
    }

    fn assert_checksums_independently(packet: &[u8]) {
        let version = packet[0] >> 4;
        let (source, destination, protocol, transport_start, total_len) = match version {
            4 => {
                let header_len = (packet[0] as usize & 0x0f) * 4;
                let source = &packet[12..16];
                let destination = &packet[16..20];
                (
                    source.to_vec(),
                    destination.to_vec(),
                    packet[9],
                    header_len,
                    u16::from_be_bytes([packet[2], packet[3]]) as usize,
                )
            }
            6 => (
                packet[8..24].to_vec(),
                packet[24..40].to_vec(),
                packet[6],
                40,
                40 + u16::from_be_bytes([packet[4], packet[5]]) as usize,
            ),
            _ => panic!("unsupported fixture version"),
        };
        if version == 4 {
            assert_eq!(ones_complement_sum(&packet[..transport_start]), 0xffff);
        }
        let transport = &packet[transport_start..total_len];
        let mut pseudo = Vec::new();
        pseudo.extend(source);
        pseudo.extend(destination);
        if version == 4 {
            pseudo.extend([0, protocol]);
            pseudo.extend((transport.len() as u16).to_be_bytes());
        } else {
            pseudo.extend((transport.len() as u32).to_be_bytes());
            pseudo.extend([0, 0, 0, protocol]);
        }
        pseudo.extend(transport);
        assert_eq!(ones_complement_sum(&pseudo), 0xffff);
    }

    fn assert_non_tuple_bytes_preserved(before: &[u8], after: &[u8], protocol: Protocol) {
        let version = before[0] >> 4;
        let transport_start = if version == 4 {
            usize::from(before[0] & 0x0f) * 4
        } else {
            40
        };
        if version == 4 {
            assert_eq!(&before[20..transport_start], &after[20..transport_start]);
        }
        let checksum_offset = match protocol {
            Protocol::Udp => 6,
            Protocol::Tcp => 16,
        };
        assert_eq!(
            &before[transport_start + 4..transport_start + checksum_offset],
            &after[transport_start + 4..transport_start + checksum_offset]
        );
        assert_eq!(
            &before[transport_start + checksum_offset + 2..],
            &after[transport_start + checksum_offset + 2..]
        );
    }

    fn ones_complement_sum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in bytes.chunks(2) {
            let value = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
            sum += u32::from(value);
            sum = (sum & 0xffff) + (sum >> 16);
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }
}
