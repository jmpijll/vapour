use std::io::{self, Write};
pub const SNAPLEN: usize = 9000;
pub struct Packet {
    pub kind: u16,
    pub timestamp: i64,
    pub bytes: Vec<u8>,
}
fn block(kind: u32, body: &[u8]) -> Vec<u8> {
    let length = (body.len() + 12) as u32;
    let mut b = Vec::with_capacity(length as usize);
    b.extend(kind.to_le_bytes());
    b.extend(length.to_le_bytes());
    b.extend(body);
    b.extend(length.to_le_bytes());
    b
}
pub fn header() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(0x1A2B3C4Du32.to_le_bytes());
    b.extend(1u16.to_le_bytes());
    b.extend(0u16.to_le_bytes());
    b.extend((-1i64).to_le_bytes());
    let mut out = block(0x0A0D0D0A, &b);
    for link in [1u16, 101u16] {
        let mut b = Vec::new();
        b.extend(link.to_le_bytes());
        b.extend(0u16.to_le_bytes());
        b.extend((SNAPLEN as u32).to_le_bytes());
        out.extend(block(1, &b));
    }
    out
}
pub fn encode(packet: &Packet) -> Option<Vec<u8>> {
    // The API has no original-size field. Exclude the truncation boundary instead
    // of claiming a truncated frame was complete. Oversize warnings count as loss.
    if packet.bytes.is_empty() || packet.bytes.len() >= SNAPLEN {
        return None;
    }
    let interface: u32 = match packet.kind {
        1 => 0,
        3 => 1,
        _ => return None,
    };
    let stamp = packet
        .timestamp
        .checked_sub(116444736000000000)
        .filter(|v| *v >= 0)? as u64
        / 10;
    let mut b = Vec::with_capacity(packet.bytes.len() + 24);
    b.extend(interface.to_le_bytes());
    b.extend(((stamp >> 32) as u32).to_le_bytes());
    b.extend((stamp as u32).to_le_bytes());
    b.extend((packet.bytes.len() as u32).to_le_bytes());
    b.extend((packet.bytes.len() as u32).to_le_bytes());
    b.extend(&packet.bytes);
    while b.len() % 4 != 0 {
        b.push(0);
    }
    Some(block(6, &b))
}
pub fn write_packet(output: &mut impl Write, packet: &Packet) -> io::Result<usize> {
    let bytes = encode(packet)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Unsupported packet"))?;
    output.write_all(&bytes)?;
    Ok(bytes.len())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn creates_pcapng_blocks_and_exact_original_length() {
        let h = header();
        assert_eq!(h.len(), 68);
        assert_eq!(&h[..4], &0x0A0D0D0Au32.to_le_bytes());
        let p = Packet {
            kind: 1,
            timestamp: 116444736000000010,
            bytes: vec![1, 2, 3],
        };
        let b = encode(&p).unwrap();
        assert_eq!(b.len(), 36);
        assert_eq!(&b[20..24], &3u32.to_le_bytes());
        assert_eq!(&b[24..28], &3u32.to_le_bytes());
        assert_eq!(&b[28..31], &[1, 2, 3]);
        assert_eq!(&b[32..36], &36u32.to_le_bytes());
        assert_eq!(&b[16..20], &1u32.to_le_bytes());
    }
    #[test]
    fn excludes_ambiguous_truncation_and_unsupported_frames() {
        for p in [
            Packet {
                kind: 2,
                timestamp: 116444736000000000,
                bytes: vec![1],
            },
            Packet {
                kind: 1,
                timestamp: 0,
                bytes: vec![1],
            },
            Packet {
                kind: 1,
                timestamp: 116444736000000000,
                bytes: vec![0; 9000],
            },
        ] {
            assert!(encode(&p).is_none());
        }
    }
}
