//! Prior UDP bind evidence. This is not a remote-peer or TCP-generation oracle.
#![allow(dead_code)] // Enabled in the capture path after native reconciliation tests.
use super::attribution::{Identity, Verdict};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use windows::Win32::{
    Foundation::ERROR_INSUFFICIENT_BUFFER,
    NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDP6ROW_OWNER_MODULE, MIB_UDP6TABLE_OWNER_MODULE,
        MIB_UDPROW_OWNER_MODULE, MIB_UDPTABLE_OWNER_MODULE, UDP_TABLE_OWNER_MODULE,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
};

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_ROWS: usize = 32_768;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Bind {
    local: SocketAddr,
    owner: Option<Identity>,
    created: u64,
}

pub struct Snapshot {
    rows: Vec<Bind>,
}

pub struct StableBinds {
    before: Snapshot,
    after: Snapshot,
}

impl StableBinds {
    pub fn between(before: Snapshot, after: Snapshot) -> Self {
        Self { before, after }
    }
    pub fn classify(&self, local: SocketAddr, selected: &[Identity]) -> Verdict {
        if local.port() == 0
            || local.ip().is_unspecified()
            || selected.is_empty()
            || selected
                .iter()
                .any(|id| id.pid == 0 || id.creation_time_100ns == 0)
        {
            return Verdict::Invalid;
        }
        let before: Vec<_> = self
            .before
            .rows
            .iter()
            .filter(|row| overlaps(row.local, local))
            .collect();
        let after: Vec<_> = self
            .after
            .rows
            .iter()
            .filter(|row| overlaps(row.local, local))
            .collect();
        if before.is_empty() || after.is_empty() {
            return Verdict::Unknown;
        }
        let mut known = None;
        for row in before.iter().chain(after.iter()) {
            let Some(owner) = row.owner else {
                return Verdict::Unknown;
            };
            if owner.pid == 0
                || owner.creation_time_100ns == 0
                || row.created < owner.creation_time_100ns
            {
                return Verdict::Unknown;
            }
            if known.is_some_and(|other| other != owner) {
                return Verdict::Ambiguous;
            }
            known = Some(owner);
        }
        if before.iter().any(|row| !after.contains(row))
            || after.iter().any(|row| !before.contains(row))
        {
            return Verdict::Unknown;
        }
        if known.is_some_and(|owner| selected.contains(&owner)) {
            Verdict::Selected
        } else {
            Verdict::Other
        }
    }
}

fn overlaps(bind: SocketAddr, local: SocketAddr) -> bool {
    if bind.port() != local.port() {
        return false;
    }
    match (bind, local) {
        (SocketAddr::V4(bind), SocketAddr::V4(local)) => {
            bind.ip().is_unspecified() || bind.ip() == local.ip()
        }
        (SocketAddr::V6(bind), SocketAddr::V6(local)) => {
            (bind.ip().is_unspecified() || bind.ip() == local.ip())
                && (bind.scope_id() == 0
                    || local.scope_id() == 0
                    || bind.scope_id() == local.scope_id())
        }
        (SocketAddr::V6(bind), SocketAddr::V4(local)) => {
            // The UDP table does not expose IPV6_V6ONLY. Treat a wildcard as
            // overlapping IPv4 instead of assuming it cannot receive there.
            bind.ip().is_unspecified() || bind.ip().to_ipv4_mapped().as_ref() == Some(local.ip())
        }
        (SocketAddr::V4(bind), SocketAddr::V6(local)) => local
            .ip()
            .to_ipv4_mapped()
            .is_some_and(|ip| bind.ip().is_unspecified() || *bind.ip() == ip),
    }
}

impl Snapshot {
    pub fn read() -> Result<Self, String> {
        let mut rows = Vec::new();
        let ipv4 = read_table(AF_INET.0 as u32)?;
        for row in decode::<MIB_UDPROW_OWNER_MODULE>(
            &ipv4,
            std::mem::offset_of!(MIB_UDPTABLE_OWNER_MODULE, table),
        )? {
            rows.push(make_bind(
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                    u16::from_be(row.dwLocalPort as u16),
                ),
                row.dwOwningPid,
                row.liCreateTimestamp,
            )?);
        }
        let ipv6 = read_table(AF_INET6.0 as u32)?;
        for row in decode::<MIB_UDP6ROW_OWNER_MODULE>(
            &ipv6,
            std::mem::offset_of!(MIB_UDP6TABLE_OWNER_MODULE, table),
        )? {
            rows.push(make_bind(
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(row.ucLocalAddr),
                    u16::from_be(row.dwLocalPort as u16),
                    0,
                    row.dwLocalScopeId,
                )),
                row.dwOwningPid,
                row.liCreateTimestamp,
            )?);
        }
        if rows.len() > MAX_ROWS {
            return Err("UDP bind snapshot exceeds row limit".into());
        }
        Ok(Self { rows })
    }
}

fn make_bind(local: SocketAddr, pid: u32, created: i64) -> Result<Bind, String> {
    if local.port() == 0 {
        return Err("UDP bind snapshot contains a zero port".into());
    }
    let created = u64::try_from(created).unwrap_or(0);
    // An unreadable process stays in the candidate set as unknown; dropping
    // it could incorrectly turn overlapping ownership into a selected match.
    let owner = super::windivert::identity(pid)
        .filter(|owner| owner.creation_time_100ns != 0 && created >= owner.creation_time_100ns);
    Ok(Bind {
        local,
        owner,
        created,
    })
}

fn read_table(family: u32) -> Result<Vec<u8>, String> {
    let mut needed = 0u32;
    let code =
        unsafe { GetExtendedUdpTable(None, &mut needed, false, family, UDP_TABLE_OWNER_MODULE, 0) };
    if code != 0 && code != ERROR_INSUFFICIENT_BUFFER.0 {
        return Err(format!("Cannot size UDP bind snapshot ({code})"));
    }
    for _ in 0..2 {
        let requested = needed as usize;
        if !(4..=MAX_BYTES).contains(&requested) {
            return Err("Invalid UDP snapshot size".into());
        }
        // The OWNER_MODULE rows contain 64-bit fields. Keep the native write
        // buffer aligned and use only the returned byte length afterward.
        let mut storage = vec![0u64; requested.div_ceil(8)];
        let code = unsafe {
            GetExtendedUdpTable(
                Some(storage.as_mut_ptr().cast()),
                &mut needed,
                false,
                family,
                UDP_TABLE_OWNER_MODULE,
                0,
            )
        };
        if code == ERROR_INSUFFICIENT_BUFFER.0 {
            continue;
        }
        if code != 0 {
            return Err(format!("Cannot read UDP bind snapshot ({code})"));
        }
        if needed as usize > requested {
            return Err("UDP snapshot returned an oversized buffer".into());
        }
        return Ok(unsafe {
            std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), needed as usize)
        }
        .to_vec());
    }
    Err("UDP bind snapshot changed during collection".into())
}

// SAFETY: Implementations must be pointer-free Copy types valid for every bit pattern.
unsafe trait NativeRow: Copy {}
unsafe impl NativeRow for MIB_UDPROW_OWNER_MODULE {}
unsafe impl NativeRow for MIB_UDP6ROW_OWNER_MODULE {}

fn decode<R: NativeRow>(bytes: &[u8], table_offset: usize) -> Result<Vec<R>, String> {
    let count = u32::from_ne_bytes(
        bytes
            .get(..4)
            .ok_or("Truncated UDP snapshot header")?
            .try_into()
            .unwrap(),
    ) as usize;
    let size = std::mem::size_of::<R>();
    if count > MAX_ROWS
        || size == 0
        || table_offset < 4
        || table_offset > bytes.len()
        || count
            .checked_mul(size)
            .and_then(|n| table_offset.checked_add(n))
            .is_none_or(|end| end > bytes.len())
    {
        return Err("Truncated or oversized UDP snapshot rows".into());
    }
    // R is only used here with the SDK's integer-only UDP OWNER_MODULE rows.
    Ok((0..count)
        .map(|index| unsafe {
            bytes
                .as_ptr()
                .add(table_offset + index * size)
                .cast::<R>()
                .read_unaligned()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner(pid: u32) -> Identity {
        Identity {
            pid,
            creation_time_100ns: 100,
        }
    }
    fn bind(local: &str, pid: u32) -> Bind {
        Bind {
            local: local.parse().unwrap(),
            owner: Some(owner(pid)),
            created: 200,
        }
    }
    fn stable(rows: Vec<Bind>) -> StableBinds {
        StableBinds::between(Snapshot { rows: rows.clone() }, Snapshot { rows })
    }
    #[test]
    fn exact_and_wildcard_prior_bind_authorize_only_the_matching_port() {
        for address in ["127.0.0.1:8000", "0.0.0.0:8000"] {
            let evidence = stable(vec![bind(address, 1)]);
            assert_eq!(
                evidence.classify("127.0.0.1:8000".parse().unwrap(), &[owner(1)]),
                Verdict::Selected
            );
            assert_eq!(
                evidence.classify("127.0.0.1:8001".parse().unwrap(), &[owner(1)]),
                Verdict::Unknown
            );
        }
    }
    #[test]
    fn wildcard_competitor_and_dual_stack_overlap_are_ambiguous() {
        for competitor in ["0.0.0.0:8000", "[::]:8000", "[::ffff:127.0.0.1]:8000"] {
            let evidence = stable(vec![bind("127.0.0.1:8000", 1), bind(competitor, 2)]);
            assert_eq!(
                evidence.classify("127.0.0.1:8000".parse().unwrap(), &[owner(1)]),
                Verdict::Ambiguous
            );
        }
    }
    #[test]
    fn changed_bind_lifetime_or_identity_cannot_seed_capture() {
        let first = bind("127.0.0.1:8000", 1);
        for replacement in [
            Bind {
                created: 201,
                ..first.clone()
            },
            bind("127.0.0.1:8000", 2),
        ] {
            let evidence = StableBinds::between(
                Snapshot {
                    rows: vec![first.clone()],
                },
                Snapshot {
                    rows: vec![replacement],
                },
            );
            assert_ne!(
                evidence.classify(first.local, &[owner(1)]),
                Verdict::Selected
            );
        }
    }
    #[test]
    fn unreadable_owner_is_not_discarded_as_if_no_competitor_existed() {
        let selected = bind("127.0.0.1:8000", 1);
        let unknown = Bind {
            owner: None,
            ..bind("0.0.0.0:8000", 2)
        };
        assert_eq!(
            stable(vec![selected.clone(), unknown]).classify(selected.local, &[owner(1)]),
            Verdict::Unknown
        );
    }
    #[test]
    fn ipv6_scopes_are_preserved_and_unknown_scope_does_not_hide_competitors() {
        let evidence = stable(vec![
            bind("[fe80::1%2]:8000", 1),
            bind("[fe80::1%3]:8000", 2),
        ]);
        assert_eq!(
            evidence.classify("[fe80::1%2]:8000".parse().unwrap(), &[owner(1)]),
            Verdict::Selected
        );
        assert_eq!(
            evidence.classify("[fe80::1]:8000".parse().unwrap(), &[owner(1)]),
            Verdict::Ambiguous
        );
    }
    #[test]
    fn duplicate_rows_do_not_create_another_owner_but_invalid_lifetimes_do_not_authorize() {
        let row = bind("127.0.0.1:8000", 1);
        assert_eq!(
            stable(vec![row.clone(), row.clone()]).classify(row.local, &[owner(1)]),
            Verdict::Selected
        );
        assert_eq!(
            stable(vec![Bind {
                created: 99,
                ..row.clone()
            }])
            .classify(row.local, &[owner(1)]),
            Verdict::Unknown
        );
        assert_eq!(
            stable(vec![row.clone()]).classify(row.local, &[owner(2)]),
            Verdict::Other
        );
    }
    #[test]
    fn new_competing_bind_between_snapshots_is_not_ignored() {
        let row = bind("127.0.0.1:8000", 1);
        let evidence = StableBinds::between(
            Snapshot {
                rows: vec![row.clone()],
            },
            Snapshot {
                rows: vec![row.clone(), bind("0.0.0.0:8000", 2)],
            },
        );
        assert_eq!(
            evidence.classify(row.local, &[owner(1)]),
            Verdict::Ambiguous
        );
    }
    #[test]
    fn decoder_checks_returned_length_count_and_header_padding() {
        let offset = std::mem::offset_of!(MIB_UDPTABLE_OWNER_MODULE, table);
        let size = std::mem::size_of::<MIB_UDPROW_OWNER_MODULE>();
        let mut bytes = vec![0u8; offset + size];
        bytes[..4].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(
            decode::<MIB_UDPROW_OWNER_MODULE>(&bytes, offset)
                .unwrap()
                .len(),
            1
        );
        assert!(decode::<MIB_UDPROW_OWNER_MODULE>(&bytes[..bytes.len() - 1], offset).is_err());
        bytes[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(decode::<MIB_UDPROW_OWNER_MODULE>(&bytes, offset).is_err());
        assert!(decode::<MIB_UDPROW_OWNER_MODULE>(&[0; 3], offset).is_err());
        assert!(decode::<MIB_UDPROW_OWNER_MODULE>(&[0; 4], offset).is_err());
    }
    #[test]
    #[ignore = "Reads native UDP owner-module tables with held local IPv4/IPv6 sockets; no system changes"]
    fn live_snapshot_identifies_existing_udp_sockets() {
        let sockets = [
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            std::net::UdpSocket::bind("[::1]:0").unwrap(),
        ];
        let selected = super::super::windivert::identity(std::process::id()).unwrap();
        let evidence = StableBinds::between(
            Snapshot::read().expect("first native snapshot"),
            Snapshot::read().expect("second native snapshot"),
        );
        for socket in &sockets {
            assert_eq!(
                evidence.classify(socket.local_addr().unwrap(), &[selected]),
                Verdict::Selected
            );
        }
    }
}
