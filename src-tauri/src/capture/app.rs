use super::{
    attribution::{Event, Flow, Identity, Ledger, Verdict},
    generation::{Generations, Packet as TcpPacket},
    packet, raw, windivert, CaptureStatus,
};
#[cfg(debug_assertions)]
use super::attribution::EventKind;

// Diagnostics are deliberately debug-build only. The release application
// never reads an environment-controlled path or creates a sidecar file.
#[cfg(debug_assertions)]
struct DiagnosticFlow {
    protocol: u8,
    first_port: u16,
    second_port: u16,
}
#[cfg(debug_assertions)]
struct Diagnostics {
    writer: Option<BufWriter<fs::File>>,
    flows: Vec<DiagnosticFlow>,
}
#[cfg(debug_assertions)]
impl Diagnostics {
    fn from_environment() -> Self {
        let flows = std::env::var("VAPOUR_CAPTURE_DIAGNOSTIC_FLOWS")
            .ok()
            .into_iter()
            .flat_map(|spec| spec.split(';').map(str::to_owned).collect::<Vec<_>>())
            .filter_map(|entry| {
                let mut parts = entry.split(',');
                let protocol = parts.next()?.parse().ok()?;
                let first_port = parts.next()?.parse().ok()?;
                let second_port = parts.next()?.parse().ok()?;
                // A zero port is a bounded wildcard for the ephemeral side of
                // a loopback probe. Both zeroes would make the sidecar global.
                (matches!(protocol, 6 | 17) && (first_port != 0 || second_port != 0))
                    .then_some(DiagnosticFlow { protocol, first_port, second_port })
            })
            .collect::<Vec<_>>();
        let writer = if flows.is_empty() {
            None
        } else {
            std::env::var_os("VAPOUR_CAPTURE_DIAGNOSTIC_PATH")
                .and_then(|path| {
                    OpenOptions::new().write(true).create(true).truncate(true).open(path).ok()
                })
                .map(BufWriter::new)
        };
        let mut diagnostics = Self { writer, flows };
        diagnostics.line("version=1");
        diagnostics
    }
    fn match_flow(&self, flow: &Flow) -> Option<(usize, bool)> {
        self.flows.iter().enumerate().find_map(|(slot, expected)| {
            if !flow.local.ip().is_loopback() || !flow.remote.ip().is_loopback() {
                return None;
            }
            let direct = expected.protocol == flow.protocol
                && (expected.first_port == 0 || flow.local.port() == expected.first_port)
                && (expected.second_port == 0 || flow.remote.port() == expected.second_port);
            let reverse = expected.protocol == flow.protocol
                && (expected.second_port == 0 || flow.local.port() == expected.second_port)
                && (expected.first_port == 0 || flow.remote.port() == expected.first_port);
            if direct {
                Some((slot, false))
            } else if reverse {
                Some((slot, true))
            } else {
                None
            }
        })
    }
    fn line(&mut self, value: &str) {
        if let Some(writer) = self.writer.as_mut() {
            let _ = writeln!(writer, "{value}");
        }
    }
    fn event(&mut self, event: Event, anchor: i64, selected: &[Identity]) {
        let Some((slot, reverse)) = self.match_flow(&event.flow) else { return; };
        let kind = match event.kind {
            EventKind::Connect => 1,
            EventKind::Accept => 2,
            EventKind::Established => 3,
            EventKind::Close => 4,
            EventKind::Deleted => 5,
        };
        self.line(&format!(
            "event slot={slot} qpc_rel={} kind={kind} reverse={} owner_valid={} owner_selected={}",
            event.timestamp_qpc.saturating_sub(anchor),
            u8::from(reverse),
            u8::from(event.owner.creation_time_100ns != 0),
            u8::from(selected.contains(&event.owner)),
        ));
    }
    fn packet(
        &mut self,
        at: i64,
        flow: &Flow,
        flags: u8,
        payload: usize,
        sequence: Option<u32>,
        acknowledgment: Option<u32>,
        verdict: Verdict,
        anchor: i64,
    ) {
        let Some((slot, reverse)) = self.match_flow(flow) else { return; };
        let verdict = match verdict {
            Verdict::Selected => 1,
            Verdict::Other => 2,
            Verdict::Unknown => 3,
            Verdict::Ambiguous => 4,
            Verdict::Invalid => 5,
        };
        self.line(&format!(
            "packet slot={slot} qpc_rel={} protocol={} reverse={} flags={} seq={} ack={} payload_bytes={} verdict={verdict}",
            at.saturating_sub(anchor),
            flow.protocol,
            u8::from(reverse),
            flags,
            sequence.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            acknowledgment.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            payload,
        ));
    }
}
#[cfg(debug_assertions)]
impl Drop for Diagnostics {
    fn drop(&mut self) {
        if let Some(writer) = self.writer.as_mut() { let _ = writer.flush(); }
    }
}
#[cfg(not(debug_assertions))]
struct Diagnostics;
#[cfg(not(debug_assertions))]
impl Diagnostics {
    fn from_environment() -> Self { Self }
    fn event(&mut self, _event: Event, _anchor: i64, _selected: &[Identity]) {}
    fn packet(
        &mut self,
        _at: i64,
        _flow: &Flow,
        _flags: u8,
        _payload: usize,
        _sequence: Option<u32>,
        _acknowledgment: Option<u32>,
        _verdict: Verdict,
        _anchor: i64,
    ) {}
}
use parking_lot::Mutex;
use std::{
    fs::{self, OpenOptions},
    io::{BufWriter, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, mpsc::SyncSender, Arc},
};

pub fn stage(directory: &Path) -> Result<PathBuf, String> {
    // Embedded versioned files; never resolve DLLs via PATH or the working directory.
    let directory = directory.join("windivert-2.2.2-A-x64");
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    for (name, bytes) in [
        (
            "WinDivert.dll",
            include_bytes!("../../vendor/windivert/WinDivert.dll").as_slice(),
        ),
        (
            "WinDivert64.sys",
            include_bytes!("../../vendor/windivert/WinDivert64.sys").as_slice(),
        ),
        (
            "LICENSE",
            include_bytes!("../../vendor/windivert/LICENSE").as_slice(),
        ),
    ] {
        let path = directory.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                f.write_all(bytes).map_err(|e| e.to_string())?;
                f.sync_all().map_err(|e| e.to_string())?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
        if fs::read(&path).map_err(|e| e.to_string())? != bytes {
            return Err("Capture runtime integrity check failed".into());
        }
    }
    Ok(directory.join("WinDivert.dll"))
}

pub fn resolve(pid: u32, expected_path: &str) -> Result<Identity, String> {
    use windows::{
        core::PWSTR,
        Win32::{
            Foundation::{CloseHandle, FILETIME},
            System::Threading::*,
        },
    };
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|_| "App has closed")?;
        struct Guard(windows::Win32::Foundation::HANDLE);
        impl Drop for Guard {
            fn drop(&mut self) {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
        let _guard = Guard(h);
        let mut path = vec![0u16; 32768];
        let mut len = path.len() as u32;
        QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_FORMAT(0),
            PWSTR(path.as_mut_ptr()),
            &mut len,
        )
        .map_err(|e| e.to_string())?;
        if !String::from_utf16_lossy(&path[..len as usize]).eq_ignore_ascii_case(expected_path) {
            return Err("App identity changed".into());
        }
        let (mut creation, mut exit, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        GetProcessTimes(h, &mut creation, &mut exit, &mut kernel, &mut user)
            .map_err(|e| e.to_string())?;
        Ok(Identity {
            pid,
            creation_time_100ns: ((creation.dwHighDateTime as u64) << 32)
                | creation.dwLowDateTime as u64,
        })
    }
}

fn timestamp(qpc: i64, anchor: i64, filetime: i64, frequency: u64) -> Option<i64> {
    if frequency == 0 {
        return None;
    }
    let time = filetime as i128 + (qpc as i128 - anchor as i128) * 10_000_000 / frequency as i128;
    i64::try_from(time)
        .ok()
        .filter(|time| *time >= 116444736000000000)
}

pub fn capture(
    dll: &Path,
    output: &Path,
    identities: Vec<Identity>,
    cancel: &AtomicBool,
    state: &Arc<Mutex<CaptureStatus>>,
    ready: SyncSender<Result<(), String>>,
) -> Result<(), String> {
    let mut diagnostics = Diagnostics::from_environment();
    let mut loss = super::CaptureLossDetails::default();
    let result = windivert::collect(dll, cancel, super::MAX_SECONDS, ready, &mut loss);
    state.lock().loss_details = loss;
    let mut capture = result?;
    state.lock().finalizing = true;
    let mut ledger = Ledger::new(20_000);
    for event in &capture.events {
        diagnostics.event(*event, capture.qpc_anchor, &identities);
        if !ledger.ingest(*event) {
            return Err("Incomplete process evidence; recording discarded".into());
        }
    }
    let udp_events: Vec<_> = capture.events.iter().filter(|event| event.flow.protocol == 17).copied().collect();
    let mut generations = Generations::new(capture.events, 4096);
    capture.packets.sort_by_key(|p| p.0);
    // Broad bytes never reach disk. Only admitted packets are encoded below.
    let pending = output.with_extension("pending");
    struct Pending(PathBuf);
    impl Drop for Pending {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let cleanup = Pending(pending.clone());
    let mut file = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)
            .map_err(|e| e.to_string())?,
    );
    file.write_all(&packet::header())
        .map_err(|e| e.to_string())?;
    let mut selected = 0u64;
    let mut total = packet::header().len() as u64;
    let mut unknown = 0u64;
    for (at, bytes) in capture.packets {
        let Some(info) = raw::parse_packet(&bytes) else {
            unknown += 1;
            continue;
        };
        let flow = super::attribution::Flow {
            protocol: info.protocol,
            local: SocketAddr::new(
                info.src.parse().map_err(|_| "Invalid capture IP")?,
                info.sport,
            ),
            remote: SocketAddr::new(
                info.dst.parse().map_err(|_| "Invalid capture IP")?,
                info.dport,
            ),
        };
        let verdict = if info.protocol == 6 {
            generations.classify_any(
                TcpPacket {
                    flow,
                    at,
                    seq: info.tcp_sequence.ok_or("Missing sequence")?,
                    ack: info.tcp_acknowledgment.ok_or("Missing ACK")?,
                    flags: info.flags,
                    payload: info
                        .payload_bytes
                        .try_into()
                        .map_err(|_| "Oversized TCP payload")?,
                },
                &identities,
            )
        } else {
            let decisions: Vec<_> = identities
                .iter()
                .map(|id| ledger.classify(&flow, at, *id))
                .collect();
            if decisions.contains(&Verdict::Invalid) {
                Verdict::Invalid
            } else if decisions.contains(&Verdict::Ambiguous) {
                Verdict::Ambiguous
            } else if decisions.contains(&Verdict::Selected) {
                Verdict::Selected
            } else if decisions.contains(&Verdict::Unknown) {
                Verdict::Unknown
            } else {
                Verdict::Other
            }
        };
        let verdict = if info.protocol == 17 && matches!(verdict, Verdict::Unknown | Verdict::Other)
            && capture.udp_binds.as_ref().is_some_and(|binds|
                binds.incoming(&flow, at, &udp_events, &ledger, &identities) == Verdict::Selected) {
            Verdict::Selected
        } else {
            verdict
        };
        diagnostics.packet(
            at,
            &flow,
            info.flags,
            info.payload_bytes,
            info.tcp_sequence,
            info.tcp_acknowledgment,
            verdict,
            capture.qpc_anchor,
        );
        match verdict {
            Verdict::Invalid => {
                return Err("Capture evidence limit reached; recording discarded".into())
            }
            Verdict::Unknown | Verdict::Ambiguous => {
                unknown += 1;
                continue;
            }
            Verdict::Other => continue,
            Verdict::Selected => {}
        }
        let time = timestamp(
            at,
            capture.qpc_anchor,
            capture.filetime_anchor,
            capture.qpc_frequency,
        )
        .ok_or("Invalid capture clock")?;
        let packet = packet::Packet {
            kind: 3,
            timestamp: time,
            bytes,
        };
        let Some(encoded) = packet::encode(&packet) else {
            unknown += 1;
            continue;
        };
        total += encoded.len() as u64;
        if total > super::MAX_BYTES {
            return Err("Capture size limit reached".into());
        }
        file.write_all(&encoded).map_err(|e| e.to_string())?;
        selected += 1;
    }
    file.flush().map_err(|e| e.to_string())?;
    file.get_ref().sync_all().map_err(|e| e.to_string())?;
    drop(file);
    if selected == 0 {
        return Err("No new app connections captured".into());
    }
    fs::rename(&pending, output).map_err(|e| e.to_string())?;
    drop(cleanup);
    let mut status = state.lock();
    status.packets = selected;
    status.bytes = total;
    status.loss_details.scope_rejected = unknown;
    status.path = Some(output.to_string_lossy().into_owned());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qpc_conversion_uses_anchor_not_absolute_qpc() {
        let epoch = 116444736000000000;
        assert_eq!(timestamp(150, 100, epoch, 100), Some(epoch + 5_000_000));
        assert_eq!(
            timestamp(90, 100, epoch + 10_000_000, 100),
            Some(epoch + 9_000_000)
        );
        assert_eq!(timestamp(100, 100, epoch, 0), None);
        assert_eq!(timestamp(i64::MAX, 0, i64::MAX, 1), None);
    }
}
