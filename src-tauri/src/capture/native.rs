//! ABI source: Microsoft Learn PacketMonitorCreateRealtimeStream and EnumDataSources.
//! Microsoft publishes no SDK header/import library. The packed 40-byte stream
//! metadata layout is additionally verified by the repository's runtime probe.
use super::{
    endpoint::Endpoint,
    packet::{self, Packet},
    CaptureInterface, CaptureLossDetails, CaptureStatus, MAX_BYTES, MAX_SECONDS,
};
use parking_lot::Mutex;
use std::{
    ffi::c_void,
    io::{BufWriter, Write},
    path::Path,
    ptr::null_mut,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Handle = *mut c_void;
type Close = unsafe extern "system" fn(Handle);
type Active = unsafe extern "system" fn(Handle, u8) -> i32;
type Enumerate = unsafe extern "system" fn(Handle, i32, u8, usize, *mut usize, *mut c_void) -> i32;
#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(name: *const u16, file: Handle, flags: u32) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: Handle) -> i32;
    fn GetLastError() -> u32;
}
struct Module(Handle);
impl Drop for Module {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0);
        }
    }
}
struct Resource {
    handle: Handle,
    close: Close,
}
impl Drop for Resource {
    fn drop(&mut self) {
        unsafe {
            (self.close)(self.handle);
        }
    }
}
struct Running {
    session: Handle,
    set: Active,
}
impl Drop for Running {
    fn drop(&mut self) {
        unsafe {
            (self.set)(self.session, 0);
        }
    }
}
fn check(hr: i32, operation: &str) -> Result<(), String> {
    if hr < 0 {
        Err(if hr as u32 == 0x80070005 {
            "Administrator access is required for capture".into()
        } else {
            format!("{operation}: 0x{:08X}", hr as u32)
        })
    } else {
        Ok(())
    }
}
// Fields drop in order: close driver before unloading its DLL.
struct Api {
    driver: Resource,
    module: Module,
}
impl Api {
    fn open() -> Result<Self, String> {
        let name: Vec<u16> = "PktMonApi.dll\0".encode_utf16().collect();
        let module = Module(unsafe { LoadLibraryExW(name.as_ptr(), null_mut(), 0x800) });
        if module.0.is_null() {
            return Err(format!(
                "Windows packet capture is unavailable ({})",
                unsafe { GetLastError() }
            ));
        }
        let initialize: unsafe extern "system" fn(u32, *mut c_void, *mut Handle) -> i32 =
            unsafe { std::mem::transmute(resolve(&module, "PacketMonitorInitialize")?) };
        let close: Close =
            unsafe { std::mem::transmute(resolve(&module, "PacketMonitorUninitialize")?) };
        let mut handle = null_mut();
        check(
            unsafe { initialize(0x10000, null_mut(), &mut handle) },
            "Initialize capture",
        )?;
        Ok(Self {
            module,
            driver: Resource { handle, close },
        })
    }
    fn sources(&self) -> Result<Sources, String> {
        let enumerate: Enumerate =
            unsafe { std::mem::transmute(resolve(&self.module, "PacketMonitorEnumDataSources")?) };
        let mut needed = 0;
        unsafe {
            enumerate(self.driver.handle, 1, 0, 0, &mut needed, null_mut());
        }
        if !(16..=1024 * 1024).contains(&needed) {
            return Err("Invalid capture interface inventory".into());
        }
        let mut buffer = vec![0u64; needed.div_ceil(8)];
        let capacity = buffer.len() * 8;
        check(
            unsafe {
                enumerate(
                    self.driver.handle,
                    1,
                    0,
                    capacity,
                    &mut needed,
                    buffer.as_mut_ptr().cast(),
                )
            },
            "Read capture interfaces",
        )?;
        if needed > capacity {
            return Err("Capture interface inventory changed".into());
        }
        let count = buffer[0] as u32 as usize;
        if count > (capacity - 8) / 8 {
            return Err("Invalid interface count".into());
        }
        let begin = buffer.as_ptr() as usize;
        let mut items = Vec::new();
        for position in 0..count {
            let pointer = buffer[1 + position] as usize;
            if pointer < begin
                || pointer
                    .checked_add(404)
                    .filter(|end| *end <= begin + capacity)
                    .is_none()
            {
                return Err("Invalid interface descriptor".into());
            }
            let raw = unsafe { std::slice::from_raw_parts(pointer as *const u8, 404) };
            let decode = |bytes: &[u8]| {
                String::from_utf16_lossy(
                    &bytes
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .take_while(|v| *v != 0)
                        .collect::<Vec<_>>(),
                )
            };
            let description = decode(&raw[132..388]);
            let name = if description.trim().is_empty() {
                decode(&raw[4..132])
            } else {
                description
            };
            let id = u32::from_le_bytes(raw[388..392].try_into().unwrap());
            items.push((CaptureInterface { id, name }, position));
        }
        Ok(Sources { buffer, items })
    }
}
struct Sources {
    buffer: Vec<u64>,
    items: Vec<(CaptureInterface, usize)>,
}
unsafe fn resolve(module: &Module, name: &str) -> Result<*mut c_void, String> {
    let name = format!("{name}\0");
    let p = GetProcAddress(module.0, name.as_ptr());
    if p.is_null() {
        Err("Windows capture API is incomplete".into())
    } else {
        Ok(p)
    }
}
pub fn list_interfaces() -> Result<Vec<CaptureInterface>, String> {
    let api = Api::open()?;
    Ok(api.sources()?.items.into_iter().map(|(i, _)| i).collect())
}
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct Ip([u8; 16]);
#[repr(C)]
struct Constraint {
    name: [u16; 64],
    flags: u32,
    mac1: [u8; 6],
    mac2: [u8; 6],
    vlan: u16,
    ether: u16,
    dscp: u16,
    protocol: u8,
    ip1: Ip,
    ip2: Ip,
    prefix1: u8,
    prefix2: u8,
    port1: u16,
    port2: u16,
    tcp: u8,
    encap: u32,
    vx: u16,
    packets: u64,
    bytes: u64,
}
// Layout verified against PktMonApi and the standalone live probe.
const _: () = assert!(std::mem::size_of::<Constraint>() == 216);
impl Constraint {
    fn endpoint(target: &Endpoint) -> Self {
        let mut filter: Self = unsafe { std::mem::zeroed() };
        filter.name[0] = 86;
        filter.flags = (1 << 5) | (1 << 6) | (1 << 7) | (1 << 11) | (1 << 12);
        filter.protocol = target.protocol;
        if target.local_ip.is_ipv6() {
            filter.flags |= 1 << 8;
        }
        for (field, address) in [
            (&mut filter.ip1, target.local_ip),
            (&mut filter.ip2, target.remote_ip),
        ] {
            match address {
                std::net::IpAddr::V4(ip) => field.0[..4].copy_from_slice(&ip.octets()),
                std::net::IpAddr::V6(ip) => field.0.copy_from_slice(&ip.octets()),
            }
        }
        filter.port1 = target.local_port;
        filter.port2 = target.remote_port;
        filter
    }
}
#[repr(C)]
struct Descriptor {
    data: *const u8,
    size: u32,
    metadata: u32,
    packet: u32,
    length: u32,
    missed_write: u32,
    missed_read: u32,
}
#[repr(C)]
struct Configuration {
    context: *mut c_void,
    event: Option<unsafe extern "system" fn(*mut c_void, *const c_void, i32)>,
    data: Option<unsafe extern "system" fn(*mut c_void, *const Descriptor)>,
    multiplier: u16,
    truncation: u16,
}
// PACKETMONITOR_STREAM_PROCESS_INFO; supplied only for the process-info event.
#[repr(C)]
#[derive(Clone, Copy)]
struct StreamProcessInfo {
    is_warning: u8,
    reason: u32,
    packet_length: u64,
}
const _: () = assert!(std::mem::size_of::<StreamProcessInfo>() == 16);
#[derive(Default)]
struct LossCounters {
    native_missed_read: AtomicU64,
    native_missed_write: AtomicU64,
    stream_warnings: AtomicU64,
    stream_last_reason: AtomicU64,
    stream_max_packet_length: AtomicU64,
    invalid_records: AtomicU64,
    unsupported_frames: AtomicU64,
    scope_rejected: AtomicU64,
    queue_full: AtomicU64,
    size_limit: AtomicU64,
}
impl LossCounters {
    fn snapshot(&self) -> CaptureLossDetails {
        CaptureLossDetails {
            native_missed_read: self.native_missed_read.load(Ordering::Relaxed),
            native_missed_write: self.native_missed_write.load(Ordering::Relaxed),
            stream_warnings: self.stream_warnings.load(Ordering::Relaxed),
            stream_last_reason: self.stream_last_reason.load(Ordering::Relaxed),
            stream_max_packet_length: self.stream_max_packet_length.load(Ordering::Relaxed),
            invalid_records: self.invalid_records.load(Ordering::Relaxed),
            unsupported_frames: self.unsupported_frames.load(Ordering::Relaxed),
            scope_rejected: self.scope_rejected.load(Ordering::Relaxed),
            queue_full: self.queue_full.load(Ordering::Relaxed),
            size_limit: self.size_limit.load(Ordering::Relaxed),
        }
    }
}
struct Queue {
    endpoint: Option<Endpoint>,
    sender: SyncSender<Packet>,
    dropped: AtomicU64,
    loss: LossCounters,
    fatal: AtomicBool,
}
// Created before the native stream so its final snapshot also runs on errors,
// after callback resources have been closed and before their queue is released.
struct LossSnapshot<'a> {
    queue: &'a Queue,
    state: &'a Mutex<CaptureStatus>,
}
impl Drop for LossSnapshot<'_> {
    fn drop(&mut self) {
        let mut status = self.state.lock();
        status.dropped = self.queue.dropped.load(Ordering::Relaxed);
        status.loss_details = self.queue.loss.snapshot();
    }
}
unsafe extern "system" fn on_event(context: *mut c_void, info: *const c_void, kind: i32) {
    if context.is_null() {
        return;
    }
    let q = &*(context as *const Queue);
    match kind {
        2 => {
            q.fatal.store(true, Ordering::Release);
        }
        3 => {
            q.loss.stream_warnings.fetch_add(1, Ordering::Relaxed);
            if !info.is_null() {
                let info = std::ptr::read_unaligned(info.cast::<StreamProcessInfo>());
                q.loss
                    .stream_last_reason
                    .store(info.reason as u64, Ordering::Relaxed);
                q.loss
                    .stream_max_packet_length
                    .fetch_max(info.packet_length, Ordering::Relaxed);
            }
            q.dropped.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}
unsafe extern "system" fn on_data(context: *mut c_void, data: *const Descriptor) {
    if context.is_null() || data.is_null() {
        return;
    }
    let q = &*(context as *const Queue);
    let d = &*data;
    q.loss
        .native_missed_read
        .fetch_add(d.missed_read as u64, Ordering::Relaxed);
    q.loss
        .native_missed_write
        .fetch_add(d.missed_write as u64, Ordering::Relaxed);
    q.dropped.fetch_add(
        d.missed_write as u64 + d.missed_read as u64,
        Ordering::Relaxed,
    );
    if d.data.is_null()
        || d.length == 0
        || d.length >= packet::SNAPLEN as u32
        || d.packet as u64 + d.length as u64 > d.size as u64
        || d.metadata as u64 + 40 > d.size as u64
        || d.metadata as u64 + 40 != d.packet as u64
    {
        q.loss.invalid_records.fetch_add(1, Ordering::Relaxed);
        q.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let metadata = std::slice::from_raw_parts(d.data.add(d.metadata as usize), 40);
    let kind = u16::from_le_bytes([metadata[14], metadata[15]]);
    let timestamp = i64::from_le_bytes(metadata[32..40].try_into().unwrap());
    if !matches!(kind, 1 | 3) {
        q.loss.unsupported_frames.fetch_add(1, Ordering::Relaxed);
        q.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if timestamp < 116444736000000000 {
        q.loss.invalid_records.fetch_add(1, Ordering::Relaxed);
        q.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let bytes = std::slice::from_raw_parts(d.data.add(d.packet as usize), d.length as usize);
    if q.endpoint
        .as_ref()
        .is_some_and(|target| !target.matches(kind, bytes))
    {
        q.loss.scope_rejected.fetch_add(1, Ordering::Relaxed);
        q.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let packet = Packet {
        kind,
        timestamp,
        bytes: bytes.to_vec(),
    };
    if q.sender.try_send(packet).is_err() {
        q.loss.queue_full.fetch_add(1, Ordering::Relaxed);
        q.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
pub fn capture(
    id: u32,
    path: &Path,
    cancel: &AtomicBool,
    state: &Arc<Mutex<CaptureStatus>>,
    ready: SyncSender<Result<(), String>>,
    endpoint: Option<Endpoint>,
) -> Result<(), String> {
    let result = run(id, path, cancel, state, &ready, endpoint);
    if let Err(e) = &result {
        let _ = ready.try_send(Err(e.clone()));
    }
    result
}
fn run(
    id: u32,
    path: &Path,
    cancel: &AtomicBool,
    state: &Arc<Mutex<CaptureStatus>>,
    ready: &SyncSender<Result<(), String>>,
    endpoint: Option<Endpoint>,
) -> Result<(), String> {
    let api = Api::open()?;
    let sources = api.sources()?;
    let position = sources
        .items
        .iter()
        .find(|(item, _)| item.id == id)
        .map(|(_, position)| *position)
        .ok_or("Capture interface is no longer available")?;
    macro_rules! export {
        ($name:literal,$ty:ty) => {
            unsafe { std::mem::transmute::<*mut c_void, $ty>(resolve(&api.module, $name)?) }
        };
    }
    let create = export!(
        "PacketMonitorCreateLiveSession",
        unsafe extern "system" fn(Handle, *const u16, *mut Handle) -> i32
    );
    let close = export!("PacketMonitorCloseSessionHandle", Close);
    let add = export!(
        "PacketMonitorAddSingleDataSourceToSession",
        unsafe extern "system" fn(Handle, *const c_void) -> i32
    );
    let create_stream = export!(
        "PacketMonitorCreateRealtimeStream",
        unsafe extern "system" fn(Handle, *const Configuration, *mut Handle) -> i32
    );
    let close_stream = export!("PacketMonitorCloseRealtimeStream", Close);
    let attach = export!(
        "PacketMonitorAttachOutputToSession",
        unsafe extern "system" fn(Handle, Handle) -> i32
    );
    let active = export!("PacketMonitorSetSessionActive", Active);
    let name = format!(
        "Vapour-Capture-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos()
    );
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut session = null_mut();
    check(
        unsafe { create(api.driver.handle, name.as_ptr(), &mut session) },
        "Create capture session",
    )?;
    let session = Resource {
        handle: session,
        close,
    };
    check(
        unsafe {
            add(
                session.handle,
                sources.buffer[1 + position] as *const c_void,
            )
        },
        "Select capture interface",
    )?;
    // Add the OS constraint before creating the stream or activating this session.
    // Failure must never fall back to an unfiltered capture.
    if let Some(target) = endpoint.as_ref() {
        let add_constraint = export!(
            "PacketMonitorAddCaptureConstraint",
            unsafe extern "system" fn(Handle, *const Constraint) -> i32
        );
        let filter = Constraint::endpoint(target);
        check(
            unsafe { add_constraint(session.handle, &filter) },
            "Constrain capture endpoints",
        )?;
    }
    let (sender, receiver) = mpsc::sync_channel(256);
    let queue = Box::new(Queue {
        endpoint,
        sender,
        dropped: AtomicU64::new(0),
        loss: LossCounters::default(),
        fatal: AtomicBool::new(false),
    });
    let _loss_snapshot = LossSnapshot {
        queue: &queue,
        state,
    };
    let config = Configuration {
        context: (&*queue as *const Queue).cast_mut().cast(),
        event: Some(on_event),
        data: Some(on_data),
        multiplier: 4,
        truncation: packet::SNAPLEN as u16,
    };
    let mut stream = null_mut();
    check(
        unsafe { create_stream(api.driver.handle, &config, &mut stream) },
        "Create capture stream",
    )?;
    let stream = Resource {
        handle: stream,
        close: close_stream,
    };
    check(
        unsafe { attach(session.handle, stream.handle) },
        "Attach capture stream",
    )?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    let mut owned = OwnedOutput {
        path,
        complete: false,
    };
    let mut output = BufWriter::with_capacity(64 * 1024, file);
    let header = packet::header();
    output.write_all(&header).map_err(|e| e.to_string())?;
    let mut written = header.len() as u64;
    state.lock().bytes = written;
    check(unsafe { active(session.handle, 1) }, "Start capture")?;
    let running = Running {
        session: session.handle,
        set: active,
    };
    let start = Instant::now();
    let _ = ready.send(Ok(()));
    let mut limit = false;
    while !cancel.load(Ordering::Acquire) && start.elapsed() < Duration::from_secs(MAX_SECONDS) {
        if queue.fatal.load(Ordering::Acquire) {
            return Err("Windows stopped the capture stream".into());
        }
        if let Ok(packet) = receiver.recv_timeout(Duration::from_millis(50)) {
            if !store(&mut output, &packet, &mut written, state)? {
                queue.loss.size_limit.fetch_add(1, Ordering::Relaxed);
                queue.dropped.fetch_add(1, Ordering::Relaxed);
                limit = true;
                break;
            }
        }
        let mut s = state.lock();
        s.duration_ms = start.elapsed().as_millis() as u64;
        s.dropped = queue.dropped.load(Ordering::Relaxed);
        s.loss_details = queue.loss.snapshot();
    }
    let stopped = unsafe { active(session.handle, 0) };
    drop(running);
    drop(stream);
    // Callbacks are closed before draining or releasing their context.
    drain(&receiver, &mut output, &mut written, state, &queue, limit)?;
    check(stopped, "Stop capture")?;
    if queue.fatal.load(Ordering::Acquire) {
        return Err("Windows stopped the capture stream".into());
    }
    output.flush().map_err(|e| e.to_string())?;
    output.get_ref().sync_all().map_err(|e| e.to_string())?;
    let mut s = state.lock();
    s.duration_ms = start.elapsed().as_millis() as u64;
    s.dropped = queue.dropped.load(Ordering::Relaxed);
    s.loss_details = queue.loss.snapshot();
    s.path = Some(path.to_string_lossy().into_owned());
    owned.complete = true;
    Ok(())
}
struct OwnedOutput<'a> {
    path: &'a Path,
    complete: bool,
}
impl Drop for OwnedOutput<'_> {
    fn drop(&mut self) {
        if !self.complete {
            let _ = std::fs::remove_file(self.path);
        }
    }
}
fn store(
    output: &mut impl Write,
    packet: &Packet,
    written: &mut u64,
    state: &Arc<Mutex<CaptureStatus>>,
) -> Result<bool, String> {
    let size = 32 + packet.bytes.len().next_multiple_of(4) as u64;
    if *written + size > MAX_BYTES {
        return Ok(false);
    }
    let added = packet::write_packet(output, packet).map_err(|e| e.to_string())?;
    *written += added as u64;
    let mut s = state.lock();
    s.packets += 1;
    s.bytes = *written;
    Ok(true)
}
fn drain(
    receiver: &Receiver<Packet>,
    output: &mut impl Write,
    written: &mut u64,
    state: &Arc<Mutex<CaptureStatus>>,
    queue: &Queue,
    mut limit: bool,
) -> Result<(), String> {
    for packet in receiver.try_iter() {
        if limit || !store(output, &packet, written, state)? {
            limit = true;
            queue.loss.size_limit.fetch_add(1, Ordering::Relaxed);
            queue.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loss_diagnostics_separate_native_loss_warning_and_rejections() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let q = Queue {
            endpoint: None,
            sender,
            dropped: AtomicU64::new(0),
            loss: LossCounters::default(),
            fatal: AtomicBool::new(false),
        };
        let state = Mutex::new(CaptureStatus::default());
        let snapshot = LossSnapshot {
            queue: &q,
            state: &state,
        };
        let mut bytes = vec![0u8; 43];
        bytes[14..16].copy_from_slice(&2u16.to_le_bytes());
        bytes[32..40].copy_from_slice(&116444736000000000i64.to_le_bytes());
        let descriptor = Descriptor {
            data: bytes.as_ptr(),
            size: 43,
            metadata: 0,
            packet: 40,
            length: 3,
            missed_write: 3,
            missed_read: 2,
        };
        unsafe {
            let context = (&q as *const Queue).cast_mut().cast();
            on_data(context, &descriptor);
            let info = StreamProcessInfo {
                is_warning: 1,
                reason: 122,
                packet_length: 64_000,
            };
            on_event(context, (&info as *const StreamProcessInfo).cast(), 3);
            on_event(context, std::ptr::null(), 2);
        }
        assert!(receiver.try_recv().is_err());
        assert!(q.fatal.load(Ordering::Acquire));
        // The guard publishes diagnostics even when fatal stream failure exits.
        drop(snapshot);
        let status = state.lock();
        assert_eq!(status.dropped, 7);
        assert_eq!(status.loss_details.native_missed_read, 2);
        assert_eq!(status.loss_details.native_missed_write, 3);
        assert_eq!(status.loss_details.stream_warnings, 1);
        assert_eq!(status.loss_details.stream_last_reason, 122);
        assert_eq!(status.loss_details.stream_max_packet_length, 64_000);
        assert_eq!(status.loss_details.unsupported_frames, 1);
        assert_eq!(status.loss_details.invalid_records, 0);
        assert_eq!(status.loss_details.queue_full, 0);
        assert_eq!(status.loss_details.size_limit, 0);
    }
    #[test]
    fn size_limit_drain_counts_each_unwritten_packet_separately() {
        let (sender, receiver) = mpsc::sync_channel(2);
        let q = Queue {
            endpoint: None,
            sender,
            dropped: AtomicU64::new(0),
            loss: LossCounters::default(),
            fatal: AtomicBool::new(false),
        };
        for _ in 0..2 {
            q.sender
                .try_send(Packet {
                    kind: 1,
                    timestamp: 116444736000000000,
                    bytes: vec![1, 2, 3],
                })
                .unwrap();
        }
        let state = Arc::new(Mutex::new(CaptureStatus::default()));
        let mut written = MAX_BYTES;
        let mut output = Vec::new();
        drain(&receiver, &mut output, &mut written, &state, &q, false).unwrap();
        assert!(output.is_empty());
        assert_eq!(q.dropped.load(Ordering::Relaxed), 2);
        let loss = q.loss.snapshot();
        assert_eq!(loss.size_limit, 2);
        assert_eq!(loss.queue_full, 0);
        assert_eq!(loss.invalid_records, 0);
    }
    #[test]
    fn callback_bounds_queue_and_rejects_corrupt_offsets() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut q = Queue {
            endpoint: None,
            sender,
            dropped: AtomicU64::new(0),
            loss: LossCounters::default(),
            fatal: AtomicBool::new(false),
        };
        let mut bytes = vec![0u8; 43];
        bytes[14..16].copy_from_slice(&1u16.to_le_bytes());
        bytes[32..40].copy_from_slice(&116444736000000000i64.to_le_bytes());
        bytes[40..].copy_from_slice(&[1, 2, 3]);
        let mut d = Descriptor {
            data: bytes.as_ptr(),
            size: 43,
            metadata: 0,
            packet: 40,
            length: 3,
            missed_write: 0,
            missed_read: 0,
        };
        unsafe {
            on_data((&mut q as *mut Queue).cast(), &d);
            on_data((&mut q as *mut Queue).cast(), &d);
        }
        assert_eq!(q.dropped.load(Ordering::Relaxed), 1);
        assert_eq!(receiver.try_recv().unwrap().bytes, vec![1, 2, 3]);
        d.packet = u32::MAX;
        unsafe {
            on_data((&mut q as *mut Queue).cast(), &d);
        }
        assert!(receiver.try_recv().is_err());
        assert_eq!(q.dropped.load(Ordering::Relaxed), 2);
        let loss = q.loss.snapshot();
        assert_eq!(loss.queue_full, 1);
        assert_eq!(loss.invalid_records, 1);
        assert_eq!(loss.scope_rejected, 0);
    }
    #[test]
    fn writer_never_crosses_file_cap() {
        let packet = Packet {
            kind: 1,
            timestamp: 116444736000000000,
            bytes: vec![1, 2, 3],
        };
        let state = Arc::new(Mutex::new(CaptureStatus::default()));
        let mut output = Vec::new();
        let mut written = MAX_BYTES - 35;
        assert!(!store(&mut output, &packet, &mut written, &state).unwrap());
        assert!(output.is_empty());
        assert_eq!(state.lock().packets, 0);
        written = MAX_BYTES - 36;
        assert!(store(&mut output, &packet, &mut written, &state).unwrap());
        assert_eq!(written, MAX_BYTES);
        assert_eq!(state.lock().packets, 1);
    }
    #[test]
    fn scoped_callback_rejects_packets_before_queueing() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let endpoint = Endpoint {
            local_ip: "192.0.2.1".parse().unwrap(),
            remote_ip: "192.0.2.2".parse().unwrap(),
            local_port: 1234,
            remote_port: 443,
            protocol: 6,
        };
        let mut q = Queue {
            endpoint: Some(endpoint),
            sender,
            dropped: AtomicU64::new(0),
            loss: LossCounters::default(),
            fatal: AtomicBool::new(false),
        };
        let mut bytes = vec![0u8; 80];
        bytes[14..16].copy_from_slice(&3u16.to_le_bytes());
        bytes[32..40].copy_from_slice(&116444736000000000i64.to_le_bytes());
        let ip = &mut bytes[40..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&40u16.to_be_bytes());
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[192, 0, 2, 2]);
        ip[20..22].copy_from_slice(&443u16.to_be_bytes());
        ip[22..24].copy_from_slice(&1234u16.to_be_bytes());
        ip[32] = 0x50;
        let d = Descriptor {
            data: bytes.as_ptr(),
            size: 80,
            metadata: 0,
            packet: 40,
            length: 40,
            missed_read: 0,
            missed_write: 0,
        };
        unsafe {
            on_data((&mut q as *mut Queue).cast(), &d);
        }
        assert!(receiver.try_recv().is_err());
        assert_eq!(q.dropped.load(Ordering::Relaxed), 1);
        assert_eq!(q.loss.snapshot().scope_rejected, 1);
        assert_eq!(q.loss.snapshot().unsupported_frames, 0);
        bytes[60..62].copy_from_slice(&1234u16.to_be_bytes());
        bytes[62..64].copy_from_slice(&443u16.to_be_bytes());
        unsafe {
            on_data((&mut q as *mut Queue).cast(), &d);
        }
        assert_eq!(receiver.try_recv().unwrap().bytes.len(), 40);
    }
    #[test]
    fn os_constraint_has_both_endpoints_and_protocol() {
        let endpoint = Endpoint {
            local_ip: "192.0.2.1".parse().unwrap(),
            remote_ip: "192.0.2.2".parse().unwrap(),
            local_port: 1234,
            remote_port: 443,
            protocol: 6,
        };
        let c = Constraint::endpoint(&endpoint);
        assert_eq!(
            c.flags,
            (1 << 5) | (1 << 6) | (1 << 7) | (1 << 11) | (1 << 12)
        );
        assert_eq!(c.protocol, 6);
        assert_eq!(&c.ip1.0[..4], &[192, 0, 2, 1]);
        assert_eq!(&c.ip2.0[..4], &[192, 0, 2, 2]);
        assert_eq!(c.port1, 1234);
        assert_eq!(c.port2, 443);
    }
}
