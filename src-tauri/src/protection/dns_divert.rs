//! Active DNS transport. Separate from the passive app-capture driver handle.

use std::os::windows::ffi::OsStrExt;
use std::{
    ffi::{c_char, c_void, CString},
    path::Path,
    sync::Arc,
};

const MAX_PACKET: usize = 65_575;
type Handle = *mut c_void;
type Open = unsafe extern "C" fn(*const c_char, i32, i16, u64) -> Handle;
type Recv = unsafe extern "C" fn(Handle, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type Send = unsafe extern "C" fn(Handle, *const c_void, u32, *mut u32, *const Address) -> i32;
type Shutdown = unsafe extern "C" fn(Handle, u32) -> i32;
type Close = unsafe extern "C" fn(Handle) -> i32;
type Param = unsafe extern "C" fn(Handle, i32, u64) -> i32;
type Checksums = unsafe extern "C" fn(*mut c_void, u32, *mut Address, u64) -> i32;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(path: *const u16, file: Handle, flags: u32) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: Handle) -> i32;
    fn GetLastError() -> u32;
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Address {
    timestamp: i64,
    bits: u32,
    reserved: u32,
    data: [u8; 64],
}
impl Default for Address {
    fn default() -> Self {
        Self {
            timestamp: 0,
            bits: 0,
            reserved: 0,
            data: [0; 64],
        }
    }
}
impl Address {
    pub(crate) fn outbound(&self) -> bool {
        self.bits & (1 << 17) != 0
    }
    pub(crate) fn set_outbound(&mut self, outbound: bool) {
        self.bits = (self.bits & !(1 << 17)) | (u32::from(outbound) << 17);
    }
    pub(crate) fn interface(&self) -> (u32, u32) {
        (
            u32::from_ne_bytes(self.data[..4].try_into().unwrap()),
            u32::from_ne_bytes(self.data[4..8].try_into().unwrap()),
        )
    }
    pub(crate) fn set_interface(&mut self, index: u32, sub_index: u32) {
        self.data[..4].copy_from_slice(&index.to_ne_bytes());
        self.data[4..8].copy_from_slice(&sub_index.to_ne_bytes());
    }
    fn is_network_packet(&self) -> bool {
        self.bits & 0xffff == 0
    }
}

struct Api {
    module: usize,
    open: Open,
    recv: Recv,
    send: Send,
    shutdown: Shutdown,
    close: Close,
    param: Param,
    checksums: Checksums,
}
impl Drop for Api {
    fn drop(&mut self) {
        if self.module != 0 {
            unsafe {
                FreeLibrary(self.module as Handle);
            }
        }
    }
}
impl Api {
    fn load(path: &Path) -> Result<Arc<Self>, String> {
        if !path.is_absolute() {
            return Err("Driver library path must be absolute".into());
        }
        let wide: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let module = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), 0x100 | 0x800) };
        if module.is_null() {
            return Err(native_error("load driver library"));
        }
        unsafe fn symbol(module: Handle, name: &[u8]) -> Result<*mut c_void, String> {
            let address = GetProcAddress(module, name.as_ptr());
            if address.is_null() {
                Err("Driver library entry point missing".into())
            } else {
                Ok(address)
            }
        }
        let result = (|| unsafe {
            Ok(Self {
                module: module as usize,
                open: std::mem::transmute::<*mut c_void, Open>(symbol(module, b"WinDivertOpen\0")?),
                recv: std::mem::transmute::<*mut c_void, Recv>(symbol(module, b"WinDivertRecv\0")?),
                send: std::mem::transmute::<*mut c_void, Send>(symbol(module, b"WinDivertSend\0")?),
                shutdown: std::mem::transmute::<*mut c_void, Shutdown>(symbol(
                    module,
                    b"WinDivertShutdown\0",
                )?),
                close: std::mem::transmute::<*mut c_void, Close>(symbol(
                    module,
                    b"WinDivertClose\0",
                )?),
                param: std::mem::transmute::<*mut c_void, Param>(symbol(
                    module,
                    b"WinDivertSetParam\0",
                )?),
                checksums: std::mem::transmute::<*mut c_void, Checksums>(symbol(
                    module,
                    b"WinDivertHelperCalcChecksums\0",
                )?),
            })
        })();
        if result.is_err() {
            unsafe {
                FreeLibrary(module);
            }
        }
        result.map(Arc::new)
    }
}

fn validate_filter(filter: &str) -> Result<CString, String> {
    if filter.trim().is_empty() || filter.len() > 4096 {
        return Err("DNS interception filter is empty or too large".into());
    }
    CString::new(filter).map_err(|_| "DNS interception filter contains NUL".into())
}
fn native_error(operation: &str) -> String {
    format!("Could not {operation} ({})", unsafe { GetLastError() })
}

/// No automatic elevation. Only the owning session may open this handle after
/// its proxy and upstream socket exclusions have been established.
/// Keep an Arc on the reader thread: the handle and DLL outlive any blocked
/// native receive. shutdown_receive interrupts receive without closing/reusing
/// its HANDLE underneath that call. The session must drain queued packets.
pub(crate) struct ActiveHandle {
    handle: usize,
    api: Arc<Api>,
}
impl ActiveHandle {
    pub(crate) fn open(runtime: &Path, filter: &str) -> Result<Arc<Self>, String> {
        let filter = validate_filter(filter)?;
        let path = crate::capture::stage_divert_runtime(runtime)?;
        Self::open_with_api(Api::load(&path)?, &filter)
    }
    fn open_with_api(api: Arc<Api>, filter: &CString) -> Result<Arc<Self>, String> {
        // Passive app capture at priority 0 sees the original tuple first.
        let handle = unsafe { (api.open)(filter.as_ptr(), 0, -1000, 0) };
        if handle.is_null() || handle as usize == usize::MAX {
            return Err(native_error("open DNS interception"));
        }
        let owned = Self {
            handle: handle as usize,
            api,
        };
        for (parameter, value) in [(0, 4096), (1, 2000), (2, 4 * 1024 * 1024)] {
            if unsafe { (owned.api.param)(handle, parameter, value) } == 0 {
                return Err(native_error("configure DNS interception queue"));
            }
        }
        Ok(Arc::new(owned))
    }
    pub(crate) fn receive(&self, buffer: &mut [u8]) -> Result<Option<(usize, Address)>, String> {
        if buffer.len() < MAX_PACKET {
            return Err("DNS receive buffer is too small".into());
        }
        let mut address = Address::default();
        let mut length = 0;
        let success = unsafe {
            (self.api.recv)(
                self.handle as Handle,
                buffer.as_mut_ptr().cast(),
                MAX_PACKET as u32,
                &mut length,
                &mut address,
            )
        };
        if success == 0 {
            let error = unsafe { GetLastError() };
            return if error == 232 {
                Ok(None)
            } else {
                Err(format!("DNS interception receive failed ({error})"))
            };
        }
        if length == 0 || length as usize > MAX_PACKET || !address.is_network_packet() {
            return Err("Invalid DNS interception packet metadata".into());
        }
        Ok(Some((length as usize, address)))
    }
    /// Forward an unchanged captured packet, preserving checksum-offload flags.
    pub(crate) fn reinject(&self, packet: &[u8], address: &Address) -> Result<(), String> {
        if packet.is_empty() || packet.len() > MAX_PACKET || !address.is_network_packet() {
            return Err("Invalid DNS packet for injection".into());
        }
        let mut sent = 0;
        if unsafe {
            (self.api.send)(
                self.handle as Handle,
                packet.as_ptr().cast(),
                packet.len() as u32,
                &mut sent,
                address,
            )
        } == 0
        {
            return Err(native_error("inject DNS packet"));
        }
        if sent as usize != packet.len() {
            return Err("Incomplete DNS packet injection".into());
        }
        Ok(())
    }
    pub(crate) fn send_modified(
        &self,
        packet: &mut [u8],
        address: &mut Address,
    ) -> Result<(), String> {
        super::dns_packet::decode(packet).map_err(|_| "Invalid modified DNS packet")?;
        if !address.is_network_packet() {
            return Err("Invalid DNS injection layer".into());
        }
        if unsafe {
            (self.api.checksums)(packet.as_mut_ptr().cast(), packet.len() as u32, address, 0)
        } == 0
        {
            return Err("DNS packet checksum calculation failed".into());
        }
        self.reinject(packet, address)
    }
    pub(crate) fn shutdown_receive(&self) -> Result<(), String> {
        if unsafe { (self.api.shutdown)(self.handle as Handle, 1) } == 0 {
            return Err(native_error("stop DNS interception"));
        }
        Ok(())
    }
}
impl Drop for ActiveHandle {
    fn drop(&mut self) {
        unsafe {
            (self.api.close)(self.handle as Handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    static SERIAL: Mutex<()> = Mutex::new(());
    static FAKE: Mutex<Fake> = Mutex::new(Fake {
        closes: 0,
        fail_param: false,
        short_send: false,
        checksum_failure: false,
        sends: 0,
        recv_length: 28,
        shutdown: 0,
    });
    struct Fake {
        closes: usize,
        fail_param: bool,
        short_send: bool,
        checksum_failure: bool,
        sends: usize,
        recv_length: u32,
        shutdown: u32,
    }
    unsafe extern "C" fn open(_: *const c_char, layer: i32, priority: i16, flags: u64) -> Handle {
        assert_eq!((layer, priority, flags), (0, -1000, 0));
        1usize as Handle
    }
    unsafe extern "C" fn recv(
        _: Handle,
        _: *mut c_void,
        capacity: u32,
        length: *mut u32,
        address: *mut Address,
    ) -> i32 {
        assert_eq!(capacity, MAX_PACKET as u32);
        *length = FAKE.lock().unwrap().recv_length;
        *address = Address::default();
        1
    }
    unsafe extern "C" fn send(
        _: Handle,
        _: *const c_void,
        length: u32,
        sent: *mut u32,
        _: *const Address,
    ) -> i32 {
        let mut fake = FAKE.lock().unwrap();
        fake.sends += 1;
        *sent = if fake.short_send { length - 1 } else { length };
        1
    }
    unsafe extern "C" fn shutdown(_: Handle, how: u32) -> i32 {
        FAKE.lock().unwrap().shutdown = how;
        1
    }
    unsafe extern "C" fn close(_: Handle) -> i32 {
        FAKE.lock().unwrap().closes += 1;
        1
    }
    unsafe extern "C" fn param(_: Handle, _: i32, _: u64) -> i32 {
        i32::from(!FAKE.lock().unwrap().fail_param)
    }
    unsafe extern "C" fn checksums(_: *mut c_void, _: u32, _: *mut Address, _: u64) -> i32 {
        i32::from(!FAKE.lock().unwrap().checksum_failure)
    }
    fn api() -> Arc<Api> {
        Arc::new(Api {
            module: 0,
            open,
            recv,
            send,
            shutdown,
            close,
            param,
            checksums,
        })
    }
    fn reset() {
        *FAKE.lock().unwrap() = Fake {
            closes: 0,
            fail_param: false,
            short_send: false,
            checksum_failure: false,
            sends: 0,
            recv_length: 28,
            shutdown: 0,
        };
    }

    #[test]
    fn failed_setup_closes_the_handle_and_reader_ownership_delays_normal_close() {
        let _serial = SERIAL.lock().unwrap();
        reset();
        let filter = validate_filter("udp.DstPort == 53001").unwrap();
        FAKE.lock().unwrap().fail_param = true;
        assert!(ActiveHandle::open_with_api(api(), &filter).is_err());
        assert_eq!(FAKE.lock().unwrap().closes, 1);
        reset();
        let handle = ActiveHandle::open_with_api(api(), &filter).unwrap();
        let reader = handle.clone();
        handle.shutdown_receive().unwrap();
        assert_eq!(FAKE.lock().unwrap().shutdown, 1);
        drop(handle);
        assert_eq!(FAKE.lock().unwrap().closes, 0);
        drop(reader);
        assert_eq!(FAKE.lock().unwrap().closes, 1);
    }

    #[test]
    fn malformed_receive_short_send_and_checksum_failure_are_not_success() {
        let _serial = SERIAL.lock().unwrap();
        reset();
        let handle = ActiveHandle::open_with_api(api(), &validate_filter("udp").unwrap()).unwrap();
        assert!(handle.receive(&mut [0; 10]).is_err());
        let mut buffer = vec![0; MAX_PACKET];
        FAKE.lock().unwrap().recv_length = MAX_PACKET as u32 + 1;
        assert!(handle.receive(&mut buffer).is_err());
        FAKE.lock().unwrap().recv_length = 0;
        assert!(handle.receive(&mut buffer).is_err());
        FAKE.lock().unwrap().recv_length = 28;
        assert_eq!(handle.receive(&mut buffer).unwrap().unwrap().0, 28);
        assert!(handle.reinject(&[], &Address::default()).is_err());
        FAKE.lock().unwrap().short_send = true;
        assert!(handle.reinject(&[1, 2], &Address::default()).is_err());
        FAKE.lock().unwrap().short_send = false;
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = 17;
        packet[24..26].copy_from_slice(&8u16.to_be_bytes());
        FAKE.lock().unwrap().checksum_failure = true;
        assert!(handle
            .send_modified(&mut packet, &mut Address::default())
            .is_err());
        assert_eq!(FAKE.lock().unwrap().sends, 1);
        FAKE.lock().unwrap().checksum_failure = false;
        handle
            .send_modified(&mut packet, &mut Address::default())
            .unwrap();
        assert_eq!(FAKE.lock().unwrap().sends, 2);
    }

    #[test]
    fn address_reversal_preserves_interface_and_driver_metadata() {
        let mut address = Address::default();
        address.bits = (1 << 17) | (1 << 19) | (1 << 20);
        address.data[..4].copy_from_slice(&7u32.to_ne_bytes());
        address.data[4..8].copy_from_slice(&3u32.to_ne_bytes());
        assert_eq!(std::mem::size_of::<Address>(), 80);
        assert!(address.outbound());
        address.set_outbound(false);
        assert!(!address.outbound());
        assert_eq!(address.interface(), (7, 3));
        assert_eq!(address.bits, (1 << 19) | (1 << 20));
        address.set_interface(11, 2);
        assert_eq!(address.interface(), (11, 2));
        assert_eq!(address.bits, (1 << 19) | (1 << 20));
    }

    #[test]
    fn filter_input_rejects_empty_overlong_or_nul_before_loading_driver() {
        for filter in ["", "  ", "udp\0or tcp", &"x".repeat(4097)] {
            assert!(validate_filter(filter).is_err());
        }
        assert!(validate_filter("outbound and udp.DstPort == 53001").is_ok());
    }

    /// Opt-in only: this opens an active driver handle, not a mock. The filter
    /// matches only the ephemeral loopback socket owned by this test.
    #[test]
    #[ignore = "requires an explicitly scheduled elevated Windows driver test"]
    fn native_loopback_udp_tcp_passthrough_and_cleanup() {
        use std::{
            io::{Read, Write},
            net::{TcpListener, TcpStream, UdpSocket},
            sync::atomic::{AtomicUsize, Ordering},
            thread,
            time::{Duration, Instant},
        };
        struct Reader {
            handle: Option<Arc<ActiveHandle>>,
            thread: Option<thread::JoinHandle<Result<(), String>>>,
            count: Arc<AtomicUsize>,
        }
        impl Reader {
            fn start(runtime: &Path, filter: &str) -> Self {
                let handle = ActiveHandle::open(runtime, filter).unwrap();
                let reading = handle.clone();
                let count = Arc::new(AtomicUsize::new(0));
                let seen = count.clone();
                let worker = thread::spawn(move || {
                    let mut buffer = vec![0; MAX_PACKET];
                    while let Some((length, mut address)) = reading.receive(&mut buffer)? {
                        reading.send_modified(&mut buffer[..length], &mut address)?;
                        seen.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(())
                });
                Self {
                    handle: Some(handle),
                    thread: Some(worker),
                    count,
                }
            }
            fn stop(&mut self) -> Result<(), String> {
                if let Some(handle) = &self.handle {
                    handle.shutdown_receive()?;
                }
                let deadline = Instant::now() + Duration::from_secs(2);
                if let Some(worker) = self.thread.as_ref() {
                    while !worker.is_finished() && Instant::now() < deadline {
                        thread::sleep(Duration::from_millis(5));
                    }
                    if !worker.is_finished() {
                        return Err("Driver receive did not stop".into());
                    }
                }
                if let Some(worker) = self.thread.take() {
                    worker.join().map_err(|_| "Driver reader panicked")??;
                }
                self.handle.take();
                Ok(())
            }
        }
        impl Drop for Reader {
            fn drop(&mut self) {
                let _ = self.stop();
            }
        }
        let runtime =
            std::env::temp_dir().join(format!("vapour-dns-driver-probe-{}", std::process::id()));
        for ip in ["127.0.0.1", "::1"] {
            let bind: std::net::SocketAddr =
                format!("{}:0", if ip == "::1" { "[::1]" } else { ip })
                    .parse()
                    .unwrap();
            let server = UdpSocket::bind(bind).unwrap();
            let client = UdpSocket::bind(bind).unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let port = server.local_addr().unwrap().port();
            let mut reader = Reader::start(
                &runtime,
                &format!("loopback and udp and (udp.SrcPort == {port} or udp.DstPort == {port})"),
            );
            let mut bytes = [0; 64];
            client
                .send_to(b"dns-driver-request", server.local_addr().unwrap())
                .unwrap();
            let (size, peer) = server.recv_from(&mut bytes).unwrap();
            assert_eq!(&bytes[..size], b"dns-driver-request");
            server.send_to(b"dns-driver-reply", peer).unwrap();
            let size = client.recv(&mut bytes).unwrap();
            assert_eq!(&bytes[..size], b"dns-driver-reply");
            // An unrelated socket continues to work while interception is active.
            let control = UdpSocket::bind(bind).unwrap();
            control
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            client
                .send_to(b"control", control.local_addr().unwrap())
                .unwrap();
            assert_eq!(control.recv(&mut bytes).unwrap(), 7);
            reader.stop().unwrap();
            assert_eq!(reader.count.load(Ordering::SeqCst), 2);
            client
                .send_to(b"after-close", server.local_addr().unwrap())
                .unwrap();
            assert_eq!(server.recv(&mut bytes).unwrap(), 11);

            let listener = TcpListener::bind(bind).unwrap();
            listener.set_nonblocking(true).unwrap();
            let endpoint = listener.local_addr().unwrap();
            let port = endpoint.port();
            let mut reader = Reader::start(
                &runtime,
                &format!("loopback and tcp and (tcp.SrcPort == {port} or tcp.DstPort == {port})"),
            );
            let mut client = TcpStream::connect_timeout(&endpoint, Duration::from_secs(2)).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut server = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("Test accept failed: {error}"),
                }
            };
            for stream in [&client, &server] {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
            }
            client.write_all(b"request").unwrap();
            let mut request = [0; 7];
            server.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"request");
            server.write_all(b"reply").unwrap();
            let mut reply = [0; 5];
            client.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"reply");
            reader.stop().unwrap();
            assert!(reader.count.load(Ordering::SeqCst) >= 5);
            client.write_all(b"request").unwrap();
            server.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"request");
        }
    }
}
