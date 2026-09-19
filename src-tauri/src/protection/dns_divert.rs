//! Active DNS transport. Separate from the passive app-capture driver handle.

use std::os::windows::ffi::OsStrExt;
use std::{
    ffi::{c_char, c_void, CStr, CString},
    path::Path,
    sync::Arc,
};

const MAX_PACKET: usize = 65_575;
const MAX_FILTER_BYTES: usize = 32 * 1024;
type Handle = *mut c_void;
type Open = unsafe extern "C" fn(*const c_char, i32, i16, u64) -> Handle;
type Recv = unsafe extern "C" fn(Handle, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type Send = unsafe extern "C" fn(Handle, *const c_void, u32, *mut u32, *const Address) -> i32;
type Shutdown = unsafe extern "C" fn(Handle, u32) -> i32;
type Close = unsafe extern "C" fn(Handle) -> i32;
type Param = unsafe extern "C" fn(Handle, i32, u64) -> i32;
type Checksums = unsafe extern "C" fn(*mut c_void, u32, *mut Address, u64) -> i32;
type CompileFilter =
    unsafe extern "C" fn(*const c_char, i32, *mut c_char, u32, *mut *const c_char, *mut u32) -> i32;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(path: *const u16, file: Handle, flags: u32) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: Handle) -> i32;
    fn GetLastError() -> u32;
    #[cfg(test)]
    fn SetLastError(error: u32);
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
    compile_filter: CompileFilter,
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
                compile_filter: std::mem::transmute::<*mut c_void, CompileFilter>(symbol(
                    module,
                    b"WinDivertHelperCompileFilter\0",
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

    fn compile_filter(&self, filter: &CString) -> Result<(), String> {
        let mut description = std::ptr::null();
        let mut position = 0;
        let success = unsafe {
            (self.compile_filter)(
                filter.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                &mut description,
                &mut position,
            )
        };
        if success != 0 {
            return Ok(());
        }
        // The official helper returns a static error string owned by this DLL.
        let message = if description.is_null() {
            "unknown filter error".into()
        } else {
            unsafe { CStr::from_ptr(description) }
                .to_string_lossy()
                .into_owned()
        };
        Err(format!(
            "Invalid DNS interception filter at {position}: {message}"
        ))
    }
}

fn validate_filter(filter: &str) -> Result<CString, String> {
    if filter.trim().is_empty() || filter.len() > MAX_FILTER_BYTES {
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
        api.compile_filter(filter)?;
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
    unsafe extern "C" fn compile_filter(
        _: *const c_char,
        _: i32,
        _: *mut c_char,
        _: u32,
        _: *mut *const c_char,
        _: *mut u32,
    ) -> i32 {
        1
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
            compile_filter,
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
        for filter in ["", "  ", "udp\0or tcp", &"x".repeat(MAX_FILTER_BYTES + 1)] {
            assert!(validate_filter(filter).is_err());
        }
        assert!(validate_filter("outbound and udp.DstPort == 53001").is_ok());
    }

    #[test]
    fn native_filter_compiler_validates_without_opening_driver() {
        let directory =
            std::env::temp_dir().join(format!("vapour-dns-filter-{}", std::process::id()));
        let path = crate::capture::stage_divert_runtime(&directory).unwrap();
        let api = Api::load(&path).unwrap();
        assert!(api
            .compile_filter(&validate_filter("outbound and udp.DstPort == 53").unwrap())
            .is_ok());
        assert!(api
            .compile_filter(&validate_filter("not_a_windivert_field == 1").unwrap())
            .is_err());
        drop(api);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn generated_filter_matches_only_covered_requests_and_owned_proxy_replies() {
        use crate::protection::dns_filter::{build_dns_filter, build_dns_filters, DnsFilterConfig};
        use std::net::{IpAddr, SocketAddr};
        type Evaluate =
            unsafe extern "C" fn(*const c_char, *const c_void, u32, *const Address) -> i32;

        // Loading and evaluating the user-mode helper never calls WinDivertOpen.
        let directory =
            std::env::temp_dir().join(format!("vapour-dns-filter-eval-{}", std::process::id()));
        let path = crate::capture::stage_divert_runtime(&directory).unwrap();
        let api = Api::load(&path).unwrap();
        let symbol = unsafe {
            GetProcAddress(
                api.module as Handle,
                b"WinDivertHelperEvalFilter\0".as_ptr(),
            )
        };
        assert!(!symbol.is_null());
        let evaluate: Evaluate = unsafe { std::mem::transmute(symbol) };
        let ips: Vec<IpAddr> = ["192.0.2.10", "2001:db8::10"]
            .into_iter()
            .map(|ip| ip.parse().unwrap())
            .collect();
        let mut config = DnsFilterConfig {
            local_ips: ips.clone(),
            udp_proxy_listeners: ips.iter().map(|ip| SocketAddr::new(*ip, 40000)).collect(),
            tcp_proxy_listeners: ips.iter().map(|ip| SocketAddr::new(*ip, 40001)).collect(),
            udp_upstreams: ips
                .iter()
                .flat_map(|ip| (41000..41008).map(move |port| SocketAddr::new(*ip, port)))
                .collect(),
            tcp_upstreams: ips
                .iter()
                .flat_map(|ip| (42000..42008).map(move |port| SocketAddr::new(*ip, port)))
                .collect(),
        };
        // A covered second IPv4 address owns different ports. A port exempt
        // on the first address must still be intercepted on this address.
        let second: IpAddr = "192.0.2.11".parse().unwrap();
        config.local_ips.push(second);
        config
            .udp_proxy_listeners
            .push(SocketAddr::new(second, 40002));
        config
            .tcp_proxy_listeners
            .push(SocketAddr::new(second, 40003));
        config
            .udp_upstreams
            .extend((43000..43008).map(|p| SocketAddr::new(second, p)));
        config
            .tcp_upstreams
            .extend((44000..44008).map(|p| SocketAddr::new(second, p)));
        let filter = validate_filter(&build_dns_filter(&config).unwrap()).unwrap();
        api.compile_filter(&filter)
            .unwrap_or_else(|error| panic!("{error}: {filter:?}"));
        for (local, remote, other) in [
            ("192.0.2.10", "198.51.100.53", "192.0.2.12"),
            ("2001:db8::10", "2001:db8:1::53", "2001:db8::11"),
        ] {
            for tcp in [false, true] {
                let owned = if tcp { 42000 } else { 41000 };
                let other_protocol_owned = if tcp { 41000 } else { 42000 };
                let proxy = if tcp { 40001 } else { 40000 };
                for (source, source_port, destination_port, outbound, expected) in [
                    (local, 45000, 53, true, true),
                    (local, owned, 53, true, false),
                    (local, owned + 7, 53, true, false),
                    (local, owned + 8, 53, true, true),
                    (local, other_protocol_owned, 53, true, true),
                    (other, 45000, 53, true, false),
                    (local, 45000, 443, true, false),
                    (local, 45000, 53, false, false),
                    (local, proxy, 45000, true, true),
                    (other, proxy, 45000, true, false),
                    (remote, 53, owned, false, false),
                ] {
                    let source = SocketAddr::new(source.parse().unwrap(), source_port);
                    let destination = SocketAddr::new(remote.parse().unwrap(), destination_port);
                    let packet = filter_fixture(source, destination, tcp);
                    let mut address = Address::default();
                    address.set_outbound(outbound);
                    address.set_interface(7, 0);
                    if source.is_ipv6() {
                        address.bits |= 1 << 20;
                    }
                    let actual = unsafe {
                        SetLastError(0);
                        evaluate(
                            filter.as_ptr(),
                            packet.as_ptr().cast(),
                            packet.len() as u32,
                            &address,
                        )
                    };
                    assert_eq!(
                        actual != 0,
                        expected,
                        "{source} -> {destination}, tcp={tcp}, outbound={outbound}"
                    );
                    // Win32 last-error is meaningful only on FALSE here;
                    // successful evaluation may leave an internal parser error.
                    if actual == 0 {
                        assert_eq!(unsafe { GetLastError() }, 0, "native error for {source} -> {destination}, tcp={tcp}, outbound={outbound}");
                    }
                }
            }
        }
        for tcp in [false, true] {
            let packet = filter_fixture(
                SocketAddr::new(second, if tcp { 42000 } else { 41000 }),
                "198.51.100.53:53".parse().unwrap(),
                tcp,
            );
            let mut address = Address::default();
            address.set_outbound(true);
            assert_ne!(
                unsafe {
                    evaluate(
                        filter.as_ptr(),
                        packet.as_ptr().cast(),
                        packet.len() as u32,
                        &address,
                    )
                },
                0
            );
        }
        let ips: Vec<IpAddr> = (1..=16)
            .map(|i| format!("2001:db8:{i:x}::1").parse().unwrap())
            .collect();
        let maximal = DnsFilterConfig {
            local_ips: ips.clone(),
            udp_proxy_listeners: ips.iter().map(|ip| SocketAddr::new(*ip, 40000)).collect(),
            tcp_proxy_listeners: ips.iter().map(|ip| SocketAddr::new(*ip, 40001)).collect(),
            udp_upstreams: ips
                .iter()
                .flat_map(|ip| (41000..41008).map(move |p| SocketAddr::new(*ip, p)))
                .collect(),
            tcp_upstreams: ips
                .iter()
                .flat_map(|ip| (42000..42008).map(move |p| SocketAddr::new(*ip, p)))
                .collect(),
        };
        let filters: Vec<_> = build_dns_filters(&maximal)
            .unwrap()
            .iter()
            .map(|filter| validate_filter(filter).unwrap())
            .collect();
        assert_eq!(filters.len(), 4);
        for filter in &filters {
            api.compile_filter(filter).unwrap();
        }
        for ip in ips {
            for tcp in [false, true] {
                for (port, expected_matches) in [(45000, 1), (if tcp { 42000 } else { 41000 }, 0)] {
                    let packet = filter_fixture(
                        SocketAddr::new(ip, port),
                        "[2001:db8:ff::53]:53".parse().unwrap(),
                        tcp,
                    );
                    let mut address = Address::default();
                    address.set_outbound(true);
                    address.bits |= 1 << 20;
                    let matches = filters.iter().filter(|filter| unsafe { evaluate(filter.as_ptr(), packet.as_ptr().cast(), packet.len() as u32, &address) } != 0).count();
                    assert_eq!(
                        matches, expected_matches,
                        "disjoint coverage for {ip}:{port}, tcp={tcp}"
                    );
                }
            }
        }
        let scoped = |port| {
            std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                "fe80::10".parse().unwrap(),
                port,
                0,
                7,
            ))
        };
        let scoped_config = DnsFilterConfig {
            local_ips: vec!["fe80::10".parse().unwrap()],
            udp_proxy_listeners: vec![scoped(40000)],
            tcp_proxy_listeners: vec![scoped(40001)],
            udp_upstreams: (41000..41008).map(scoped).collect(),
            tcp_upstreams: (42000..42008).map(scoped).collect(),
        };
        let filter = validate_filter(&build_dns_filter(&scoped_config).unwrap()).unwrap();
        api.compile_filter(&filter).unwrap();
        for (interface, expected) in [(7, true), (8, false)] {
            let mut address = Address::default();
            address.set_outbound(true);
            address.bits |= 1 << 20;
            address.set_interface(interface, 0);
            let packet = filter_fixture(
                "[fe80::10]:45000".parse().unwrap(),
                "[fe80::53]:53".parse().unwrap(),
                false,
            );
            assert_eq!(
                unsafe {
                    evaluate(
                        filter.as_ptr(),
                        packet.as_ptr().cast(),
                        packet.len() as u32,
                        &address,
                    )
                } != 0,
                expected
            );
        }
        drop(api);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn filter_fixture(
        source: std::net::SocketAddr,
        destination: std::net::SocketAddr,
        tcp: bool,
    ) -> Vec<u8> {
        use std::net::IpAddr;
        let header = if source.is_ipv4() { 20 } else { 40 };
        let transport = if tcp { 20 } else { 8 };
        let mut packet = vec![0; header + transport];
        let protocol = if tcp { 6 } else { 17 };
        match (source.ip(), destination.ip()) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&((header + transport) as u16).to_be_bytes());
                packet[8] = 64;
                packet[9] = protocol;
                packet[12..16].copy_from_slice(&source.octets());
                packet[16..20].copy_from_slice(&destination.octets());
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                packet[0] = 0x60;
                packet[4..6].copy_from_slice(&(transport as u16).to_be_bytes());
                packet[6] = protocol;
                packet[7] = 64;
                packet[8..24].copy_from_slice(&source.octets());
                packet[24..40].copy_from_slice(&destination.octets());
            }
            _ => panic!("fixture address-family mismatch"),
        }
        packet[header..header + 2].copy_from_slice(&source.port().to_be_bytes());
        packet[header + 2..header + 4].copy_from_slice(&destination.port().to_be_bytes());
        if tcp {
            packet[header + 12] = 5 << 4;
            packet[header + 13] = 2;
        } else {
            packet[header + 4..header + 6].copy_from_slice(&(transport as u16).to_be_bytes());
        }
        packet
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
