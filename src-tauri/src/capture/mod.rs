//! Bounded, user-started interface capture. No global Pktmon session or filters.
mod endpoint;
mod bind_snapshot;
mod tcp_snapshot;
mod native;
mod packet;
mod attribution;
mod generation;
mod raw;
mod app;
mod windivert;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread::JoinHandle,
};

pub const MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_SECONDS: u64 = 60;
static NEXT_RUN: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Debug, Serialize)]
pub struct CaptureInterface {
    pub id: u32,
    pub name: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTarget {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub protocol: String,
}
impl SessionTarget {
    pub fn validate(&self) -> Result<(), String> {
        self.endpoint().map(|_| ())
    }
    fn endpoint(&self) -> Result<endpoint::Endpoint, String> {
        use std::net::IpAddr;
        let local_ip: IpAddr = self
            .local_ip
            .parse()
            .map_err(|_| "Invalid local capture address")?;
        let remote_ip: IpAddr = self
            .remote_ip
            .parse()
            .map_err(|_| "Invalid remote capture address")?;
        let valid = |ip: IpAddr| {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && match ip {
                    IpAddr::V4(v) => !v.is_broadcast(),
                    IpAddr::V6(v) => v.to_ipv4_mapped().is_none(),
                }
        };
        if local_ip.is_ipv4() != remote_ip.is_ipv4()
            || !valid(local_ip)
            || !valid(remote_ip)
            || self.local_port == 0
            || self.remote_port == 0
        {
            return Err(
                "Capture requires two concrete endpoints in the same address family".into(),
            );
        }
        let protocol = match self.protocol.as_str() {
            "TCP" => 6,
            "UDP" => 17,
            _ => return Err("Unsupported capture protocol".into()),
        };
        Ok(endpoint::Endpoint {
            local_ip,
            local_port: self.local_port,
            remote_ip,
            remote_port: self.remote_port,
            protocol,
        })
    }
}
/// Diagnostic counts preserve the legacy `dropped` aggregate. Warnings and
/// intentional scope exclusions are not necessarily lost packets.
#[derive(Clone, Debug, Default, Serialize)]
pub struct CaptureLossDetails {
    pub native_missed_read: u64,
    pub native_missed_write: u64,
    pub stream_warnings: u64,
    pub stream_last_reason: u64,
    pub stream_max_packet_length: u64,
    pub invalid_records: u64,
    pub unsupported_frames: u64,
    pub scope_rejected: u64,
    pub queue_full: u64,
    pub size_limit: u64,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct CaptureStatus {
    pub partial: bool,
    pub native_loss_available: bool,
    pub finalizing: bool,
    pub scope_label: Option<String>,
    pub run_id: u64,
    pub target: Option<SessionTarget>,
    pub active: bool,
    pub packets: u64,
    pub bytes: u64,
    pub dropped: u64,
    pub loss_details: CaptureLossDetails,
    pub duration_ms: u64,
    pub path: Option<String>,
    pub error: Option<String>,
}
struct Worker {
    cancel: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}
#[derive(Default)]
pub struct CaptureManager {
    started: Mutex<Option<std::time::Instant>>,
    worker: Mutex<Option<Worker>>,
    state: Arc<Mutex<CaptureStatus>>,
}
pub fn list_interfaces() -> Result<Vec<CaptureInterface>, String> {
    native::list_interfaces()
}
impl CaptureManager {
    pub fn start_app(&self, output: PathBuf, runtime: PathBuf, path: String, pids: Vec<u32>) -> Result<CaptureStatus,String> {
        if !output.is_absolute() || pids.is_empty() || pids.len()>64 {return Err("App capture requires a running app".into());}
        let identities=pids.into_iter().map(|pid|app::resolve(pid,&path)).collect::<Result<Vec<_>,_>>()?;
        let dll=app::stage(&runtime)?;
        let mut worker=self.worker.lock();
        if self.state.lock().active{return Err("A capture is already running".into());}
        if let Some(previous)=worker.take(){let _=previous.thread.join();}
        let cancel=Arc::new(AtomicBool::new(false));let cancellation=cancel.clone();let state=self.state.clone();
        let started=std::time::Instant::now();*self.started.lock()=Some(started);
        *state.lock()=CaptureStatus {active:true,partial:true,scope_label:Some(path),run_id:NEXT_RUN.fetch_add(1,Ordering::Relaxed),..Default::default()};
        let (ready,receive)=std::sync::mpsc::sync_channel(1);
        let thread=std::thread::Builder::new().name("vapour-app-capture".into()).spawn(move||{
            let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||app::capture(&dll,&output,identities,&cancellation,&state,ready)));
            let mut status=state.lock();status.active=false;status.finalizing=false;status.duration_ms=started.elapsed().as_millis() as u64;
            match result {Ok(Ok(()))=>{},Ok(Err(e))=>{status.error=Some(e);status.path=None;},Err(_)=>{status.error=Some("App capture stopped unexpectedly".into());status.path=None;}}
        }).map_err(|e|{self.state.lock().active=false;e.to_string()})?;
        *worker=Some(Worker{cancel,thread});
        match receive.recv(){Ok(Ok(()))=>Ok(self.status()),Ok(Err(e))=>Err(e),Err(_)=>Err(self.status().error.unwrap_or_else(||"App capture could not start".into()))}
    }
    /// Caller supplies a newly generated path in its private capture cache.
    pub fn start(&self, interface_id: u32, output: PathBuf) -> Result<CaptureStatus, String> {
        self.start_scoped(interface_id, output, None)
    }
    pub fn start_session(
        &self,
        interface_id: u32,
        output: PathBuf,
        target: SessionTarget,
    ) -> Result<CaptureStatus, String> {
        target.validate()?;
        self.start_scoped(interface_id, output, Some(target))
    }
    fn start_scoped(
        &self,
        interface_id: u32,
        output: PathBuf,
        target: Option<SessionTarget>,
    ) -> Result<CaptureStatus, String> {
        let endpoint = target.as_ref().map(SessionTarget::endpoint).transpose()?;
        if !output.is_absolute() {
            return Err("Capture path must be absolute".into());
        }
        let mut worker = self.worker.lock();
        if self.state.lock().active {
            return Err("A capture is already running".into());
        }
        if let Some(previous) = worker.take() {
            let _ = previous.thread.join();
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let cancellation = cancel.clone();
        let state = self.state.clone();
        *self.started.lock()=Some(std::time::Instant::now());
        *state.lock() = CaptureStatus {
            active: true,
            native_loss_available: true,
            run_id: NEXT_RUN.fetch_add(1, Ordering::Relaxed),
            target,
            ..Default::default()
        };
        let (ready, receive) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("vapour-capture".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    native::capture(
                        interface_id,
                        &output,
                        &cancellation,
                        &state,
                        ready,
                        endpoint,
                    )
                }));
                let error = match result {
                    Ok(Ok(())) => None,
                    Ok(Err(e)) => Some(e),
                    Err(_) => Some("Capture worker stopped unexpectedly".into()),
                };
                let mut status = state.lock();
                status.active = false;
                if let Some(error) = error {
                    status.error = Some(error);
                    status.path = None;
                }
            })
            .map_err(|e| {
                self.state.lock().active = false;
                e.to_string()
            })?;
        *worker = Some(Worker { cancel, thread });
        match receive.recv() {
            Ok(Ok(())) => Ok(self.status()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(self
                .status()
                .error
                .unwrap_or_else(|| "Capture could not start".into())),
        }
    }
    pub fn stop(&self) -> CaptureStatus {
        self.stop_matching(None)
    }
    pub fn stop_run(&self, run_id: u64) -> CaptureStatus {
        self.stop_matching(Some(run_id))
    }
    fn stop_matching(&self, run_id: Option<u64>) -> CaptureStatus {
        let mut worker = self.worker.lock();
        if run_id.is_some_and(|id| self.state.lock().run_id != id) {
            return self.status();
        }
        if let Some(worker) = worker.take() {
            worker.cancel.store(true, Ordering::Release);
            let _ = worker.thread.join();
        }
        self.status()
    }
    pub fn status(&self) -> CaptureStatus {
        let mut status=self.state.lock().clone();
        if status.active {if let Some(started)=*self.started.lock(){status.duration_ms=started.elapsed().as_millis() as u64;}}
        status
    }
    /// Clear only the completed file that the caller successfully exported.
    /// A concurrent new run must retain its own state.
    pub fn exported(&self, path: &std::path::Path) {
        let mut state = self.state.lock();
        if !state.active && state.path.as_deref().map(std::path::Path::new) == Some(path) {
            state.path = None;
        }
    }
}
impl Drop for CaptureManager {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exporting_old_file_does_not_clear_new_capture() {
        let manager = CaptureManager::default();
        manager.state.lock().path = Some("C:/capture/new.pcapng".into());
        manager.exported(std::path::Path::new("C:/capture/old.pcapng"));
        assert!(manager.status().path.is_some());
        manager.state.lock().active = true;
        manager.exported(std::path::Path::new("C:/capture/new.pcapng"));
        assert!(manager.status().path.is_some());
        manager.state.lock().active = false;
        manager.exported(std::path::Path::new("C:/capture/new.pcapng"));
        assert!(manager.status().path.is_none());
    }
    #[test]
    fn validates_concrete_numeric_endpoints() {
        let target = SessionTarget {
            local_ip: "192.0.2.1".into(),
            remote_ip: "192.0.2.2".into(),
            local_port: 1234,
            remote_port: 443,
            protocol: "TCP".into(),
        };
        assert!(target.validate().is_ok());
        for ip in [
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "example.com",
            "::1",
            "192.0.2.2:443",
        ] {
            let mut t = target.clone();
            t.remote_ip = ip.into();
            assert!(t.validate().is_err(), "{ip}");
        }
        let mut t = target.clone();
        t.local_port = 0;
        assert!(t.validate().is_err());
        let mut t = target.clone();
        t.protocol = "ICMP".into();
        assert!(t.validate().is_err());
        let mut t = target;
        t.local_ip = "2001:db8::1".into();
        t.remote_ip = "2001:db8::2".into();
        assert!(t.validate().is_ok());
        for ip in ["::", "ff02::1", "::ffff:192.0.2.1"] {
            t.remote_ip = ip.into();
            assert!(t.validate().is_err());
        }
    }
    #[test]
    fn stale_run_stop_leaves_new_worker_untouched() {
        let manager = CaptureManager::default();
        let cancel = Arc::new(AtomicBool::new(false));
        *manager.worker.lock() = Some(Worker {
            cancel: cancel.clone(),
            thread: std::thread::spawn(|| {}),
        });
        manager.state.lock().run_id = 2;
        manager.stop_run(1);
        assert!(!cancel.load(Ordering::Acquire));
        assert!(manager.worker.lock().is_some());
        manager.stop_run(2);
        assert!(cancel.load(Ordering::Acquire));
        assert!(manager.worker.lock().is_none());
    }
}
