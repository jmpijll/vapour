use super::{
    tag_database::{DatasetStatus, DbIpRelease, TagDatabase},
    NetworkMonitor,
};
use std::{path::PathBuf, sync::Arc, time::Duration};

#[repr(C)]
#[derive(Default)]
struct SystemTimeFields {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    millisecond: u16,
}
#[link(name = "kernel32")]
extern "system" {
    fn GetSystemTime(time: *mut SystemTimeFields);
}
fn current_release() -> Result<DbIpRelease, String> {
    let mut time = SystemTimeFields::default();
    unsafe {
        GetSystemTime(&mut time);
    }
    DbIpRelease::new(time.year, time.month as u8).map_err(|e| e.to_string())
}
/// Slow disk/decompression/network work never runs on the telemetry sampler.
pub fn start(monitor: &Arc<NetworkMonitor>, path: PathBuf) -> Result<(), String> {
    let monitor = Arc::downgrade(monitor);
    std::thread::Builder::new().name("vapour-destination-database".into()).spawn(move||{
        let database=TagDatabase::new(path);
        let mut snapshot=database.load_last_good();
        if let Some(target)=monitor.upgrade(){target.set_destination_tags(snapshot.cache());}else{return;}
        loop {
            if let Ok(release)=current_release(){
                let current=matches!(&snapshot.status,DatasetStatus::Ready(metadata) if metadata.release==release);
                if !current {
                    match database.refresh(release) {
                        Ok(updated)=>{snapshot=updated;if let Some(target)=monitor.upgrade(){target.set_destination_tags(snapshot.cache());}else{return;}}
                        Err(error)=>log::warn!("Destination database refresh unavailable: {}",error),
                    }
                }
            }
            // Failed downloads retry daily; a valid monthly pair is reused.
            for _ in 0..1440 {if monitor.strong_count()==0{return;}std::thread::sleep(Duration::from_secs(60));}
        }
    }).map(|_|()).map_err(|_|"Destination database worker unavailable".into())
}
