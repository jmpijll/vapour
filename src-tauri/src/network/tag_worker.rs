use super::{
    tag_database::{DatasetStatus, DbIpRelease, TagDatabase},
    NetworkMonitor,
};
use std::{path::PathBuf, sync::Arc, time::Duration};

/// Slow disk/decompression/network work never runs on the telemetry sampler.
pub fn start(monitor: &Arc<NetworkMonitor>, path: PathBuf) -> Result<(), String> {
    let monitor = Arc::downgrade(monitor);
    std::thread::Builder::new().name("vapour-destination-database".into()).spawn(move||{
        let database=TagDatabase::new(path);
        let mut snapshot=database.load_last_good();
        if let Some(target)=monitor.upgrade(){target.set_destination_tags(snapshot.cache());}else{return;}
        loop {
            if let Ok(release)=DbIpRelease::current_utc(){
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Downloads current official country/ASN databases into explicit VAPOUR_DBIP_CACHE"]
    fn live_monthly_download_loads_real_tags() {
        let path = std::env::var_os("VAPOUR_DBIP_CACHE").expect("explicit cache path required");
        let database = TagDatabase::new(PathBuf::from(path));
        let snapshot = database
            .refresh_current()
            .expect("current official dataset download");
        let cache = snapshot.cache();
        for address in ["1.1.1.1", "2606:4700:4700::1111"] {
            let result = cache.lookup(address.parse().unwrap());
            assert_eq!(
                result.status,
                super::super::destination_tags::DestinationTagStatus::Known
            );
            let tags = result.tags.expect("real dataset tags");
            assert!(tags.country_code.is_some());
            assert!(tags.asn.is_some());
            assert!(tags.organization.is_some());
        }
        let loaded = database
            .try_load_last_good()
            .unwrap()
            .expect("persisted database");
        assert!(matches!(loaded.status, DatasetStatus::Ready(_)));
        println!("Current DB-IP pair downloaded, persisted and queried for IPv4/IPv6");
    }
    #[test]
    #[ignore = "Uses installed VAPOUR_DBIP_CACHE and opens one public TCP test connection"]
    fn live_session_snapshot_contains_offline_tags() {
        let path = std::env::var_os("VAPOUR_DBIP_CACHE").expect("explicit cache path required");
        let dataset = TagDatabase::new(PathBuf::from(path))
            .try_load_last_good()
            .unwrap()
            .expect("installed database");
        let monitor = NetworkMonitor::new();
        monitor.set_destination_tags(dataset.cache());
        let connection = std::net::TcpStream::connect_timeout(
            &"1.1.1.1:443".parse().unwrap(),
            Duration::from_secs(3),
        )
        .expect("test endpoint reachable");
        let port = connection.local_addr().unwrap().port();
        let snapshot = monitor.capture_snapshot();
        let socket = snapshot
            .processes
            .iter()
            .flat_map(|p| &p.sockets)
            .find(|s| s.local_port == port && s.remote_ip == "1.1.1.1" && s.remote_port == 443)
            .expect("native session in snapshot");
        let tags = socket.destination_tags.as_ref().expect("attached tags");
        assert_eq!(
            tags.status,
            super::super::destination_tags::DestinationTagStatus::Known
        );
        assert!(tags.tags.as_ref().unwrap().organization.is_some());
        monitor.stop();
        println!("Native session snapshot includes verified offline country/ASN tags");
    }
}
