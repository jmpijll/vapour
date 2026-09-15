use serde::{Deserialize, Serialize};
use windows::Win32::NetworkManagement::IpHelper::MIB_IF_ROW2;

/// Direct adapter observations. Counters are decimal strings to preserve u64
/// precision in JavaScript, and are lifetime totals reported by the driver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterDetails {
    pub source: String,
    pub interface_guid: String,
    pub interface_index: u32,
    pub mtu_bytes: Option<u32>,
    pub operational_status: String,
    pub administrative_status: String,
    pub media_state: String,
    pub interface_type_code: u32,
    pub physical_medium_code: i32,
    pub tunnel_type_code: i32,
    pub hardware_interface: bool,
    pub connector_present: bool,
    pub filter_interface: bool,
    pub paused: bool,
    pub low_power: bool,
    pub counters: AdapterCounters,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterCounters {
    pub received_bytes: String,
    pub sent_bytes: String,
    pub received_unicast_packets: String,
    pub sent_unicast_packets: String,
    pub received_non_unicast_packets: String,
    pub sent_non_unicast_packets: String,
    pub receive_errors: String,
    pub transmit_errors: String,
    pub receive_discards: String,
    pub transmit_discards: String,
    pub unknown_protocol_packets: String,
}
pub fn details(row: &MIB_IF_ROW2) -> AdapterDetails {
    let flags = row.InterfaceAndOperStatusFlags._bitfield;
    AdapterDetails {
        source: "windows_mib_if_row2".into(),
        interface_guid: format!("{:?}", row.InterfaceGuid),
        interface_index: row.InterfaceIndex,
        mtu_bytes: (row.Mtu > 0).then_some(row.Mtu),
        operational_status: match row.OperStatus.0 { 1 => "up", 2 => "down", 3 => "testing", 4 => "unknown", 5 => "dormant", 6 => "not_present", 7 => "lower_layer_down", _ => "unknown" }.into(),
        administrative_status: match row.AdminStatus.0 { 1 => "up", 2 => "down", 3 => "testing", _ => "unknown" }.into(),
        media_state: match row.MediaConnectState.0 { 1 => "connected", 2 => "disconnected", _ => "unknown" }.into(),
        interface_type_code: row.Type,
        physical_medium_code: row.PhysicalMediumType.0,
        tunnel_type_code: row.TunnelType.0,
        hardware_interface: flags & 1 != 0,
        connector_present: flags & 4 != 0,
        filter_interface: flags & 2 != 0,
        paused: flags & 32 != 0,
        low_power: flags & 64 != 0,
        counters: AdapterCounters {
            received_bytes: row.InOctets.to_string(), sent_bytes: row.OutOctets.to_string(),
            received_unicast_packets: row.InUcastPkts.to_string(), sent_unicast_packets: row.OutUcastPkts.to_string(),
            received_non_unicast_packets: row.InNUcastPkts.to_string(), sent_non_unicast_packets: row.OutNUcastPkts.to_string(),
            receive_errors: row.InErrors.to_string(), transmit_errors: row.OutErrors.to_string(),
            receive_discards: row.InDiscards.to_string(), transmit_discards: row.OutDiscards.to_string(),
            unknown_protocol_packets: row.InUnknownProtos.to_string(),
        },
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Reads live Windows adapter metadata; run explicitly on Windows"]
    fn live_adapter_metadata_serializes_without_elevation() {
        use windows::Win32::NetworkManagement::IpHelper::{GetIfTable2, FreeMibTable, MIB_IF_TABLE2};
        unsafe {
            let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
            assert_eq!(GetIfTable2(&mut table).0, 0);
            assert!(!table.is_null());
            // Always release the table, including if validation below panics.
            struct TableGuard(*mut MIB_IF_TABLE2);
            impl Drop for TableGuard { fn drop(&mut self) { unsafe { FreeMibTable(self.0.cast()); } } }
            let _guard = TableGuard(table);
            let count = (*table).NumEntries as usize;
            let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
            for row in rows {
                let d = details(row);
                assert_eq!(d.interface_index, row.InterfaceIndex);
                assert_eq!(d.counters.received_bytes.parse::<u64>().unwrap(), row.InOctets);
                assert_eq!(d.counters.transmit_errors.parse::<u64>().unwrap(), row.OutErrors);
                assert!(serde_json::to_string(&d).is_ok());
            }
            println!("Validated metadata for {count} adapters; no identifiers logged");
        }
    }
    #[test]
    fn preserves_counter_precision_and_unknown_states() {
        let mut row = MIB_IF_ROW2::default();
        row.InOctets = u64::MAX;
        let result = details(&row);
        assert_eq!(result.counters.received_bytes, "18446744073709551615");
        assert_eq!(result.mtu_bytes, None);
        assert_eq!(result.operational_status, "unknown");
        assert_eq!(result.administrative_status, "unknown");
        assert_eq!(result.media_state, "unknown");
    }
    #[test]
    fn distinguishes_dormant_from_disabled_and_decodes_flags() {
        let mut row = MIB_IF_ROW2::default();
        row.OperStatus.0 = 5; row.AdminStatus.0 = 1; row.Mtu = 1500;
        row.InterfaceAndOperStatusFlags._bitfield = 1 | 4 | 64;
        let result = details(&row);
        assert_eq!(result.operational_status, "dormant");
        assert_eq!(result.administrative_status, "up");
        assert_eq!(result.mtu_bytes, Some(1500));
        assert!(result.hardware_interface && result.connector_present && result.low_power);
        assert!(!result.filter_interface && !result.paused);
    }
}
