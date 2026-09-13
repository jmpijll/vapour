# Interface data for Basic and Advanced

The current page remains compact. Advanced presentation is future work; the data contract is prepared independently of its final layout.

## Collected now

The existing Windows interface sample includes an optional frontend `details` object, with source `windows_mib_if_row2`. Its timestamp is the enclosing snapshot timestamp. No additional polling, network request or permission prompt is introduced.

- Interface GUID and index, MTU, raw interface/physical-medium/tunnel type codes.
- Separate operational, administrative and media states; unknown enum values remain unknown.
- Hardware, connector, filter, paused and low-power flags reported by Windows.
- Driver cumulative byte, unicast/non-unicast packet, error, discard and unknown-protocol counters.
- Existing receive/transmit link rates remain separate from throughput.

Counters are decimal strings, preserving unsigned 64-bit values in JavaScript. Driver resets/reinitialization can reset them; do not describe these as lifetime usage or Vapour-session totals. Zero error counters do not prove that a driver supports all diagnostics. Error/discard totals do not measure internet packet loss. Hardware=false does not identify a VPN vendor or prove a specific virtualization technology.

The existing `is_default_gateway` is now nullable: interface type is not route evidence. IPv4/IPv6 fields are still unpopulated in native snapshots; do not invent addresses. The GUID and index are local identifiers, not stable device identity across reinstallation; redact them in shared diagnostics.

## Next acquisition layers

| Layer | Useful data | Acquisition and constraints |
| --- | --- | --- |
| IP configuration | All IPv4/IPv6 addresses and prefixes, DNS servers, DHCP state, gateway configuration | Cached GetAdaptersAddresses data. Keep lists, not one address per family. Refresh on change or a slower cadence. |
| Routing | Default routes, route and interface metrics, family and interface association | Read route tables. Multiple defaults and VPN routes are valid; destination routing can differ. |
| Wi-Fi quality | Link quality, PHY/radio information, per-link frequency/band where available | Prefer privacy-friendly realtime quality API; validate OS/driver support and result size before reading. No legacy fallback that prompts automatically. |
| Wi-Fi identity | SSID/BSSID and connection security | Explicit on-demand opt-in if needed; location-sensitive Windows APIs can deny access. Never require these to show generic adapter statistics. |
| Driver/device | Provider/version/date, PnP identity, duplex/autonegotiation/offload properties | Separate slower device query. Treat driver-specific properties as optional; never infer duplex from speed. |

Future optional collectors should return a reason such as unsupported, disconnected, permission_denied or query_failed, plus their own sample time. Do not reuse stale Wi-Fi values after a connection change. Basic/Advanced changes presentation, not consent: switching modes must not trigger a scan, network request or privacy prompt by itself.

## Validation

Unit tests cover unknown states, flag decoding and exact u64 counters. An explicit ignored native test (`live_adapter_metadata_serializes_without_elevation`) reads the real table and validates serialization without logging adapter identifiers. Browser builds remain compatible with demo snapshots that omit details.

## References

- [Microsoft MIB_IF_ROW2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2)
- [Microsoft Wi-Fi access and location changes](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes)
