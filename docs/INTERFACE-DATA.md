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

The existing `is_default_gateway` is now nullable: interface type is not route evidence. Native IP configuration now contains all observed addresses/prefixes, DNS servers, configured gateways and per-family interface metrics. The legacy IPv4/IPv6 fields expose only the first address in each family. The GUID and index are local identifiers, not stable device identity across reinstallation; redact them in shared diagnostics.

## Next acquisition layers

| Layer | Useful data | Acquisition and constraints |
| --- | --- | --- |
| IP configuration | Implemented: all IPv4/IPv6 addresses and prefixes, DNS servers, gateway configuration, interface metrics. DHCPv4 enabled state and DHCPv4/v6 server addresses are also collected. Lease timers remain future work. | GetAdaptersAddresses cache, 30-second interval, own timestamp. Joined by LUID; query failure clears stale data. Configured gateways do not prove an active default route. |
| Routing | Implemented: destination prefixes, next hops, route metric offsets, protocol/origin and default-route markers | GetIpForwardTable2; 30-second cache with own timestamp. Multiple defaults and VPN routes remain distinct. Route metric is an offset, not the sum with interface metric. |
| Wi-Fi quality | Link quality, PHY/radio information, per-link frequency/band where available | Prefer privacy-friendly realtime quality API; validate OS/driver support and result size before reading. No legacy fallback that prompts automatically. |
| Wi-Fi identity | SSID/BSSID and connection security | Explicit on-demand opt-in if needed; location-sensitive Windows APIs can deny access. Never require these to show generic adapter statistics. |
| Driver/device | Provider/version/date, PnP identity, duplex/autonegotiation/offload properties | Separate slower device query. Treat driver-specific properties as optional; never infer duplex from speed. |

Future optional collectors should return a reason such as unsupported, disconnected, permission_denied or query_failed, plus their own sample time. Do not reuse stale Wi-Fi values after a connection change. Basic/Advanced changes presentation, not consent: switching modes must not trigger a scan, network request or privacy prompt by itself.

## Validation

Unit tests cover unknown states, flag decoding and exact u64 counters. An explicit ignored native test (`live_adapter_metadata_serializes_without_elevation`) reads the real table and validates serialization without logging adapter identifiers. Browser builds remain compatible with demo snapshots that omit details.

## References

- [Microsoft MIB_IF_ROW2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2)
- [Microsoft Wi-Fi access and location changes](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes)

IP and route queries run in a separate workers with one in-flight query per collector and refresh at most every 30 seconds when telemetry is sampled. The throughput sampler does not wait for the Windows calls. Topology changes may take up to one interval to appear. The initial buffer is 15 KB, allocation is capped at 8 MiB and retries at three; returned linked lists, declared structure lengths and socket lengths are bounded. IPv6 scope IDs are preserved. No DNS query is made to read configured DNS servers.

Wi-Fi research: realtime connection quality supports per-link/MLO data without SSID/BSSID, but current Microsoft documentation marks it prerelease without a clear minimum OS. Feature detection and payload-length validation are required; current windows 0.58 bindings do not expose it. Do not silently fall back to a location-sensitive query.

The first query reports pending. Prior successful samples can remain visible during a refresh, with their original timestamps; a failed refresh clears that collector's data. A stalled Windows call cannot spawn further workers or block app shutdown. Each collector reports stale after 60 seconds, including a hung first query; IP and route queries complete independently. Old timestamped samples remain distinguishable until restart or a successful refresh. Empty route configuration with available status means no routes were returned for that interface. A default-route marker is table evidence, not a connectivity check or a claim that a destination uses that route. Infinite route lifetime and unused route metric use null; addresses and next hops remain local and are never logged by tests.

Route reference: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
