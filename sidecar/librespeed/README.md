# Vapour LibreSpeed sidecar

Source base: LibreSpeed CLI commit `b660d1e6c24f14fc93624538d9e73163e7784335`
<https://github.com/librespeed/speedtest-cli/tree/b660d1e6c24f14fc93624538d9e73163e7784335>.
The `defs/` and `output/` source trees, module checksums, and LGPLv3 LICENSE
are retained from upstream. Vapour modifications are `defs/timed.go`, this
JSONL entry point, and its tests. This is a duration-controlled adapter/fork,
not an unmodified official LibreSpeed release. Retained upstream methods are
not used for Vapour's timed phases.

Build using Go 1.26+ (the module's dependency constraints may require a newer
toolchain): `go build -trimpath -o vapour-librespeed.exe .`. Run `go test ./...`.
The full integration fixture takes at least 44 seconds and only uses localhost.

The first stdin line is JSON:

```json
{"run_id":"unique-id","servers":[{"id":1,"name":"LAN","server":"http://192.168.1.20/","dlURL":"garbage.php","ulURL":"empty.php","pingURL":"empty.php"}],"duration_ms":10000,"parallel":4}
```

Omitting `servers` fetches the same official HTTPS catalogue as upstream,
with a five-second timeout, 1 MiB limit and HTTPS-only endpoint validation.
Explicit servers may use HTTP for a user-selected local backend.
Optional `server_id` selects that server; otherwise three successful HTTP RTT
probes per candidate select the lowest median. A selected server never changes
mid-test. Candidate selection runs at most four probes concurrently and is
bounded to 15 seconds. TLS validation is enabled and redirects are rejected. No telemetry,
sharing, automatic tests, registry changes or service installation.

Keep stdin open; `{"command":"cancel"}` or EOF cancels. File mode:
`--config config.json --events new-events.jsonl --cancel cancel-marker`.
The events file must not exist; creating the marker cancels within a 100ms poll.
Every process has a 120-second overall deadline; accepted per-phase duration
is 10–20 seconds (default 10). Parent must launch with a
non-elevated token and retain a bounded kill fallback.

Events share `run_id`, `event`, optional `phase`, `warmup`, `duration_ms`.
Types: `selected`, `progress`, `phase_complete`, `complete`, `cancelled`, `error`.
Selected/complete include `server`. Progress and phase_complete include
`elapsed_ms`, `value`, `bytes`, `requests`, `timeouts`; phase_complete includes
raw `samples_ms` for latency/jitter. Values are milliseconds for HTTP RTT
latency/jitter and decimal Mbps for transfer. Errors are terminal and incomplete.

Each of latency, jitter, download and upload measures a separate >=10-second
monotonic window. One-second warmup is excluded; transfer warmup uses the same
continuous workers and HTTP connections, but byte counters are gated to the
measurement window. Upload requests crossing the warmup boundary are excluded. Latency is median full
HTTP RTT; jitter is mean absolute difference between successive full HTTP RTTs.
This includes server processing and is not ICMP or loaded latency. Transfer
requests run in parallel and replenish until the deadline; none end early on
a stability heuristic.

Download counts bytes received inside the window. Upload counts only complete
256KiB requests whose successful HTTP response finishes inside the window.
The boundary's incomplete upload requests are deliberately excluded; therefore
this acknowledged-request estimate has a bounded tail undercount (up to one
payload per worker plus server response time). It is not wire-byte capture or
cryptographic proof of server receipt. A server too slow to complete any request
produces an error, not a zero-speed success. Further cross-server live comparison
is required before claiming broad measurement accuracy.

Existing upstream files remain under LGPLv3 (see LICENSE); this sidecar's
modifications are also LGPLv3. Vapour's main application has its separate GPLv3
license. Distributions must include corresponding sidecar source and notices.
