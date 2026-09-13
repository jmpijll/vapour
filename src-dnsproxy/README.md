# Vapour DNS proxy companion

`src-dnsproxy` is a source-built Go companion for the Windows tray app.  It
keeps domain filtering in a small supervised process so the Tauri layer can
start and stop DNS protection without embedding a Go runtime.  This directory
is a nested Go module and is intentionally self-contained.

The companion uses pinned, maintained upstream packages:

- [`dnsproxy` v0.84.2](https://github.com/AdguardTeam/dnsproxy/tree/v0.84.2)
  for plain DNS UDP/TCP listeners and explicit upstream forwarding;
- [`urlfilter` v0.23.4](https://github.com/AdguardTeam/urlfilter/tree/v0.23.4)
  for AdGuard rule parsing, exceptions, and `$dnstype`; and
- [`miekg/dns` v1.1.72](https://github.com/miekg/dns/tree/v1.1.72) for the
  test resolver and DNS client.

The process never changes system DNS settings, installs a driver, changes
Windows Firewall state, elevates itself, or logs DNS queries.  The caller owns
any later Windows resolver routing and rollback policy.

## Build and run

From this directory in PowerShell:

```powershell
go test ./...
go vet ./...
go build -o src-dnsproxy.exe .
```

The tested runtime is Go 1.27.1.  The upstream dnsproxy README requires Go
1.26 or later.

The default mode reads one JSON command per line from stdin and writes one
JSON status per line to stdout.  A start command has this shape:

```json
{"op":"start","config":{"upstream":"127.0.0.1:5353","listen_address":"127.0.0.1","listen_port":53,"rules":"||ads.example^\n@@||allowed.ads.example^"}}
```

The upstream must be a numeric IP address and port; hostnames are rejected so
startup cannot silently consult the system resolver.  `listen_address` must
be a loopback IP and defaults to `127.0.0.1`.  `listen_port` accepts `0` for
OS-assigned test ports and `53` for a production DNS port; the process does
not request elevation.  A caller that selects port 53 must arrange the
required Windows privilege and any routing/rollback outside this process.

Send `{"op":"stop"}` to shut down and exit.  Closing stdin has the same
effect after a successful start, which lets a parent process use pipe closure
as the crash-safe shutdown signal.  Blank lines are ignored.  Unknown JSON
fields, malformed commands, non-loopback listeners, non-IP upstreams, invalid
ports, and oversized or unsupported rules produce an `error` status.

Send `{"op":"reload","rules":"||ads.example^"}` to replace the active
filter without restarting either listener. The replacement is fully parsed
before an atomic swap; invalid updates leave the previous filter active.
Each in-flight DNS request retains one consistent filter snapshot. Success
returns `{"status":"updated","rules_count":1}`. Reload changes only rules,
not the upstream or listening addresses, and requires a running service.

The alternate mode validates one JSON config file before binding listeners:

```powershell
& .\src-dnsproxy.exe --config-file .\dnsproxy.json
```

The file contains the `config` object shown above without the `op` wrapper.
The process stays alive until its stdin pipe closes, then emits `stopped`.
Config files and individual command lines are bounded at roughly 16 MiB plus
small JSON overhead; decoded rule text is bounded at 8 MiB.

Status examples:

```json
{"status":"ready","udp_addr":"127.0.0.1:54001","tcp_addr":"127.0.0.1:54002","rules_count":2}
{"status":"error","error":"listen_address must be a loopback IP address"}
{"status":"stopped"}
```

The ready status is emitted only after both listeners bind.  The process uses a
discarded dnsproxy logger and never emits per-query status, so stdout remains a
small control/status channel for the Tauri supervisor.

## Filtering behavior

The process builds an immutable AdGuard `urlfilter.DNSEngine` before replacing
any running service.  Basic domain rules and `@@` exceptions use urlfilter's
priority handling, and the DNS question type is passed through so a
`$dnstype=A` rule does not accidentally block AAAA.  Host-file entries are
accepted only for `0.0.0.0`, `::`, and `127.0.0.1`, and only for their matching
A or AAAA question.  Arbitrary host mappings and `$dnsrewrite` rules are
rejected with a line-numbered error; they are not guessed to be blocks.

Blocked questions receive an authoritative NXDOMAIN locally and are never sent
to the explicit upstream.  Allowed questions are resolved by dnsproxy.  The
test fixture returns both A and AAAA documentation addresses over a local
UDP/TCP upstream, proving that the proxy preserves allowed IPv6 answers and
that an exception can pass over both listener protocols.

This is a DNS policy component.  It sees only clients that use its resolver;
browser or application DoH/DoT/DoQ can bypass a local plain DNS listener.
Windows routing and encrypted-DNS policy need separate review.  WFP can be an
additional transport enforcement layer, but resolving shared-CDN domains into
IP firewall rules would create false blocks and is outside this companion.

## Tests

`main_test.go` builds the actual companion binary with `GO_BIN` (or `go` from
`PATH`), starts it with pipes, and uses a synthetic loopback upstream.  It
checks start/stop protocol statuses, invalid configuration errors, config-file
startup, graceful EOF shutdown, loopback high-port binding, blocked UDP/TCP
queries, exception and control forwarding, upstream query counts, and A/AAAA
answers.  The fixture never changes system DNS or uses a public resolver.

## Licensing

Vapour is GPL-3.0-only.  The direct `urlfilter` dependency is GPL-3.0, while
`dnsproxy` is Apache-2.0 and `miekg/dns` is BSD-3-Clause.  The pinned source
license texts are retained in [`licenses/`](licenses/) and the dependency
versions are recorded in [`go.mod`](go.mod).  Preserve these notices and add
the complete transitive dependency notice set when producing a distribution.
