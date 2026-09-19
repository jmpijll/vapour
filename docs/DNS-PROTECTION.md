# DNS protection implementation status

The ad/tracker switch is not ready for native acceptance. The modules below
are backend groundwork; the application does not yet route system DNS through
the filtering companion.

## Implemented boundaries

- A pure packet codec validates exact IP/transport lengths and rewrites
  same-family IPv4/IPv6 TCP/UDP tuples with recalculated checksums. It rejects
  fragments, IPv6 extension headers, IPv4 source routes and malformed options.
  IPv6 scope metadata belongs to the later routing layer, not the wire codec.
  This module does not intercept traffic or authorize a flow.
- A bounded flow registry reflects requests and restores registered reverse
  replies, retaining the original resolver and interface. It rejects ambiguous
  reflected tuples across interfaces. Expired keys are quarantined until the
  registry is dropped; continuous operation still requires a rollover policy.
- A separate active WinDivert wrapper owns its DLL and handle, validates packet
  bounds, checks injection counts and supports draining shutdown. It is not
  started by the app. The isolated native forwarding probe remains unexecuted;
  the current checks exercise its API through a fake driver.
- The source-built companion listens on loopback and accepts an explicit numeric
  upstream. Rust verifies the embedded executable and supervises its lifetime.
- An elevated caller launches the companion with the desktop user's primary
  token through `CreateProcessWithTokenW`. The child is created suspended,
  attached to a kill-on-close job, and verified non-elevated with medium-or-lower
  integrity before it runs. Startup failure never falls back to an elevated child.
- Dual-stack mode shares one filter engine across UDP/TCP listeners on
  127.0.0.1 and ::1. Rust rejects incomplete families, unexpected ports and an
  upstream pointing back to either listener before accepting readiness.
- A live rule reload validates the complete replacement before switching engines.
  A rejected list preserves the active filter. An uncertain protocol response
  terminates the companion instead of reporting an unverified state.
- Cache validation uses a separate companion on an ephemeral port. It does not
  interrupt the active listener or change Windows DNS settings.
- The updater retrieves the fixed official AdGuard DNS filter over bounded HTTPS.
  Its controller-facing request method coalesces concurrent refreshes, refreshes
  stale lists after 24 hours and backs off failed attempts for 15 minutes.
  A valid cached list avoids an unnecessary startup download. The periodic
  controller integration remains outstanding.
- Invalid replacements preserve the previous cache. Filters older than seven
  days cannot be selected for enabling protection, including an in-memory copy.
  This selection policy is not an implemented automatic disable policy.
- Windows configuration snapshots preserve static versus automatic settings.
  Apply records recovery data before changing settings. Rollback and recovery
  re-read the current value and verify the restored value. They refuse to
  overwrite a visible change from another program. Windows does not provide an
  atomic compare-and-set operation, so an external writer can still race a set.
- The internal recovery CLI accepts only the parent PID and creation time. The
  recovery path is derived from the machine's known ProgramData location, with
  storage ownership and permissions checked separately. It is not a UI argument.
- The watchdog verifies the exact process handle, reports readiness before
  waiting, and attempts recovery only after that process exits. Failed readiness
  prevents recovery. Recovery errors return a bounded machine-readable status.
- The launcher resolves the current executable internally, requests job
  breakaway where needed and verifies the child is outside a process job.
  Readiness and failed-start cleanup are bounded. Disarming checks that the
  trusted journal is absent; dropping its handle does not kill the watchdog.

## Verified without system DNS changes

Eleven packet-codec tests cover all four address-family/transport combinations,
payload and TCP-header preservation, independent checksum assertions, computed
UDP-zero encoding, every truncated fixture prefix, trailing bytes, malformed
lengths/options, fragments and unsupported extensions. Flow tests additionally
cover reverse-tuple ownership, retry reuse, cross-interface collisions,
quarantined expiry, capacity and TCP close grace. No active driver forwarding
is exercised by these tests.

Real companion tests cover initial filtering, live reload, invalid-replacement
preservation and separate parser validation. Hidden-process watchdog tests cover
readiness while the parent is alive, waiting until parent exit, and failed
readiness without reading or restoring a sentinel journal.

The production updater has also been exercised against the official source:
179,077 rules downloaded, parsed by the companion, cached, and loaded by a new
updater instance without rewriting the cache. Worker-failure tests verify that
a panic releases the in-flight state while preserving the retry backoff.

The real Rust process manager also passes allowed/blocked UDP and TCP queries
over IPv4 and IPv6 through one companion, then reloads its engine without
changing listeners. Go integration tests verify cleanup after an IPv6 bind
conflict while the IPv4 address was available.

Native elevated tests now verify the real companion's start/stop lifecycle,
dual-stack UDP/TCP filtering and reload, and preservation of the active rules
after an invalid replacement. A separate native probe verifies redirected
stdin/stdout and that additional inheritable sentinel handles do not increase
the child's handle count. These checks made no system DNS changes. The linked
UAC token on this host is identification-only; attempting to use or convert it
as a primary token failed. The working launch path uses the desktop token.

## Resolver integration decision

Direct numeric forwarding cannot be assumed to preserve Windows resolver
policy. Selecting every adapter's servers is also not equivalent to Windows
fallback and VPN policy. The native
[DnsQueryRaw API](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsqueryraw)
can apply host NRPT and encrypted DNS settings. An isolated native probe on
Windows build 26200 resolved a real raw DNS query successfully and exercised
cancellation of a pending query. Runtime API discovery succeeded; adapter DNS
settings were unchanged. This establishes API availability on the test host,
not VPN-policy coverage or compatibility with older Windows versions.
Calling it after pointing system DNS back at this
proxy would risk recursion, so it is not a drop-in upstream replacement.

The next implementation follows the
[transparent routing plan](superpowers/plans/2026-09-15-transparent-dns.md):
intercept conventional UDP/TCP port 53 traffic with a separate active WinDivert
handle and retain the original resolver destination selected by Windows. The
companion now has an internal command mode for exact per-flow routing and owned
upstream sockets. The Rust controller still needs to connect that mode to packet
interception before it can replace the fixed-upstream test configuration. Adapter DNS
settings remain unchanged in this design. The existing configuration journal
and watchdog are groundwork for the alternative adapter-rewrite approach; they
must not be enabled alongside transparent interception.

The internal mode prebinds exclusive UDP/TCP upstream ports and reports them
with its explicit IPv4/IPv6 listeners. Only parent-registered transport tuples
can reach DNS parsing and filtering. Resolver assignments cannot be retargeted;
expired and released tuples remain quarantined until the session ends. Failed
TCP connections retain their reserved socket until interception can be stopped.
Local tests use synthetic endpoints and do not change adapter DNS settings.

The Windows filter builder now checks complete companion bindings and emits
disjoint filters covering at most four local addresses each. Sixteen addresses
require four filter groups and, once integrated, four handles: the real WinDivert compiler rejects the
larger single expression. Tests use the shipped DLL's compiler and evaluator
without opening a driver handle. They verify IPv4/IPv6 UDP/TCP matching,
protocol-specific source-port exclusions, different local addresses using the
same port, numeric IPv6 interface scope and complete non-overlapping coverage.
An additional local bind test verifies numeric IPv6 scope in every companion
listener and reserved socket reported to the Rust controller.

The Rust process manager now starts that mode, verifies all listener and slot
bindings, and serializes bounded register/release commands alongside reload and
stop. Unexpected acknowledgements or stream failure terminate the child;
explicit command rejection preserves it. An unelevated integration test starts
the real embedded companion, builds filters from its readiness response,
registers a real local UDP client, receives a blocked response, releases that
flow, verifies subsequent queries receive no response, and stops the process.
No interception handle or system DNS changes are involved in this test.

These checks do not establish end-to-end protection. Remaining work includes
connecting the bounded packet/flow reflection to these listeners, installing
the exact owned-port exclusions, session rollover, helper/driver failure recovery,
graceful shutdown with a companion quiesce phase that retains reserved sockets,
restart, periodic updates and the UI switch. Native tests must verify that
adapter settings stay unchanged and that cleanup restores ordinary packet flow.
VPN, NRPT and per-application routing still need explicit verification: retaining
the destination alone does not prove equivalent process or compartment policy.
Encrypted DoH/DoT/DoQ traffic is outside port-53 interception and must not be
presented as filtered by this mechanism.
