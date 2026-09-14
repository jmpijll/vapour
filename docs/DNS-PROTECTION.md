# DNS protection implementation status

The ad/tracker switch is not ready for native acceptance. The modules below
are backend groundwork; the application does not yet route system DNS through
the filtering companion.

## Implemented boundaries

- The source-built companion listens on loopback and accepts an explicit numeric
  upstream. Rust verifies the embedded executable and supervises its lifetime.
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

These checks do not establish end-to-end protection. The remaining work includes
the elevated launch path, protected journal creation and restore on this system,
watchdog launch and handshake integration, upstream selection, IPv4/IPv6 routing,
proxy failure recovery, graceful shutdown, restart recovery, periodic updates,
and the UI switch. DoH, VPN and per-application resolver behavior also need
explicit coverage before broader protection claims.
