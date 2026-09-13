# DNS protection implementation status

The ad/tracker switch is not ready for native acceptance. The modules below
are backend groundwork; the application does not yet route system DNS through
the filtering companion.

## Implemented boundaries

- The source-built companion listens on loopback and accepts an explicit numeric
  upstream. Rust verifies the embedded executable and supervises its lifetime.
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

## Verified without system DNS changes

Real companion tests cover initial filtering, live reload, invalid-replacement
preservation and separate parser validation. Hidden-process watchdog tests cover
readiness while the parent is alive, waiting until parent exit, and failed
readiness without reading or restoring a sentinel journal.

The production updater has also been exercised against the official source:
179,077 rules downloaded, parsed by the companion, cached, and loaded by a new
updater instance without rewriting the cache. Worker-failure tests verify that
a panic releases the in-flight state while preserving the retry backoff.

These checks do not establish end-to-end protection. The remaining work includes
the elevated launch path, protected journal creation and restore on this system,
watchdog launch and handshake integration, upstream selection, IPv4/IPv6 routing,
proxy failure recovery, graceful shutdown, restart recovery, periodic updates,
and the UI switch. DoH, VPN and per-application resolver behavior also need
explicit coverage before broader protection claims.
