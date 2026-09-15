# Windows DNS protection integration

This plan completes the existing ad/tracker roadmap item. Passing component
tests does not make the switch ready for owner acceptance.

## Runtime ownership

One session owns one dual-stack filtering companion, one independent recovery
watchdog, and the fixed protected recovery journal. The tray's presentation
mode never changes this ownership or enables protection. Serialize enable,
disable, rule replacement and recovery operations.

The companion must report both UDP and TCP listeners for 127.0.0.1 and ::1 on
the requested port before any Windows DNS setting changes. Reject missing or
duplicate families, unexpected ports, inconsistent primary addresses and an
upstream pointing back to either listener. Share one filter engine between
families instead of building an index in two companion processes.

## Start and recovery order

1. Resolve protected storage and recover any existing journal before starting
   a new generation. Preserve visible settings changed by another program.
2. Read the actual resolver configuration and routing policy. The upstream
   strategy must preserve Windows/VPN/split-DNS behavior; do not pick the first
   adapter or substitute a public resolver. The implementation decision and
   native policy tests remain open.
3. Validate a usable filter and start the companion. Verify every requested
   listener and ensure the companion remains alive.
4. Launch the hidden same-executable watchdog independently of the parent's
   process job. Wait for its bounded readiness response after it has verified
   the parent PID and creation time. A failed breakaway or handshake prevents
   DNS changes.
5. Re-read the configuration preconditions, persist the journal, then apply
   and verify the owned generation. Check both helper processes before
   reporting protection active.

On an apply failure, restore the journal before stopping the companion or
disarming recovery. If restoration fails, retain the recovery journal and
the surviving helpers and expose a recovery-required state. Do not report
successful disable or drop the only working resolver while Windows still
points at it.

## Active session and stop

- Monitor both helpers. Companion or watchdog failure triggers restoration;
  an active tray process must not wait for its own exit to restore DNS.
- Invoke the updater periodically. Validate a replacement before live reload;
  rejection preserves the old engine. An uncertain response triggers recovery.
- Define and test the action at the seven-day filter age limit. Cache selection
  already rejects expired filters; an active-session policy is still required.
- Normal disable and application shutdown restore and verify the journal first,
  then disarm the watchdog and stop the companion. Disarming independently
  verifies that the recovery journal is absent.
- Process death leaves the independently running watchdog responsible for
  restoring the journal. Its Drop implementation must not terminate it.

## Acceptance evidence still required

Exercise blocked and allowed queries over UDP/TCP and IPv4/IPv6, startup bind
conflicts, malformed/late readiness, companion exit, watchdog exit, normal
disable, forced application exit, restart recovery, and concurrent external
DNS changes. Compare Windows settings before and after each isolated test.
Validate VPN/NRPT behavior and preserve the ordinary resolver on unsupported
configurations. Ship the UI switch only with accurate effective and requested
states, a current native preview, and successful cleanup evidence.
