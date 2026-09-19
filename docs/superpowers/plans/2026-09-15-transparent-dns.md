# Transparent Windows DNS filtering

## Intended behavior

The ad/tracker switch filters conventional UDP/TCP DNS while retaining the
resolver destination Windows selected. Do not replace adapter DNS settings with
a single guessed upstream. Use the WinDivert driver already packaged for
capture, with a separate active forwarding handle and lifecycle.

Encrypted DNS over HTTPS, TLS or QUIC is outside port-53 interception. Surface
that coverage boundary accurately; do not silently block encrypted traffic or
claim all application DNS is filtered. VPN/NRPT route equivalence needs native
tests because a new proxy socket can have different process/compartment policy.

## Implementation increments

The pure packet codec and bounded flow registry are implemented. The registry
restores only registered reverse tuples and retains the original interface
metadata. Expired keys remain quarantined for the registry lifetime; the
production controller still needs a rollover policy before this can run
continuously.

The separate active driver wrapper now owns receive, reinjection, checksum and
shutdown APIs. Its unit tests use a fake API. An ignored native probe covers
isolated loopback TCP/UDP over both families and traffic after handle closure;
that probe has not been run. The Rust process manager now starts the transparent
companion and registers/releases exact flow tuples. A real unelevated companion
test covers blocked UDP delivery and post-release silence. Filter construction
is checked with the real WinDivert compiler/evaluator without opening a handle.
Real packet reflection remains outstanding. None of this groundwork enables
system interception.

Ruling: split filter coverage into disjoint groups of at most four addresses.
The real DLL rejected the complete sixteen-address expression as too long;
native evaluator tests prove complete, non-overlapping coverage across four
groups. The controller must own all returned handles, not just the first.

Ruling: add a quiesce phase before normal stop/rollover. It must stop new work
and wait for handlers while retaining reserved upstream sockets. Only after
the driver readers drain and their handles close may those reservations be
released. This ordering is not implemented yet. Native tests must still cover
late TCP control packets, retransmission and process failure; a user-mode
handler barrier alone does not prove the network stack has stopped sending.

1. Implement a pure IPv4/IPv6 packet reflection and mapping module. Retain the
   original local address, resolver address, interface, transport and ports.
   Validate IP and transport lengths, reject unsupported fragments/extensions,
   and calculate checksums after changes. Test round trips, malformed packets,
   resolver collisions, unsolicited replies and bounded mapping capacity.
2. Add an active WinDivert API separate from passive capture. Resolve send and
   checksum helpers from the same verified DLL, preserve the address ABI, and
   exercise only isolated synthetic local endpoints first. Closing this handle
   must leave normal Windows resolver settings unchanged.
3. Reflect client requests into an exclusively bound proxy listener. The
   reflected peer carries the original resolver destination. Authenticate each
   response against the registered flow mapping; arbitrary traffic to the proxy
   port must not become an injected DNS reply.
4. Extend the source-built filtering companion for dynamic per-flow upstreams.
   Pre-bind and exclusively retain every exempt upstream port before installing
   a filter that exempts it. Register the exact upstream tuple before sending.
   Never exempt an unowned port range or use an unverified PID assumption at
   NETWORK layer. Bound sockets, mappings, response sizes and query deadlines.
5. Integrate rules, live reload, updater and session ownership. Start all
   listeners and verify the companion before interception. On helper failure,
   stop interception promptly and report the effective state truthfully.
6. Test UDP/TCP over both families, multiple resolvers, retry behavior, malformed
   replies, port exhaustion, proxy/driver exit, restart, cleanup and VPN/NRPT
   behavior. Compare actual adapter settings before and after. Only then wire
   the switch and ship a current native review build.

The existing loopback companion and restoration modules remain available for
controlled testing. Their successful component tests do not establish a working
transparent runtime. Do not enable both routing approaches simultaneously.

## Source basis

- [WinDivert API](https://github.com/basil00/WinDivert/blob/master/doc/windivert.html)
- [Official streamdump reflection example](https://github.com/basil00/WinDivert/blob/master/examples/streamdump/streamdump.c)
- [WFP bind/connect redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)

`Impostor` is not an application identity marker. NETWORK packets have no PID.
Do not call the system-configured `DnsQueryRaw` resolver from a loopback-routing
proxy: it can resolve through the proxy again. Forwarding to the captured
numeric destination avoids that recursive dependency.
