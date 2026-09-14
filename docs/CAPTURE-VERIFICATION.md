# Windows appcapture verification

Appcapture remains **Partial**. Isolated native debug and release runs check
selected and control processes using local traffic. A positive result requires
application payload in both directions and no exported control traffic;
capturing a TCP SYN alone is insufficient.

| Scenario | IPv4 | IPv6 | Evidence |
| --- | --- | --- | --- |
| New outbound TCP | Passed | Passed | 7 selected packets, 21 outbound and 19 reply payload bytes per capture |
| New outbound UDP | Passed | Passed | 2 selected packets, 19 outbound and 23 reply payload bytes per capture |
| Incoming TCP | Passed | Passed | 8 selected packets, 21 request and 19 reply payload bytes per capture |
| Incoming UDP | Failed | Failed | Only one direction exported |
| TCP established before capture | Unsupported | Unsupported | Packets excluded when ownership cannot be established from capture events |

The pre-existing TCP cases pass their exclusion assertions, but this is not
support for capturing existing connections. They must not inflate the supported
scenario count. Six of the eight positive capture cases currently pass.

An independent Python parser checked the six passing PCAPNG files from each build: block
lengths and footers, raw-IP interface records, captured/original lengths, IP and
transport lengths, selected payload and reply markers, and absence of the
control marker. TCP exports contain 40 application bytes and UDP exports contain
42 application bytes per address family. Private traces and captures are kept
outside the public repository.

This evidence covers controlled loopback fixtures in a debug and release native harness
that imports the production capture modules. It does not establish complete
UDP server-side attribution, existing-connection support, process churn,
retransmission coverage or sustained-load accuracy. Scoped diagnostics are
excluded from release builds; the release run produced no diagnostic traces.

The fixed TCP generation tracks verified opening evidence separately for each
endpoint. A selected server's Accept can authorize subsequent packets even when
the peer's Connect preceded the SYN. Conflicting same-side ownership remains
ambiguous. Regression tests also reject a stale selected Accept before a newer
peer Connect, including the later handshake and payload packets. The full Rust
library suite passes 205 tests, with 26 environment/native tests explicitly
ignored; the release harness passes 69 offline tests.

For incoming UDP, the first request precedes the selected server's Accept event;
the reply follows it and is captured. Later ownership evidence must not silently
authorize an earlier datagram. Complete first-request support needs additional
prior ownership evidence, and remains unverified.

A new bounded UDP owner-module snapshot is verified against held IPv4/IPv6
sockets in both native debug and release tests. It preserves bind timestamps,
process creation times, scope IDs, wildcard overlap and unreadable competitors.
Two snapshots must agree before a bind can identify the selected owner.
Eight pure tests and the native socket test pass; the expanded release harness
passes 69 offline tests plus the explicitly invoked native snapshot test.

This snapshot is not yet used to authorize capture packets. Integration must
record Bind/Close changes with their native timestamps and invalidate ownership
after a matching change or metadata loss. A bind table describes the local
socket, not its connected remote peer. First-datagram attribution must therefore
combine prior bind evidence with verified matching flow ownership; a later
Accept alone must not authorize an earlier packet or a reused socket lifetime.
