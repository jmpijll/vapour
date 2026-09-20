# Windows appcapture verification

Appcapture remains **Partial**. Isolated native debug and release runs check
selected and control processes using local traffic. A positive result requires
application payload in both directions and no exported control traffic;
capturing a TCP SYN alone is insufficient.

| Scenario | IPv4 | IPv6 | Evidence |
| --- | --- | --- | --- |
| New outbound TCP | Passed | Passed | 7–9 selected packets including optional closing packets, 21 outbound and 19 reply payload bytes |
| New outbound UDP | Passed | Passed | 2 selected packets, 19 outbound and 23 reply payload bytes per capture |
| Incoming TCP | Passed | Passed | 8 selected packets, 21 request and 19 reply payload bytes per capture |
| Incoming UDP | Passed | Passed | 2 selected packets, first 19-byte request and 23-byte reply included |
| TCP established before capture | Passed | Passed | 4–6 selected packets, 21 request and 19 reply payload bytes |
| New app process during capture, outbound TCP | Passed (release) | Passed (release) | 9 selected packets, 21 request and 19 reply payload bytes; post-start different-path control excluded |
| New app process during capture, outbound UDP | Passed (release) | Passed (release) | 2 selected packets, 19 request and 23 reply payload bytes; post-start different-path control excluded |

All fourteen positive capture cases currently pass in release. The original ten
cases also passed in debug. The existing-TCP fixtures now
require application payload in both directions and zero control traffic, just
like the new-connection fixtures; exclusion is no longer considered a pass.

An independent Python parser checked the ten original PCAPNG files from each
build and all fourteen files from the expanded release run: block
lengths and footers, raw-IP interface records, captured/original lengths, IP and
transport lengths, selected payload and reply markers, and absence of the
control marker. TCP exports contain 40 application bytes and UDP exports contain
42 application bytes per address family. Private traces and captures are kept
outside the public repository.

This evidence covers controlled loopback fixtures in a debug and release native harness
that imports the production capture modules. It does not establish complete
coverage of all UDP socket configurations, arbitrary TCP socket lifetimes, rapid process churn,
retransmission coverage or sustained-load accuracy. Scoped diagnostics are
excluded from release builds; the release run produced no diagnostic traces.

The fixed TCP generation tracks verified opening evidence separately for each
endpoint. A selected server's Accept can authorize subsequent packets even when
the peer's Connect preceded the SYN. Conflicting same-side ownership remains
ambiguous. Regression tests also reject a stale selected Accept before a newer
peer Connect, including the later handshake and payload packets. The full Rust
library suite passes 232 tests, with 27 environment/native tests explicitly
ignored; the expanded release harness passes 86 offline tests.

The bounded UDP owner-module snapshot is verified against held IPv4/IPv6
sockets in both native debug and release tests. It preserves bind timestamps,
process creation times, scope IDs, wildcard overlap and unreadable competitors.
Two snapshots must agree before a bind can identify the selected owner.
The collector takes snapshots around driver startup, records Bind/Close changes
with native timestamps, and refuses prior evidence following a matching change.
Queue/metadata loss discards the recording. A bind table describes the local
socket, not its connected remote peer: a first datagram also needs a matching
Accept from the same verified process identity and an unambiguous flow ledger.
A later Accept alone cannot authorize an earlier packet or a reused socket.
Unknown bind addresses invalidate prior evidence; unrelated socket changes do
not. The native snapshot test is invoked separately from the regular suite.

The snapshots and event stream are not an atomic Windows networking transaction.
The current evidence covers the controlled fixtures above. Further tests must
cover rapid socket reuse, shared UDP bindings and network traffic beyond loopback
before expanding the completeness claim.

Existing TCP connections use a separate ownership path, not fabricated handshake
or endpoint IDs. Two owner-module snapshots must contain the same established
tuple, process creation identity and socket context timestamp. Both orientations
of a loopback connection are supported; conflicting ownership on one orientation
is not. Native socket events end prior evidence at their timestamp. A new SYN,
SYN/ACK or reset prevents subsequent fallback to the old connection. Unreadable
TCP metadata stops future prior-evidence admission. Hash-indexed tuples avoid
scanning the complete Windows table for each packet.

The TCP context timestamp is not a sequence-number boundary. This path proves
stable local socket ownership for the tested window, not full TCP reassembly or
delivery to the application. Tests reject changed lifetimes, PID reuse,
transitional states, unknown competing owners and new handshakes. Native rapid
reuse, late closing packets and sustained traffic remain acceptance work.

During collection, new processes are eligible only when their creation time is
at or after the collector's clock anchor and a held process handle confirms both
the selected executable path and the event's PID/creation-time identity. Existing
processes outside the initial selection are not added. The selection is bounded
to 1,024 identities; exceeding it discards the recording. UDP attribution
classifies the complete selection in one pass through each flow's history.
Unit tests cover the start boundary, duplicate admission, PID reuse, missing
identity, path mismatch and the capacity limit. Very short-lived processes that
exit before their image can be verified remain outside the completeness claim.
Native fixtures start with an idle selected process, then launch a new process
of the selected executable and a control from a copied executable path after
capture readiness. Both exchange real payloads and replies; the control must
remain absent from the export. These fixtures verify new-process admission,
not rapid PID reuse or coverage of processes too short-lived to inspect.
