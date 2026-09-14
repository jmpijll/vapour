# Windows appcapture verification

Appcapture remains **Partial**. The latest isolated native debug run checks
selected and control processes using local traffic. A positive result requires
application payload in both directions and no exported control traffic;
capturing a TCP SYN alone is insufficient.

| Scenario | IPv4 | IPv6 | Evidence |
| --- | --- | --- | --- |
| New outbound TCP | Passed | Passed | 7 selected packets, 21 outbound and 19 reply payload bytes per capture |
| New outbound UDP | Passed | Passed | 2 selected packets, 19 outbound and 23 reply payload bytes per capture |
| Incoming TCP | Failed | Failed | No selected packets exported |
| Incoming UDP | Failed | Failed | Only one direction exported |
| TCP established before capture | Unsupported | Unsupported | Packets excluded when ownership cannot be established from capture events |

The pre-existing TCP cases pass their exclusion assertions, but this is not
support for capturing existing connections. They must not inflate the supported
scenario count. Four of the eight positive capture cases currently pass.

An independent Python parser checked the four outbound PCAPNG files: block
lengths and footers, raw-IP interface records, captured/original lengths, IP and
transport lengths, selected payload and reply markers, and absence of the
control marker. TCP exports contain 40 application bytes and UDP exports contain
42 application bytes per address family. Private traces and captures are kept
outside the public repository.

This evidence covers controlled loopback fixtures in a debug native harness
that imports the production capture modules. It does not establish complete
server-side attribution, existing-connection support, release-build runtime
coverage, process churn, retransmission coverage or sustained-load accuracy.
Scoped diagnostics are excluded from release builds.
