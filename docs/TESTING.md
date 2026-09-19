# Windows review build

Extract the complete artifact and run `Vapour.exe`. Windows 10/11 x64 and
WebView2 are required; Node, Rust and Go are not. This is an unsigned alpha,
not a signed installer. `build.json` identifies the source revision and hashes;
`source.zip` contains the matching tracked source and build instructions.

## Review checklist

- Open and hide the tray window. Try light/dark appearance and Basic/Advanced.
- Compare interface traffic, link details and application activity. App
  measurements ask for administrator access; choose Not now to defer it.
- Open an application, inspect destinations and check recently closed sessions.
- Run a speedtest; each measurement phase should last at least ten seconds.
- Record and stop a short interface/session/app capture. Open its PCAPNG in
  Wireshark and compare it with the traffic you generated.
- If you choose to test firewall blocking, use a disposable connection and
  remove the rule afterwards. Check that unrelated traffic still works.

For a report, include the revision from `build.json`, the action, the expected
result and what happened. Redact personal addresses, paths and hostnames; keep
real captures private.

## Known boundaries

Appcapture remains Partial; rapid port reuse, very short-lived processes and
sustained load need more verification. DNS ad/tracker filtering is not enabled
in the app yet. Administrator mode currently elevates the whole app. Connected
Wi-Fi diagnostics need testing on a connected adapter. See `docs/ROADMAP.md`
and `docs/DNS-PROTECTION.md` inside the source archive for the remaining work.
