# Transparent DNS native acceptance

The transparent runtime is not enabled by the application UI yet. Its native
tests are opt-in and have not been run. Run them only in an explicitly scheduled
administrator session with the owner present; ordinary `cargo test --lib`
does not execute them.

Run each command separately from the repository root. Do not run the entire
ignored test set: it includes unrelated privileged and environment-dependent
tests.

```powershell
cargo test --manifest-path src-tauri/Cargo.toml --locked --lib protection::dns_divert::tests::native_loopback_udp_tcp_passthrough_and_cleanup -- --ignored --exact --nocapture
cargo test --manifest-path src-tauri/Cargo.toml --locked --lib protection::dns_session_native_tests::native_session_filters_ipv4_udp_tcp_and_restores_direct_dns -- --ignored --exact --nocapture
cargo test --manifest-path src-tauri/Cargo.toml --locked --lib protection::dns_session_native_tests::native_session_filters_ipv6_udp_tcp_and_restores_direct_dns -- --ignored --exact --nocapture
```

The first test checks raw driver send/receive and shutdown with ephemeral local
sockets. The session tests then use an actual local DNS fixture on port 53:
IPv4 client `127.0.0.11` and resolver `127.0.0.12`; IPv6 uses `::1`. A port
conflict fails before interception starts. They make no external DNS requests
and do not modify adapter DNS settings or firewall rules.

Each session test must prove all of the following:

- A blocked query returns NXDOMAIN over UDP and TCP and never reaches the
  fixture resolver.
- An allowed query reaches that resolver and returns through the original
  resolver/client tuple.
- Reloading rules blocks the previously allowed name over UDP and TCP without
  replacing the session. Restoring the rules permits it again.
- Session stop finishes within its deadline.
- After stop, a subdomain of the blocked rule reaches the resolver normally
  over both transports. The server sees exactly six forwarded requests total.

The fixture requests bounded cleanup during assertion unwinding as well. A
cleanup error is a failure, not a passed test. Retained workers/driver handles
must not be mistaken for completed cleanup; keep the failing test isolated and
confirm its process has exited before another native run. Preserve only
aggregate outcomes in public documentation, never local traces or captures.

Passing these fixtures will not establish VPN/NRPT equivalence, long-running
generation rollover, interface changes, packet-loss behaviour or sustained
performance. Those remain separate acceptance cases before enabling protection
in the tray app.
