# Release readiness — PR3

**Reviewed 2026-09-20 — decision: no-go for the first stable Windows release.** This review covers PR3 at `f4fca90` plus the accepted-TCP-socket fixture correction. The CI download fix is committed and pushed; both its push and PR Windows checks passed. The repository has substantial DNS groundwork, but the user-visible DNS protection path is not complete or natively accepted. A first release that promises fully working DNS must close the mandatory gates below.

The fresh checks reported for this review are useful baseline evidence: Rust 284 passed / 41 ignored, frontend lint/build and five frontend tests passed, Edge UI checks passed, and the DNS companion, speedtest, and vet checks passed. They do not prove the administrator-only WinDivert path. The native gate is now in progress: the driver passthrough fixture passed after its test-only socket fix, but the IPv4 transparent session timed out on its first intercepted UDP response at [`dns_session_native_tests.rs`](../src-tauri/src/protection/dns_session_native_tests.rs#L227); the IPv6 case was therefore not attempted. The run reported `DNSsettingsUnchanged=true` and the child exited. This is a concrete release blocker, not evidence of a passing DNS path.

## What is implemented

- The DNS packet codec, flow ownership, companion process, transparent control protocol, grouped WinDivert filters, routing, quiescence, reload serialization, cleanup barriers, generation reconciliation, and retained background worker are present. The implementation and its limits are recorded in [DNS-PROTECTION.md](DNS-PROTECTION.md).
- Feed download/cache, persistent intent, and firewall enforcement are wired into the Tauri process. [`src-tauri/src/lib.rs`](../src-tauri/src/lib.rs#L27-L47) exposes threat-protection/feed commands and [`src-tauri/src/lib.rs`](../src-tauri/src/lib.rs#L176-L183) starts `FeedUpdater`/`ProtectionController`; [`src-tauri/src/protection/mod.rs`](../src-tauri/src/protection/mod.rs#L1-L26) shows the DNS modules are present as separate groundwork. Do not conflate the Feodo firewall feed with the DNS filtering feed.
- The companion's ordinary Go tests and Rust unit/integration tests provide meaningful codec, flow, companion, lifecycle, and control-protocol coverage. They do not establish kernel interception or system DNS behavior.

## Mandatory release gates, in order

1. **Close ownership, then wire the backend behind a disabled UI.** Add cross-process exclusion; the current lease only coordinates one Vapour process and explicitly leaves separate-process exclusion outstanding ([`DNS-PROTECTION.md`](DNS-PROTECTION.md#L185-L190)). Connect the UI switch, persisted DNS intent/feed state, adapter/topology monitoring, and status/error reporting to the transparent DNS session while keeping the switch unavailable. The current code starts the Feodo feed/firewall controller but does not start a DNS generation ([`src-tauri/src/lib.rs`](../src-tauri/src/lib.rs#L176-L183)); the documented gap is [`DNS-PROTECTION.md`](DNS-PROTECTION.md#L203-L209), and the review checklist still says DNS filtering is not enabled in the app ([`TESTING.md`](TESTING.md#L28-L32)). The eventual switch must distinguish requested from effective state, reject invalid starts, report failed cleanup, restore ordinary DNS on disable/failure, survive restart, and make the actual filtering state observable.
2. **Finish native acceptance and recovery.** In the owner-present administrator session, complete all three exact cases in [`DNS-NATIVE-TESTS.md`](DNS-NATIVE-TESTS.md#L3-L18). The required assertions include blocked and allowed UDP/TCP over IPv4/IPv6, reload, clean stop, generation replacement, and ordinary post-stop DNS flow ([`DNS-NATIVE-TESTS.md`](DNS-NATIVE-TESTS.md#L22-L49)). The current IPv4 UDP response timeout is the immediate blocker. Add and pass driver-backed tests for companion/driver crash, failed readiness, restart, sleep/resume, interface/address changes, and bounded cleanup; the current design retains resources on uncertainty, which still needs acceptance evidence ([`DNS-PROTECTION.md`](DNS-PROTECTION.md#L171-L190)).
3. **Enable the switch only after gates 1–2, then verify UX.** Verify restart, feed refresh/update, disable, recovery status, and cleanup messaging in the native app. Verify VPN/NRPT/per-application routing and decide/document treatment of encrypted DoH/DoT/DoQ, which port-53 interception cannot filter ([`DNS-PROTECTION.md`](DNS-PROTECTION.md#L211-L213)).
4. **Measure before optimizing or promising performance.** Run sustained-load, packet-loss, long-running generation/rollover, topology churn, and representative Windows 10/11 acceptance. The native fixture criteria exclude VPN/NRPT equivalence, rollover, loss, and performance ([`DNS-NATIVE-TESTS.md`](DNS-NATIVE-TESTS.md#L51-L53)). Current review hypotheses are **unmeasured**: one-second native snapshots, per-snapshot process enumeration and base64 icon cloning, and the 65,535-byte per-query UDP buffer in [`src-dnsproxy/flow_upstream.go`](../src-dnsproxy/flow_upstream.go#L139-L168). Capture hidden-app, visible-app, and DNS-active baselines before changing these paths.
5. **Make the chosen release channel operable.** Record the installer/portable choice, trust and signing policy, update channel, rollback behavior, privilege model, and support policy; then verify the selected distribution's artifacts, upgrade/uninstall behavior, and provenance. Signing is preferred but is a policy/distribution decision rather than an automatic technical blocker if a stable portable channel explicitly accepts the trust model. The current build is explicitly an unsigned alpha with no stable binary release ([`README.md`](../README.md#L45-L47)); `build:native` uses `tauri build --no-bundle` ([`package.json`](../package.json#L7-L13)), and CI only uploads a 14-day review archive ([`windows.yml`](../.github/workflows/windows.yml#L53-L64)).

## PR3 status

The PR3 implementation is **partially complete**: backend protocol and lifecycle work is implemented and broadly unit-tested; product integration, kernel-backed native acceptance, crash/topology/restart behavior, cross-process exclusion, and performance/accuracy evidence remain unfinished. The roadmap itself still lists privileged separation and release hardening as future work ([`ROADMAP.md`](ROADMAP.md#L7-L10)), while the current application elevates the whole app ([`README.md`](../README.md#L86)). Appcapture remains explicitly partial ([`README.md`](../README.md#L78-L79)), so it should not be advertised as complete in a stable release.

### Open PR disposition

| Work item | Current disposition | Release implication |
| --- | --- | --- |
| PR3 / transparent DNS | Draft; backend work present, native IPv4 session currently times out | Blocking until native and product gates pass |
| PR4 / Windows API update | Breaks the current Windows API surface | Do not merge without a compatibility fix and native retest |
| PR5 / `sha2` update | `LowerHex` breakage reported | Do not merge without a fix and build/test retest |
| PR6 / `base64` | Green on its older base; retest against the integrated code | Dependency maintenance, not a DNS prerequisite |
| PR8 / `window-vibrancy` | Green on its older base; integrated checks and native visual regression required | Dependency maintenance before UI release |
| PR9 / `lucide-react` | Green | Review/merge decision separate from DNS readiness |
| PR10 / `oxlint` | Green | Review/merge decision separate from DNS readiness |
| PR11 / Node 26 types | Deferred because the supported runtime remains Node 24 | Intentional policy; revisit with a runtime upgrade |

The open dependency work is release hygiene rather than a reason to claim readiness: Windows-targeted `glib` is absent from the locked MSVC tree, while the known `glib` advisory remains cross-platform debt documented in [DEPENDENCIES.md](DEPENDENCIES.md). Re-run dependency audits immediately before publishing and do not describe the project as vulnerability-free.

## Policy decisions that must be recorded

These are not substitutes for the technical gates: whether the first channel is signed MSI/NSIS or portable, whether DNS protection is enabled by default, whether VPN/NRPT equivalence is supported or explicitly out of scope, how encrypted DNS is communicated, and whether whole-app elevation is acceptable for an alpha-only channel. A signed alpha may still be an alpha; a stable portable release may deliberately use an unsigned trust model if that policy is explicit, documented, and validated for its audience.

## Next session

No PR has been merged and no public release has been built or published. The owner ended the native test session; do not request further elevation until another owner-present session is agreed.

The immediate action is to localize the IPv4 UDP timeout using test-only aggregate counters at capture, flow registration, injection and reverse reception. Do not increase timeouts or enable the UI to bypass this failure. A possible loopback injection-direction mismatch remains an unverified hypothesis. After reviewing the diagnostic evidence, fix the demonstrated cause, rerun the exact sequential native suite, and only then continue with the remaining ownership/product gates. Keep traces and local DNS snapshots out of the public repository.

