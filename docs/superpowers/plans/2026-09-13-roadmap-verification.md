# Windows roadmap implementation and verification plan

**Goal:** Make every requested roadmap item ready for the owner to test on this Windows system, after independent implementation checks.
**Architecture:** Keep privileged collection/enforcement separate from presentation. Optional collectors expose source, sample time and unavailable/stale states. Build changes in reviewable increments, integrate only after checks.
**Tech stack:** Tauri/Rust, React/TypeScript, Windows networking APIs, source-built LibreSpeed.
**Spec:** `docs/ROADMAP.md`, `docs/INTERFACE-DATA.md`, and the user roadmap requests.

## Constraints

- Windows is the current test platform. Linux/macOS remain explicit roadmap obligations; native verification requires those platforms and must not be claimed from Windows checks.
- Calm neutral UI, minimal necessary text, accessible icon controls, no information button.
- GPL-3.0-only. No private captures, machine identifiers, logs, keys or research artifacts in public commits.
- Basic/Advanced is global and persistent. Changing mode changes presentation, never consent or enforcement.
- Real native tests accompany mocks; do not equate green unit tests with feature completeness.

## Work and acceptance ledger

- [ ] Integrate Firewall PR #1, dependency PR #2 and adapter PR #3 after independent checks; test the combined branch and installable/native preview.
- [ ] Configuration collectors: independent bounded workers, declared buffer lengths, stale/hung reporting, live comparison with Windows. Files: network/ip_config.rs, routes.rs, adapter.rs, monitor.rs, types.rs.
- [ ] Wi-Fi quality: runtime-supported privacy-friendly API, verified units and variable-tail ABI, disconnect/unsupported/invalid payload tests, live adapter test. File: network/wifi_quality.rs; wire cache/types only after review.
- [ ] Driver/DHCP details: driver provider/version/date, optional duplex/negotiation properties with provenance, no inferred values. Slow/cache-only metadata; compare with native tools.
- [ ] Global Basic/Advanced UI: topbar toggle, persisted preference, meaningful information changes on every page. Interface details expose addresses/routes/diagnostics in collapsible sections. Test keyboard, light/dark, narrow windows, unavailable data, mode persistence and no privileged action on toggle.
- [ ] Destination tags: source-backed country/organization labels, unknown states, local/private exclusions, provenance and bounded cache. No guessed security/encryption identities. Test known/unknown/private/IPv6.
- [ ] Threat protection: choose reviewed reusable feeds; bounded validated downloads, atomic last-known-good cache, freshness, rollback and explicit enable/disable. Live isolated enforcement test and control connection; disabling removes only owned rules.
- [ ] Ad/tracker protection: domain-aware enforcement with documented DoH/VPN/shared-host behavior, same update/rollback requirements. Test blocked and allowed domains and cleanup. Do not substitute IP blocking for domain filtering silently.
- [ ] Appcapture coverage: existing sessions, server/inbound traffic, process churn, attribution uncertainty, final diagnostics. Isolated selected/control traffic tests for TCP/UDP IPv4/IPv6; validate exported PCAPNG and data isolation. Partial label remains until scope is actually proven.
- [ ] Privilege separation: authenticated narrow helper protocol, validate all commands and caller, keep tray non-admin, UAC only when necessary. Negative IPC/auth tests and real firewall/capture/ETW roundtrip.
- [ ] Performance/accuracy: idle and active CPU/memory, UI smoothness, long-lived load/event-loss and cancellation, measured transfer byte reference, multiple adapters. Save private evidence outside public repo; publish methodology and aggregate results only.
- [ ] Packaging: reproducible Windows package, dependency notices/corresponding source, signing/update policies, uninstall and owned-rule/driver cleanup; clean install/upgrade/rollback smoke tests. Never claim signed release without signing evidence.
- [ ] Owner review build: one current standalone executable with exact commit/version, clean launch, live measurements, test checklist covering every delivered feature and known limitations. Do not rely on browser sample preview for native acceptance.

## Completion

Every checkbox requires evidence (commit, test output or live observation). Retain unresolved items and external platform/signing constraints; do not shrink the goal to the completed subset.
