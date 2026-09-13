# Dependency maintenance

Reviewed 2026-09-13. This records the Windows alpha baseline, not a guarantee that dependencies are vulnerability-free.

## Baseline

| Component | Decision |
| --- | --- |
| Node.js | Node 24 LTS; `.node-version`, package engines and CI agree. |
| pnpm | Latest 11.x patch, 11.27.0; retain the existing package-manager major. pnpm has no LTS promise implied here. |
| TypeScript | Updated 6.0.3 to current 7.0.2; production typecheck/build verified. |
| React / Vite / Tauri JS | Existing lockfile versions are current according to the npm registry check. |
| Lucide | Updated 1.44.0 to 1.45.0. |
| Rust | Explicit 1.98.1 toolchain; Rust does not provide an LTS channel. Cargo package `rust-version` is a minimum, not the selected compiler. |
| Cargo lockfile | Compatible updates for crc32fast, jiff, jiff-core, jiff-static, libredox and smallvec. |
| Go | CI 1.27.1; updated modules require Go 1.26 minimum. Unused CSV/CLI/Markdown dependencies removed with `go mod tidy`. |
| WinDivert | Upstream latest release remains 2.2.2; retain the existing verified x64 download. No support-term guarantee inferred from release age. |
| GitHub Actions | checkout 7.0.1, setup-node 7.0.0 and setup-go 7.0.0, pinned to release commit IDs. Their action runtime is Node 24. |

Dependabot checks npm, Cargo, Go and Actions weekly. Updates require normal pull requests and Windows checks; there is no automatic merge policy.

## Remaining upstream dependencies

The npm audit reports no known advisories. `govulncheck` reports no known reachable vulnerabilities in the Windows speedtest module. Cargo audit reports no entries in its vulnerability category, but DOES report the following advisory warnings; a successful exit status must not hide them:

- **glib 0.18.5 / RUSTSEC-2024-0429:** unsound VariantStrIter implementation. Pulled through Tauri's GTK/WebKit stack. Absent from the Windows MSVC dependency tree. The fixed 0.20 series is not compatible with the GTK 0.18 stack; do not force a cross-major override or dismiss the GitHub alert. Resolve before enabling Linux support.
- **proc-macro-error 1.0.4 / RUSTSEC-2024-0370:** unmaintained; absent from the Windows MSVC tree. Track with the upstream GTK stack.
- **unic-* 0.9.0:** unmaintained Unicode crates brought in by `tauri-utils -> urlpattern`, including Windows build/runtime dependencies. Current compatible Tauri updates retain this chain. No known vulnerability is asserted by the maintenance notice; replacement requires upstream migration or a separately tested fork. This remains technical debt.

Older direct API series (`windows` 0.58, `window-vibrancy` 0.6, `base64` 0.22 and `sha2` 0.10) were also identified. They are not the newest major series; the audit did not identify a security advisory for these versions. Major API migrations need dedicated native regression coverage (ETW, COM firewall, window effects, capture), and are not silently bundled into this dependency refresh. There is no claim of vendor LTS support for these crates.

## Reproduce

```powershell
pnpm outdated
pnpm audit
cargo audit --file src-tauri/Cargo.lock
cargo tree --manifest-path src-tauri/Cargo.toml --target x86_64-pc-windows-msvc -i glib
```

In `sidecar/librespeed`, run `go list -m -u all`, `go test ./...` and `go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...`. Audit databases change; rerun before a binary release. Cargo audit is a separately installed developer tool, not a runtime dependency.

## Primary sources

- [Node release schedule](https://github.com/nodejs/Release#release-schedule)
- [GitHub Actions Node 20 deprecation](https://github.blog/changelog/2025-09-19-deprecation-of-node-20-on-github-actions-runners/)
- [Rust releases](https://releases.rs/)
- [Go release policy](https://go.dev/doc/devel/release#policy)
- [glib advisory](https://rustsec.org/advisories/RUSTSEC-2024-0429.html)
- [WinDivert releases](https://github.com/basil00/WinDivert/releases)
