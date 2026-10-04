# Contributing

Vapour is an early Windows-first project. Each addition or repair starts with a focused GitHub issue containing its user-visible outcome and acceptance criteria. Implement it in one PR, or a short sequence of explicitly dependent PRs. Link the issue with `Closes #number`. Keep unrelated refactors and optimization out of release repairs.

## Local checks

Complete the setup in the README, then run:

```powershell
pnpm lint
pnpm build
node --experimental-strip-types --test src/utils/sessionHistory.test.ts src/utils/speedtest.test.ts
cargo test --manifest-path src-tauri/Cargo.toml --locked --lib
Push-Location sidecar/librespeed
go test ./...
Pop-Location
pnpm build:native
```

Native capture and firewall tests need explicit, isolated test traffic and administrator access. They are not run automatically by ordinary unit tests. Never change a contributor's firewall profiles as an implicit test setup step.

## Design

Keep the interface calm and compact. Prefer familiar icons with accessible labels and useful tooltips to permanent explanatory text. Preserve keyboard navigation, narrow layouts, reduced-motion preferences and both themes. Do not present unavailable measurements as zero or estimates as observed traffic.

## Pull requests

Work on a branch and submit a PR against `main`; do not push product changes directly to `main`. CI checks and builds the exact PR commit and uploads a downloadable review package. After a reviewed PR merges, the same checks run on `main` and a successful build publishes a Windows nightly prerelease. The nightly schedule retries missing releases but skips commits already successfully published. Failed checks never publish. Users download from [Releases](https://github.com/jmpijll/vapour/releases); stable releases remain separate.

Explain the user-visible change and relevant verification. Include sample-data screenshots for visual changes. Keep recordings, private logs, generated executables, credentials and local machine paths out of commits. New dependencies need provenance and license review. Do not broaden a capture or firewall rule when an exact scope cannot be established.

## Reports

Include Windows version, build steps, expected behaviour and concise reproduction steps. Redact private data. Report security-sensitive details privately to the maintainer through a suitable private channel; do not post secrets or exploit-bearing private captures in a public issue.

Dependency updates and outstanding upstream warnings are documented in [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md). Use Node 24 LTS and the pinned Rust toolchain when reproducing CI.
