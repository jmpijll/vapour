# Contributing

Vapour is an early Windows-first project. For large changes, open an issue first so implementation and UX expectations can be agreed before substantial work begins.

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

Explain the user-visible change and relevant verification. Include sample-data screenshots for visual changes. Keep recordings, private logs, generated executables, credentials and local machine paths out of commits. New dependencies need provenance and license review. Do not broaden a capture or firewall rule when an exact scope cannot be established.

## Reports

Include Windows version, build steps, expected behaviour and concise reproduction steps. Redact private data. Report security-sensitive details privately to the maintainer through a suitable private channel; do not post secrets or exploit-bearing private captures in a public issue.

`pnpm exec playwright test` starts an isolated browser preview and checks Basic/Advanced behavior in installed Microsoft Edge.

Dependency updates and outstanding upstream warnings are documented in [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md). Use Node 24 LTS and the pinned Rust toolchain when reproducing CI.
