# Third-party components

- **LibreSpeed CLI:** modified source is included in `sidecar/librespeed`, based on upstream commit `b660d1e6c24f14fc93624538d9e73163e7784335`. See its README, LICENSE and COPYING for provenance, modifications and LGPLv3 terms.
- **WinDivert 2.2.2-A:** fetched from the official release by `scripts/setup-windivert.ps1`, rather than committed as a binary. The upstream dual-license text is preserved in `src-tauri/vendor/windivert/LICENSE`; Vapour uses the LGPLv3 option. Upstream source: https://github.com/basil00/WinDivert/tree/v2.2.2. Future binary distributions must include the appropriate corresponding source and notices.
- **Inter:** SIL Open Font License; see `licenses/Inter-OFL.txt`. Font assets are supplied by the locked font package.
- **Tauri, React, Lucide and other package dependencies:** retain their upstream licenses. Exact package versions are recorded in the JavaScript, Rust and Go lockfiles.

This source repository is not a claim that binary-release license and signing review is complete. Release artifacts need their own dependency and notice audit.
