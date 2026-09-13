# Roadmap

This is a direction, not a release schedule. Windows usability and measurement correctness come first.

## Next

- Broader alpha feedback, native CPU/memory profiling and sustained-load/event-loss tests.
- Improve appcapture coverage, existing-connection handling, server-side attribution and capture diagnostics.
- Separate privileged operations from the tray UI.
- Harden release packaging and establish signing and update policies.

## Interface and workflow

- Extend the dedicated Firewall page with validated protection sources.
- Extend interface statistics (connection state, traffic and reported link rates) with useful Wi-Fi signal information.
- A global Basic / Advanced view, developed with concrete UI examples before committing to which controls belong in each mode.
- Reliable destination tags with clear provenance and unknown states.

## Curated protection

Investigate reputable threat-intelligence and ad/tracker lists before enabling feed-based blocking. Source quality, redistribution terms, false positives, shared hosting, DNS/DoH/VPN behaviour, safe updates and rollback must be understood first. These features are not implemented yet.

## Platforms

Linux and macOS support are planned. Their collection, firewall, capture and windowing backends require platform-specific implementation and validation; the current native app is Windows-only.
