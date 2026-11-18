# Changelog

## Unreleased

- Fix Windows live collection aborting when an accessible recovery or EFI
  volume has no drive letter. Resolve GUID paths consistently for discovery
  and source-containment checks. Record unavailable volumes as discovery
  failures while continuing with accessible volumes.
- Fix raw NTFS acquisition stopping on a Windows volume handle's unsupported
  file-metadata query; obtain its length and sector size through device IOCTLs.

## 0.1.0 — Initial Release — 2026-11-18

- Initial Rust implementation under RPL-1.5.
- Embedded catalogue covering 43 Windows artifact families.
- Collection planning, explicit artifact selection and parallel local acquisition.
- Windows volume/profile discovery, backup privilege setup and read-only raw NTFS
  fallback for files that cannot be opened normally.
- Offline Windows volume-directory collection on Windows, Linux and macOS.
- Bounded copying, sparse output where supported, SHA-256 verification,
  source-change reporting and original timestamps in the manifest.
- CSV/JSONL manifests, coverage/error exports, metadata seals and verification.
- Progress display, fresh protected run directories and free-space preflight.

This is an early development release. RAM capture, VSS, cloud upload, packaging
of collected evidence, resume and comprehensive ADS discovery are not implemented.
`--memory` records a failed RAM task and returns partial status. Live Windows
acquisition still needs controlled endpoint qualification. See
[implementation status](docs/implementation-status.md) and
[validation results](docs/testing.md).
