# Changelog

## Unreleased

- Name collections and automatically named VHDX/E01 files with the hostname and UTC run start time; store evidence directly under drive-letter directories. A bare `--vhdx`/`--e01` uses the `Kumade-Results` directory beside the executable, like `-o`. Live collection keeps the catalog scope on every local fixed volume; the volume holding the destination is excluded by volume identity (the running Windows volume is always acquired), and volumes without a readable file system are recorded as excluded instead of failing the run. Offline source directories cannot take a collection metadata name such as `LiveInfo`.

- Add live-response inventory with 59 read-only Windows providers, PascalCase CSV/JSON/JSONL, bounded concurrency/deadlines/output, provider diagnostics and integrity seals. Capture volatile state before live file collection, including VHDX/E01 output. Add inventory-only `live-info`, provider selection, format selection and `--no-live-info`; offline scans never query the analyst host.

- Add `--e01 FILE` to package a collection in compressed EWF1 physical segments,
  with the VHDX backend's NTFS metadata and native ADS preservation. Reopen the
  staging disk read-only, encode with bounded segment scratch, verify the full
  media and publish a receipt last. Retain staging on failure and refuse existing
  segment sets. Add `--e01-size-gib` for automatic/explicit NTFS capacity.
  Source builds now require Rust 1.99 or later for the native EWF library.
- Read the metadata of a file Windows refuses to open, such as the in-use
  `pagefile.sys`, from the raw `$STANDARD_INFORMATION` as for NTFS system
  files, so a default live `--vhdx` or `--e01` run no longer ends partial with a
  metadata error for the paging file. Only metadata-open failures use this fallback;
  failures while reading identity, security or extended attributes retain captured
  fields and remain visible as metadata errors.
- Size evidence containers to hold their largest stream at its logical size: a
  sparse copy keeps a USN journal's `$J` at that size, and The Sleuth Kit rejects
  an NTFS run longer than the volume. An E01 run refused before staging leaves
  no empty staging directory behind.

- Default acquisition workers to the available logical CPU count (at most 128), show help
  when no arguments are supplied, and add `-v, --verbose` to list each source
  file/stream being copied instead of displaying a progress bar.
- Keep permission-sensitive ACE order and absent/empty ACL distinctions in
  VHDX metadata readback checks; size worker reserve slack from active workers.

- Add opt-in `--vhdx FILE` collection into a fresh dynamic NTFS container,
  with automatic/explicit virtual capacity and physical host-space checks.
  Preserve file/directory basic timestamps, owner/group, ACLs, attributes,
  extended attributes and native named streams; seal metadata inventories and
  report incomplete preservation as partial. Raw-only NTFS metafiles take their
  basic information and sizes from the raw provider, a container reserve keeps
  room for the manifests and seal, and kernel-namespace extended attributes and
  protected-DACL normalization are noted instead of counted as errors. See the
  VHDX guide for limits.

- Add a green Kumade terminal banner, green output labels with white values,
  and a Hayabusa/Juntei-style progress bar with a green spinner, file counters,
  percentage and a filename/size line. Keep redirected output uncolored.

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
