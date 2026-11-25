# Changelog

## Unreleased

- Add `list-vss` and opt-in `--vss-existing` collection from existing local
  snapshots. Support all/newest/newest-N-per-volume/GUID selection, structured
  listings, distinct historical source roots and explicit ownership/unknown
  writer provenance. Keep identical historical versions and never delete
  enumerated snapshots. Older snapshot metadata remains readable.

- Acquire physical RAM first with a separately supplied, hash/architecture-checked
  DumpIt toolkit (`--memory`, `--dumpit`). Disable vendor analytics, validate full
  dump structure/length, hash captured bytes and retain failed/partial captures.
  Support directory, VHDX/E01 and SFTP delivery with explicit remote RAM staging,
  bounded diagnostics, deadlines and free-space reserves. Directory imports do not
  budget a duplicate RAM allocation when hard-linking; copy fallback checks the full
  extra size while preserving pending evidence and destination/host reserves.
  Active paging files are copied concurrently with the RAM dump by default
  (`--no-memory-pagefile` skips them), recorded in `Memory/Pagefiles.json`, not
  copied again by `--paging`, and verified like the RAM dump. No vendor tools bundled.

- Add a built-in `receive` command with ephemeral SFTP credentials, append-only
  uploads, expiry/session revocation, quotas and optional source-IP restrictions.
  Verify disk readback automatically and reconstruct exports without Python
  using `verify-delivery`. Share device-name checks with export encoding so
  reserved source names remain recoverable; match IPv4-mapped IPv6 peers to IPv4
  allowlist entries. No OS upload account or OpenSSH service is required.

- Add direct SFTP streaming with pinned SSH host keys, hidden/stdin passwords,
  bounded gzip compression and exclusive remote objects. Preserve locked-file
  acquisition and volatility ordering without local payload staging. Retain
  private metadata on failure; distinguish upload acknowledgements from trusted
  server readback. Include temporary upload-only OpenSSH account provisioning,
  expiry/session revocation, a hash-verifying safe restorer and interoperability
  tests. See `docs/SFTP.md` for setup and forensic footprint limitations.

- Scope automatic entropy output exclusions by source volume, including snapshot
  reads and preserved-copy analysis. Excluding `C:\Evidence` no longer hides
  `D:\Evidence`; explicit user exclusion globs remain global. Record automatic
  paths by `SourceId` in `Settings.OutputExcludes` and accept older settings
  without that optional field.

- Acquire in volatility order: handle RAM requests first, preserve process/network/DNS/logon state before VSS and
  disk planning, then prioritize USN, `$LogFile`, `$MFT`, event logs, registry and
  active databases. Use parallel workers inside priority barriers; keep native
  base files and their ADS together so USN `$J` is not postponed behind bulk
  data. Run slower inventory and optional process YARA after hot disk evidence,
  and defer full-drive entropy analysis until selected artifacts are acquired.
  Analyze already collected files from their verified copies. Import protected
  early live-state staging with hash checks and retain it on failures. Allow
  only newly owned automatic VHDX/E01 staging containers to grow for late
  candidates; never resize source disks or silently exceed explicit capacities.

- Add an interactive collection wizard with per-category and deduplicated total
  logical transfer estimates, explicit unknown sizes, optional VSS, entropy and
  live process YARA scanning, output choices and a partition-imaging path.
  Confirm before snapshots/scans/output; support `--yes`/`--no-wizard` for scripts
  and `--wizard` for explicit guided input. Default paging/hibernation/existing
  dumps off (`--paging` or explicit artifact selection enables them); default
  acquisition to at most four logical CPU workers. Keep hashing, readback
  verification and locked-file fallback enabled. Seal embedded YARA results
  and report incomplete/failed scans as partial, including container output.

- Validate CLR header sizes, metadata bounds/signature and complete managed
  resource ranges before excluding bytes from PE section entropy. Invalid or
  overlapping declarations keep the original bytes in scoring. Clarify that
  the renamed UPX `.dat` example requires comprehensive extension coverage.

- Add opt-in `--high-entropy` drive discovery and collection of PE packing
  candidates, including binaries with misleading filename extensions. Measure
  whole-file and executable-section Shannon entropy with streaming SHA-256,
  bounded scan workers, configurable thresholds/exclusions and optional limits.
  Reuse locked-file raw NTFS and VSS sources; seal PascalCase CSV/JSONL reports,
  detect analysis/acquisition hash changes, and include candidates in directory,
  VHDX and E01 output. Only files whose extension is on the selected list are
  opened: `--entropy-coverage standard` (default: exe dll sys scr com cpl ocx xll
  drv pyd node), `broad` (adds wll ax acm tsp ime bpl efi) or `comprehensive`
  (adds bin dat tmp ini cfg png jpg cmd); `--entropy-extension` adds names and
  `--entropy-all-files` opens everything.
  PE-format files that are not executable images count as non-PE, a malformed
  PE header gets a `Malformed` row instead of failing the run, and `Plan.json`
  keeps settings and counters while the per-file inventory lives only in the
  sealed reports, which `plan` writes beside the plan. Managed assemblies are
  measured without their embedded CLR resources, so satellite `.resources.dll`
  files no longer qualify on compressed strings alone, and `IsManaged` is
  reported. High entropy is a heuristic, not a malware verdict.

- Add opt-in `scan-processes` with Boreal, YARA Forge Core/Extended/Full, local rule sources, CSV/JSONL matches, explicit coverage failures, deadlines and resource measurements. VSS acquisition and process scanning share one native-architecture check, which also rejects the x64 build under the x64 emulation of Windows on ARM64 (not reported as WOW64).

- Add opt-in `--vss` for live artifact collection (directory/VHDX/E01) and
  `forensic-copy`, plus `--volume` selection for live collection. Create an owned
  Microsoft Software Provider snapshot set with crash-consistent, no-writer,
  auto-release semantics; remap both file reads and raw NTFS fallback to it.
  Record snapshot provenance, reject unsupported/emulated requesters, report
  unsupported volumes and VSS-excluded paging data without live fallback, and
  delete only this run's snapshots. Source builds use a small Windows SDK C++
  ABI bridge, statically linked into the executable; VSS is loaded on demand.

- Add `forensic-copy -s C: -o E:\Evidence` to image one logical partition into a
  raw `.dd` file on a different external physical disk. Check actual volume and
  disk identities, available space and filesystem limits before output creation;
  use read-only sector-aligned reads, bounded memory, SHA-256 readback verification
  with the file cache bypassed where sector geometry permits. Recheck the reopened
  image's true length before bounded verification; preserve no-clobber finalization,
  PascalCase JSON receipts and failed output as `.dd.partial`. Hardware-RAID sources
  are supported; unresolved network/pool/file-backed source storage stays refused.
  Document live-volume consistency and unsupported storage limits.

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
