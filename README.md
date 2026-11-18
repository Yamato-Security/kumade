# Kumade（熊手）

**Windows evidence collection by Yamato Security.**

Kumade is an independent Rust collector under **RPL-1.5**. It acquires evidence
for tools such as Juntei and Hayabusa. This repository contains the first
development implementation.

Download **[Kumade v0.1.0 for Windows x86 (32-bit), x64 or ARM64](https://github.com/Yamato-Security/kumade/releases/tag/v0.1.0)**.
See the release notes for the development limitations and platform validation status.
The archive's executable includes the version and platform in its name; rename
it to `kumade.exe` on Windows or `kumade` elsewhere to use the examples below.

## Implemented

- Embedded acquisition catalog with 43 artifact families, including event logs,
  registry, Prefetch, Jump Lists, SRUM recovery families, browsers, Outlook,
  local GPO/SYSVOL, Defender and standard paging-file locations.
- Offline collection from Windows volume directories on Linux, macOS and Windows.
- Windows fixed-volume/mount-point discovery, profile discovery and backup privilege
  setup. Platform CI exercises offline acquisition; live Windows qualification is pending.
- Read-only raw NTFS fallback for discovered locked files and hidden metadata,
  including resident/nonresident data, named streams and sparse logical content.
- Parallel acquisition, bounded copy/hash buffers, sparse output where supported,
  SHA-256 verification, original access/modified times and separate provenance.
- JSONL/CSV manifests, family coverage, explicit failures, metadata seals and a
  verifier that rejects modified payloads and unsafe manifest paths.
- Protected fresh run directories, no overwrite of existing payloads, source/output
  separation for offline evidence, and terminal progress.

## Run locally

```bash
cargo build --release
./target/release/kumade doctor
./target/release/kumade list

# SOURCE is a Windows volume root containing Windows/Users/ProgramData.
./target/release/kumade plan -d /cases/host/C -o /cases/plans/host --computer HOST01
./target/release/kumade -d /cases/host/C -o /cases/collected --computer HOST01
./target/release/kumade verify /cases/collected/HOST01_<UTC>_<RUNID>
```

On Windows, run an elevated PowerShell session for live collection:

```powershell
.\kumade.exe -o E:\Kumade-Results
```

Without `--source`, only Windows live mode is accepted. Offline mode never
automatically reads the analyst's own Windows directories. Repeat `--source`
for disjoint volume directories; use `--profile-root` for nonstandard profiles.
`--artifact <ID>` explicitly narrows acquisition and records excluded families.
The default reserves 2 GiB of destination space; `--reserve-mib` changes it.

Each run creates `Plan.json`, `Run.json`, `Manifest.jsonl`, `Manifest.csv`,
`Coverage.csv`, `DiscoveryIssues.csv`, `Errors.csv`, `Summary.json` and `Seal.json`.
Payloads retain recognizable paths beneath `Evidence/Live/<SourceId>/`.
Windows-incompatible names are reversibly encoded; exact source paths remain
in the manifest. Very long names use a manifest-mapped hash path.

`Verified` means stored-byte hash verification, **not structural validity or an
atomic snapshot**. Source changes produce a partial result. A seal currently
uses hashes, not an authenticated signing identity.

## Not implemented yet

RAM capture/paired runtime pagefile discovery, VSS acquisition, external processing,
image-source CLI support, archive packaging, cloud upload, resume,
comprehensive ADS discovery and structural artifact validators are pending.

`--memory` currently records an explicit failed RAM task and returns partial
status after collecting supported disk artifacts. It never creates a fake dump
or silently reports memory acquisition as successful. Standard paging-file paths
are included in the disk catalog; custom active pagefile enumeration is pending.

Raw compressed/encrypted/reparse-backed content is rejected rather than copied
as incorrect logical bytes. Directory enumeration failures remain visible;
raw traversal of inaccessible directories is not implemented yet. Planning keeps
the task index in memory; million-file/disk-backed scheduling remains future work.
Use controlled lab data until live Windows and destination-policy testing is complete.

## Development

```bash
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo check --target x86_64-pc-windows-gnu
```

Tests include an attributed, redistributable synthetic NTFS image and generated
fixtures. Private evidence and validation output are kept outside this repository.
The `ntfs` dependency currently brings `binrw 0.11.3`, for which Rust reports a
future-compatibility warning; it does not fail the current build.

See [validation results](docs/testing.md), [implementation status](docs/implementation-status.md),
[architecture](docs/architecture.md) and [reference-tool comparison](docs/tool-comparison.md).

Copyright © 2026 Shirofune Security Co., Ltd. Original Kumade code and definitions
are licensed under [RPL-1.5](LICENSE). Third-party fixtures/dependencies keep their
own licenses; see [fixture provenance](tests/fixtures/SOURCES.md).
