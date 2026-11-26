<p align="center">
  <img src="art/Kumade-Logo.png" alt="Kumade — Windows Triage Collector" width="480">
</p>

# Kumade（熊手）

**Windows evidence collection by Yamato Security.**

Kumade is an independent Rust collector under **RPL-1.5**. It acquires evidence
for tools such as Juntei and Hayabusa. This repository contains the first
development implementation.

Download **[Kumade v0.1.0 for Windows x86 (32-bit), x64 or ARM64](https://github.com/Yamato-Security/kumade/releases/tag/v0.1.0)**.
See the release notes for the development limitations and platform validation status.
Each Windows build is available as a standalone `.exe` and a ZIP containing
only that `.exe`. Documentation is on this site; license notices accompany the
downloads as `LICENSES.txt`. Rename the executable to `kumade.exe` to use the
Windows examples below.

**[Read the Kumade documentation](https://yamato-security.github.io/kumade/)** —
installation, command reference, collection guides, output formats and benchmarks.

## Collector comparison

**○ Supported · △ Partial or indirect support · × Not provided in the reviewed collector.**
Development activity uses the separate cadence definition in note 6. Tool A–D
are anonymized comparisons of documented collector capabilities, reviewed on
**2026-11-25**. Optional features may require extra configuration or tools.

| Capability | Kumade | Tool A | Tool B | Tool C | Tool D |
|---|:---:|:---:|:---:|:---:|:---:|
| Fast, targeted artifact collection¹ | ○ | ○ | ○ | ○ | ○ |
| Standalone Windows base collector² | ○ | ○ | △ | × | △ |
| Customize collection without rebuilding | ○ | ○ | ○ | △ | ○ |
| Locked-file collection / raw NTFS reads | ○ | ○ | ○ | ○ | ○ |
| VSS-backed artifact collection | ○ | ○ | ○ | × | × |
| RAM capture integration³ | ○ | ○ | ○ | ○ | × |
| Paired RAM + pagefile workflow³ | ○ | △ | △ | × | × |
| `hiberfil.sys` acquisition⁷ | ○ | ○ | ○ | × | △ |
| Structured live-system inventory | ○ | × | △ | × | × |
| YARA scan integration⁴ | ○ | ○ | △ | × | × |
| Automatic YARA Forge Core / Extended / Full rules | ○ | × | × | × | × |
| High-entropy PE discovery and collection | ○ | × | × | × | × |
| Remote evidence delivery over SFTP | ○ | × | ○ | × | ○ |
| Stream SFTP payloads without a local collection archive | ○ | × | × | × | × |
| Built-in SFTP receiver | ○ | × | ○ | × | × |
| NTFS VHDX output container | ○ | × | ○ | × | × |
| Compressed E01 output container | ○ | × | × | × | × |
| Free for commercial engagements⁵ | ○ | ○ | × | ○ | ○ |
| Open-source collector | ○ | ○ | × | ○ | ○ |
| Recent collector-engine development⁶ | ○ | △ | × | × | × |

1. **Speed:** ○ means designed for targeted triage, not a measured speed ranking. Kumade's default C:-only collection took **41s** in the documented Windows 11 ARM64 VM test. The run used 3.460 GiB of allocated output and reported partial source coverage. Other collectors were not benchmarked on that VM. See the benchmark methodology before comparing times.
2. **Standalone:** Kumade and Tool A embed their base acquisition definitions. Tool B uses external definitions and a .NET Framework runtime; Tool C requires supporting DLLs; Tool D's self-contained package unpacks a bundled runtime into a cache. Optional memory providers and rule files are outside the standalone base-collection claim.
3. **RAM and pagefiles:** Kumade invokes a separately supplied DumpIt provider; it does not bundle a memory driver. Tools A–C also integrate external memory utilities. Tool A can add paging files through custom definitions, and Tool B through targets/modules; those are marked △ for the paired capture workflow. Kumade's paired capture is coordinated but is not an atomic RAM/disk snapshot.
4. **Inventory and YARA:** Kumade provides structured live inventory and a built-in process-memory YARA engine. Tool A integrates an external YARA-X executable to scan persistence-linked files. Tool B can invoke external inventory/scanning tools through modules (△); this does not imply a bundled engine or managed YARA Forge downloads.
5. **Commercial use:** This row means no collector license fee for paid third-party engagements, subject to each license. Kumade is RPL-1.5; external memory providers and downloaded rules keep their own terms. Tool B's published terms exclude third-party-network / paid-engagement use, although internal-company, educational and government uses are treated separately.
6. **Development activity:** This row rates visible **collector-engine** activity as of 2026-11-25: ○ ongoing updates, △ intermittent updates, × no public engine update found within the preceding 12 months. Tool A's latest release reviewed was August 2026; Tool B's published engine changelog ends in December 2022; Tool C's latest release was October 2024; Tool D's latest release was February 2021. Tool B's community collection definitions still receive updates, including November 2026; its × does not mean those definitions or vendor support have ended.
7. **Hibernation file:** Kumade can collect `hiberfil.sys` with `--hibernation` or the existing broad `--paging` option; both are off by default. Tool A supplies an opt-in paging/hibernation definition that must be loaded. Tool B includes the file in its supplied memory-files target. Tool C has no hibernation-file collection path in its shipped configuration/source. Tool D can use a user-specified path with its raw NTFS collector, but has no dedicated supplied hibernation definition (△). These ratings describe documented configurations; live locked-file acquisition was not benchmarked across the other tools. VSS excludes the hibernation file, so acquire it without `--vss`.

See the **[comparison guide](https://yamato-security.github.io/kumade/tool-comparison/)**
for capability details and the **[collection benchmarks](#collection-benchmarks)**
for Kumade's measurements.

## Implemented

- [Volatility-aware acquisition](docs/acquisition-order.md): preserve fast live state and hot disk artifacts before bulk data, entropy analysis and compression.

- Interactive [collection wizard](docs/collection-wizard.md) with estimated logical transfer sizes, artifact selection and conservative defaults. `--yes` accepts defaults without prompts for automation; `--paging` opts into large paging/hibernation/existing dump files.

- Optional [hibernation-file acquisition](docs/hibernation-acquisition.md): `--hibernation` adds `hiberfil.sys` without enabling other paging/dump files. The dedicated wizard choice shows its estimated size; existing broad `--paging` selections keep their scope. Uses verified copying and raw NTFS fallback without changing Windows power settings.

- Optional [high-entropy binary collection](docs/high-entropy.md): `--high-entropy` scans selected source drives for PE executable-section packing candidates, copies them through normal acquisition, and records sealed CSV/JSONL analysis with source hashes.

- Optional [VSS acquisition](docs/vss.md) with `--vss`: owned crash-consistent snapshots for locked-file collection and partition imaging, snapshot provenance and automatic cleanup. `--volume C:` selects live collection volumes.

- [Historical VSS collection](docs/vss-existing.md): `--vss-existing` adds existing snapshots; choose all, newest, newest N per volume or a snapshot GUID. `list-vss` lists volumes, IDs and UTC creation times with CSV/JSON/JSONL export. Historical versions retain separate paths and provenance, including identical copies; existing snapshots are never deleted by Kumade.

- [Raw partition imaging](docs/forensic-copy.md): `forensic-copy` reads a logical Windows partition into a `.dd` file on a different external disk, with physical-disk separation checks, SHA-256 readback verification and a JSON receipt.

- [Live-response inventory](docs/live-info.md): 59 structured Windows data sets in CSV, JSON or JSONL, with UTC observation times, PascalCase fields and sealed provenance. Included automatically in live collections; inventory-only `live-info` is also available.

- Embedded acquisition catalog with 44 artifact families, including event logs,
  registry, Prefetch, Jump Lists, SRUM recovery families, browsers, Outlook,
  local GPO/SYSVOL, Defender and standard paging-file locations.
- Offline collection from Windows volume directories on Linux, macOS and Windows.
- Windows fixed-volume/mount-point discovery, profile discovery and backup privilege
  setup. Windows x86/x64 CI includes NTFS VHDX round trips; targeted live
  collection and metadata tests also run on Windows 11 ARM64.
- Read-only raw NTFS fallback for discovered locked files and hidden metadata,
  including resident/nonresident data, named streams and sparse logical content.
- Parallel acquisition, bounded copy/hash buffers, sparse output where supported,
  SHA-256 verification, original access/modified times and separate provenance.
- JSONL/CSV manifests, family coverage, explicit failures, metadata seals and a
  verifier that rejects modified payloads and unsafe manifest paths.
- Protected fresh run directories, no overwrite of existing payloads, source/output
  separation for offline evidence, and terminal progress.
- Optional [NTFS VHDX output](docs/vhdx-output.md) with direct acquisition into
  a dynamic image, native alternate streams and explicit NTFS metadata preservation.
- Optional [compressed E01 output](docs/e01-output.md), with the same NTFS
  preservation, split EWF1 segments, automatic hash verification and a receipt.
- Green Kumade terminal banner and labels, white values, and a green progress
  bar with elapsed time, file counters, percentage, filename and approximate size.
  Redirected output is plain text; `NO_COLOR` disables terminal colors.
- Acquisition defaults to up to four workers (limited by available logical CPUs);
  `-T, --threads` explicitly accepts 1–128 workers. `-v, --verbose` lists each file/stream being copied instead of
  displaying a progress bar. Running without arguments displays help.

## Collection benchmarks

Measured on 2026-11-25 (JST) using Kumade 0.1.0 at commit
[`aa86395`](https://github.com/Yamato-Security/kumade/commit/aa863958b59c750df02d771b48e688ab04895b9e):
Windows 11 ARM64 VM, four virtual CPUs, 4 GiB RAM, with source and output on
the same NTFS virtual disk. All comparisons restrict collection to **C:** with
`collect --yes --volume C:`. “Default” means the feature defaults within that
scope; unrestricted all-volume collection was not benchmarked.

**30 measured runs:** four default controls and two runs per optional configuration.
Values are medians; changes are relative to the default median. Durations are
rounded independently to the nearest second; percentages use unrounded measurements.
Exact seconds remain in the CSV files. Output sizes
below are **allocated disk space**, including collection metadata.

| Configuration | Time | Extra time | Time change | Disk used (GiB) | Extra disk used (GiB) |
|---|---:|---:|---:|---:|---:|
| Default options (C: only) | 41s | — | — | 3.460 | — |
| Without live inventory | 23s | -17s | -42.3% | 3.459 | -0.001 |
| One acquisition worker | 1m 7s | +27s | +65.4% | 3.463 | +0.004 |
| Add RAM only | 1m 38s | +57s | +140.7% | 7.452 | +3.992 |
| Add RAM + paired pagefile | 1m 42s | +1m 2s | +151.7% | 8.138 | +4.678 |
| Add paging artifacts | 47s | +6s | +15.0% | 3.616 | +0.156 |
| Read artifacts from VSS | 44s | +3s | +7.8% | 3.436 | -0.024 |
| VHDX output | 59s | +18s | +44.0% | 3.507 | +0.047 |
| Compressed E01 output | 2m 5s | +1m 25s | +208.5% | 1.660 | -1.800 |
| Add high-entropy PE discovery | 1m 49s | +1m 9s | +169.1% | 3.671 | +0.211 |
| Add YARA Forge Core | 1m 16s | +36s | +87.8% | 3.467 | +0.008 |
| Add YARA Forge Extended | 1m 27s | +46s | +113.8% | 3.477 | +0.018 |
| Add YARA Forge Full | 1m 31s | +50s | +123.9% | 3.479 | +0.019 |
| RAM + pagefile + VSS + VHDX | 2m 12s | +1m 31s | +223.5% | 7.680 | +4.220 |

Default output had **5.180 GiB of logical file lengths but used 3.460 GiB on
disk** because of sparse data. Small size differences also reflect live-log and
filesystem growth; they are not isolated feature-payload sizes. RAM was acquired
with an external DumpIt toolkit; paired pagefiles are enabled by default with
`--memory`, while the RAM-only row uses `--no-memory-pagefile`.

VSS here reads selected artifacts from a crash-consistent snapshot. VHDX/E01
also add NTFS metadata and selected ADS coverage, so these modes are not simply
different encodings of identical directory output. All retained outputs passed
integrity verification, but all runs reported partial source coverage; failures
and partial counts are included in the detailed report.

These are warm-system observations from one VM, without rebooting or clearing
caches between runs. They do not predict USB, network, production-server or
larger-memory-system performance.

See the **[full benchmark report](docs/benchmarks/2026-11-25/README.md)** for
commands, timing ranges, logical file sizes, CPU/memory measurements, temporary
storage observations and collection limitations. Download the
[summary CSV](docs/benchmarks/2026-11-25/Benchmark-Summary.csv) or
[per-run CSV](docs/benchmarks/2026-11-25/Benchmark-Runs.csv) for the measurements.

### Combined scans and SFTP

A follow-up added **eight measured runs**, two per configuration, using the same
sender commit and C:-only scope. YARA uses **Full** from release `20261122`;
entropy uses its standard PE scope and threshold. The three SFTP cases use the
built-in upload-only receiver and default streaming gzip.

| Configuration | Collect / upload | Verified finish | Saved output (GiB allocated) |
|---|---:|---:|---:|
| Local VHDX: RAM + pagefile + VSS + entropy + YARA Full | 7m 19s | 7m 19s | 7.859 |
| SFTP: default artifact and live-inventory options | 3m 16s | 3m 25s | 1.873 |
| SFTP: RAM + pagefile + VSS | 3m 53s | 4m 4s | 4.100 |
| SFTP: RAM + pagefile + VSS + entropy + YARA Full | 8m 14s | 8m 24s | 4.180 |

Values are medians, rounded to the nearest second. The earlier **2m 12s** result
enabled RAM, paired pagefile, VSS and VHDX **without entropy or YARA**. It should
not be described as all scans enabled. These combined measurements capture
feature interactions; adding the separate option timings is not a reliable estimate.

For local VHDX, verified finish is normal collector completion with built-in
verification; the additional independent remount check is excluded. For SFTP,
it includes receiver readback and a successful verification receipt. SFTP and
VHDX/E01 are alternative output modes: the remote cases stream files and metadata,
rather than uploading a VHDX. RAM/pagefiles still require explicit local staging.

The receiver is an eight-CPU Linux ARM64 VM on the same private virtual LAN. Its
storage is ext4 in a loop image backed by host-shared storage. Both VMs share the
physical host/storage; these results do not predict WAN or dedicated-server performance.
Partial coverage remains partial after successful integrity verification.

See the **[combined-scan/SFTP report](docs/benchmarks/2026-11-25/Kumade-Combined-Scans-SFTP-Benchmarks.md)**
for ranges, scan phases, staging observations and verification details, or download
the [summary CSV](docs/benchmarks/2026-11-25/Benchmark-Extended-Summary.csv).

## Run locally

Building from source requires Rust 1.99 or later.

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

# Use crash-consistent snapshots of selected live volumes for locked files:
.\kumade.exe collect --vss --volume C: -o E:\Evidence

# Or save the entire acquisition in one new NTFS VHDX:
.\kumade.exe --vhdx E:\Evidence

# Or package the NTFS collection into compressed E01 segments:
.\kumade.exe --e01 E:\Evidence

# List each copied file instead of displaying progress:
.\kumade.exe --vhdx E:\Evidence -v
```

Without `--source`, only Windows live mode is accepted. Offline mode never
automatically reads the analyst's own Windows directories. Repeat `--source`
for disjoint volume directories; use `--profile-root` for nonstandard profiles.
`--artifact <ID>` explicitly narrows acquisition and records excluded families.
The default reserves 2 GiB of destination space; `--reserve-mib` changes it.

For a bit-for-bit logical partition image instead of selected artifact collection,
run from an elevated PowerShell session, with `E:` on a different external disk:

```powershell
.\kumade.exe forensic-copy -s C: -o E:\Evidence
```

This creates `<Hostname>_<UTC>/C.dd` and `ForensicCopy.json`. It does not overwrite
the external disk's partition table or existing files. See [forensic-copy](docs/forensic-copy.md)
for storage restrictions and the consistency limits of live-volume reads.

Each run creates `Plan.json`, `Run.json`, `Manifest.jsonl`, `Manifest.csv`,
`Coverage.csv`, `DiscoveryIssues.csv`, `Errors.csv`, `Summary.json` and `Seal.json`.
Each run directory is named `<Hostname>_YYYY-MM-DD_HH-MM-SS`, using the UTC
start time; there is no random suffix. A repeated host/start time refuses to
overwrite an existing collection. Payloads preserve their original paths directly
beneath their drive letter, with no acquisition-method wrapper directories:

```text
HOST01_2026-11-20_15-23-12/
  C/Windows/System32/config/SYSTEM
  C/Windows/System32/drivers/etc/hosts
  C/$MFT
  C/$Extend/$UsnJrnl/$J
  D/$MFT
  E/$MFT
  LiveInfo/...
  client_info.json
  Manifest.csv
  ...
```

For live collection, every local fixed volume receives the same catalog
scope: each selected artifact family is checked on every volume, so
profiles that `ProfileList` places on a data volume, `$Recycle.Bin`, IIS and
SQL Server logs are acquired wherever they are. NTFS volumes additionally
receive their NTFS metadata files: `$MFT`, `$LogFile`, USN `$J`/`$Max`,
`$Secure:$SDS`, `$Boot` and `$Bitmap`. Unlettered volumes use a stable
`Volume-<id>` folder.

The volume that holds the destination is excluded, except for the running
Windows volume, which is always acquired and noted as a live destination.
Destination matching uses the volume identity, including GUID paths and mount
aliases. Volumes without a readable filesystem (unformatted or BitLocker-locked)
are recorded as excluded rather than failing the run. Removable media is not
acquired by default.
`--artifact` can narrow the scope; explicit offline `--source` inputs keep the
full selected scope.

`--vhdx E:\Evidence` and `--e01 E:\Evidence` create hostname/date-named
containers in that directory. With no value, they use the `Kumade-Results`
directory beside the executable, the same default as `-o`; the shell's current
directory is never used. A full filename remains an explicit override. Both containers contain the same
hostname/date run directory and drive-based layout. A sealed `client_info.json`
host marker lets Juntei group all of the run’s drive folders as one computer.
Windows-incompatible names are reversibly encoded; exact source paths remain
in the manifest. Very long names in directory mode use a manifest-mapped hash path.
For the VHDX layout, metadata fields and fidelity limits, see
[NTFS VHDX output](docs/vhdx-output.md).

`Verified` means stored-byte hash verification, **not structural validity or an
atomic snapshot**. Source changes produce a partial result. A seal currently
uses hashes, not an authenticated signing identity.

## Not implemented yet

Application-writer-coordinated VSS backups, external processing,
image-source CLI support, ZIP archive packaging, resuming after process restart,
general directory-mode ADS discovery and structural artifact validators are pending.
VHDX mode inventories named data streams on selected files.

## Physical RAM acquisition

`--memory` acquires physical RAM first using a separately supplied, hash-checked
DumpIt toolkit. Active pagefiles are copied concurrently by default; use
`--no-memory-pagefile` for RAM alone. Use `--dumpit <toolkit-directory>`; optionally
add `--paging` for other cataloged swap/hibernation/existing dump files. No vendor binaries are bundled.
See [RAM acquisition](docs/memory-acquisition.md) for setup, staging requirements,
architecture selection, verification, failures, containers and SFTP delivery.

## Other limitations

Raw compressed/encrypted/reparse-backed content is rejected rather than copied
as incorrect logical bytes. Directory enumeration failures remain visible;
raw traversal of inaccessible directories is not implemented yet. Planning keeps
the task index in memory; million-file/disk-backed scheduling remains future work.
Use controlled lab data while broader Windows, destination-policy and coverage
qualification continues.

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
[architecture](docs/architecture.md) and [collector comparison](docs/tool-comparison.md).

Copyright © 2026 Shirofune Security Co., Ltd. Original Kumade code and definitions
are licensed under [RPL-1.5](LICENSE). Third-party fixtures/dependencies keep their
own licenses; see [fixture provenance](tests/fixtures/SOURCES.md).

## Process-memory YARA hunting

Use `kumade scan-processes -o Yara-Results` for an opt-in live memory scan with YARA Forge Core (default), Extended, Full or local rules. See [process-memory scanning](docs/yara-process-scan.md) for options, coverage/error reporting and interpretation limits.

## Offline YARA Forge packages

Optional Windows executables ending in `-yara-core.exe`, `-yara-extended.exe`
or `-yara-full.exe` contain that compressed ruleset and scan without extracting
rules onto the target. Decompression and compilation happen in memory. The
standard executable also accepts Forge ZIPs with `--rules` / `--yara-rules`.

```powershell
kumade update-rules --ruleset core
kumade update-rules --ruleset extended
kumade update-rules --ruleset full
```

Updates save versioned ZIP files beside the executable by default; use `-o` to
choose another directory. Use the ZIP path printed by the command;
the bundled executable is not rewritten. See the [YARA guide](docs/yara-process-scan.md)
for offline use, provenance, build variants and rule licensing.

## Amazon S3 delivery

Use `kumade collect --s3 s3://example-ir-evidence/cases/IR-042/ --yes` with
temporary AWS credentials. Hybrid delivery is the default. Requested RAM, paired
pagefiles, live tables and upload receipts stay in a protected workspace beside
the executable. Ordinary disk evidence streams directly to S3. For live collection,
run Kumade from a separate evidence volume or use `--s3-hybrid-dir E:\Evidence`.

After an interruption, `resume-s3` recovers the original volatile data and
identifies which disk files reached S3. Use `verify-s3` on the analyst workstation
for SHA-256 readback and optional restoration. [S3 permissions and setup](docs/S3.md)

Choose `--s3-recovery-dir E:\Evidence` to stage the full collection, or
`--s3-direct` for direct streaming without a restartable workspace.
[Compare the three S3 modes](docs/S3.md#hybrid-collection)

## Remote SFTP delivery

Start a built-in receiver with `kumade receive --listen 0.0.0.0:2222 --output <DIR> --expires 2h`. Add `--sources 6` to collect from six computers on the same port. Give each computer its own temporary credentials. Each gets a separate inbox and verified receipt. If the network drops while both Kumade processes are running, the collector automatically tries to reconnect and continues from the last byte the receiver accepted. See [built-in receiver setup and native restoration](docs/SFTP-Receiver.md).

Use `collect --sftp HOST --sftp-user USER --sftp-host-key "SHA256:..."` to stream payloads without local copies. A hardened temporary upload-only account and trusted server readback are required. See [setup, integrity verification and forensic footprint](docs/SFTP.md).
