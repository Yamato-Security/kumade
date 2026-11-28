# Kumade implementation status

Updated 27 November 2026. The architecture document is the target design;
this file distinguishes it from the code actually implemented.

The first increment uses one Rust package with separate library modules for
catalogue matching, discovery, acquisition, NTFS access, Windows APIs and
verification. Splitting the stable modules into workspace crates remains possible.

## Commands

| Command | Current behavior |
|---|---|
| `collect` / collection options without a subcommand | Acquire selected artifacts in a directory, VHDX or E01, or deliver them over SFTP or S3 |
| No arguments | Display help without starting collection |
| `check-support` | Describe compiled capabilities and unfinished providers |
| `list-artifacts` | List embedded or explicitly supplied acquisition definitions |
| `collect-test` | Discover matching files and write a fresh `Plan.json` without copying payloads |
| `list-vss` | List existing local shadow copies and their UTC creation times |
| `verify` | Verify sealed metadata, observation accounting and every referenced payload |
| `forensic-copy` | Copy a logical partition to a verified image on a separate external drive; optional VSS |
| `live-info` | Capture structured current host state without ordinary artifact acquisition |
| `scan-processes` | Scan readable live process memory with YARA Forge or local rules |
| `receive-sftp` | Run a temporary upload-only SFTP receiver with automatic trusted readback |
| `update-rules` | Download and validate a compressed YARA Forge ruleset |
| `resume-s3` | Resume uploads from a retained hybrid or fully staged S3 workspace |
| `verify-s3` | Verify an S3 collection independently and optionally restore its files |
| `verify-delivery` | Verify a revoked SFTP delivery and optionally restore a working copy |

`collect` also accepts `--vhdx FILE` and optional `--vhdx-size-gib GIB` on
Windows. The new dynamic NTFS image holds the acquisition directly. Available
source metadata is inventoried and restored, with explicit partial results for
losses. See [VHDX output](vhdx-output.md) for dependencies and fidelity limits.

Acquisition uses the available logical CPU count by default, capped at four;
`-T, --threads` explicitly accepts up to 128 workers. Workers are limited to the number of planned
files when there are fewer files than CPUs. `-v, --verbose` prints each source
file/stream being copied in full, one line per attempt, instead of displaying
the progress bar. Parallel copies can appear in any order; their final outcome
is recorded in the manifest. `--quiet` and `--verbose` are mutually exclusive.

The [command reference](commands/index.md) documents the exposed commands and their current help. Proposed capabilities in the architecture are not implied to work.

`collect --e01 FILE` packages the same NTFS acquisition in compressed EWF1
segments. Conversion uses an owned temporary VHDX, read-only disk streaming,
full media-hash verification and a receipt. See [E01 output](e01-output.md) for
segment handling, temporary-space requirements and recovery limits.

`collect --vss` and `forensic-copy --vss` can create owned, crash-consistent
snapshots on native elevated Windows. Artifact collection supports repeated
`--volume` selection. Both normal reads and raw NTFS fallback use the snapshot;
unsupported volumes and snapshot-omitted paging files are explicit partial results,
never a live fallback. Snapshot provenance is retained and only this requester’s
set is cleaned up. Use `list-vss` to enumerate existing copies and `collect --vss-existing` to select
them. See [historical snapshots](vss-existing.md) and [new VSS acquisition](vss.md).

## Integrity and failure behavior

- Every planned file/stream gets a result row, including failed and absent raw candidates.
- Failed partial payloads are retained and identified in the manifest.
- Hash verification uses bounded reads, not whole-file allocations.
- Acquisition overlap merges artifact selectors but preserves logical source paths.
- Source changes since planning or during copying produce `Partial`.
- Incomplete enumeration prevents treating unobserved families as proven absent.
- `Coverage.csv` contains final acquisition counts, not only the original plan.
- `Seal.json` hashes the manifest and all exported metadata. It is not a digital signature.
- CSV/JSONL source timestamps retain available precision. They are not inferred attack times.
- No original evidence is repaired, replayed, decrypted or executed.
- An unset (zero) NTFS timestamp becomes `null` in UTC metadata rather than an
  invented observation at the Windows epoch; original acquired bytes are retained.

Exit `0` means complete **within the selected prototype scope**, `2` is a fatal
argument/environment/verification error, and `3` is a partial collection. The
full design's more granular exit codes are not implemented yet.

## Windows qualification

The Windows x64 target is compile-checked locally with MinGW and tested with
MSVC in platform CI using offline fixtures. This does not establish runtime
correctness of privilege, volume, locked-file or
device-control operations on every Windows build. Synthetic NTFS tests exercise
the shared read engine without mounting an image or using a driver.

Targeted Windows 11 ARM64 tests cover fixed/GUID volumes, Prefetch collection,
raw metadata, a live locked SYSTEM hive and VHDX metadata round trips. Windows
x86/x64 CI now creates, inspects read-only and detaches a synthetic NTFS image.
These checks do not qualify every Windows build, filesystem or security policy.
No live company system or private company evidence is used in platform CI.

## Remaining milestones

1. Broader Windows runtime and filename/metadata qualification, directory-mode
   ADS discovery, inaccessible-directory raw enumeration,
   custom event-log locations. Active pagefile discovery is implemented for RAM-paired acquisition.
2. Broader memory-provider/Windows-version qualification and independent timing/range
   validation. External DumpIt and paired active-pagefile acquisition are implemented;
   there is no automatic untrusted helper download.
3. Broader historical VSS/provider qualification and application-writer coordination.
   Existing copies are listed by `list-vss` and collected with `--vss-existing`.
4. Structural validation using existing Yamato parsers without altering originals.
5. Disk-backed planning, device-aware concurrency and resuming interrupted local acquisitions.
6. Portable definition import, streaming archives and additional cloud destinations.

All proposed full-profile definitions should receive positive/versioned fixtures
and independent comparison before a release claims broad production coverage.


## High-entropy PE discovery

`--high-entropy` adds an optional selected-source PE walk. During collection,
selected artifacts are preserved first and entropy analysis is deferred until
after that acquisition; `collect-test` can inspect candidates without copying payloads.
The scanner opens files whose extension is on the selected list (`standard`
PE names by default, `broad` and `comprehensive` levels, added names, or every
file with `--entropy-all-files`), recognizes PE32/PE32+ by header signatures
regardless of what the name claims, measures logical on-disk bytes, hashes each
analyzed PE and adds qualifying unnamed streams to the existing acquisition plan. Directory, VHDX and E01
share that plan and sealed reports. An acquired-content mismatch is partial.
The default evaluates executable sections of at least 4096 bytes at 7.2
bits/byte; whole-file/either criteria and explicit resource limits are available.
It does not unpack binaries, validate Authenticode signatures, enumerate deleted
files or interpret entropy as a malware verdict. See [the guide](high-entropy.md).


Interactive collection now has a [size-estimating wizard](collection-wizard.md).
The paging and dedicated hibernation families are off by default; `--paging`
enables the broad paging family, and `--hibernation` adds just `hiberfil.sys`.
Explicit artifact selection is also supported. See [hibernation acquisition](hibernation-acquisition.md).
`--no-wizard` suppresses prompts for automation. Optional embedded
process-memory YARA runs use the existing engine and are sealed with the
collection, including native container output.

## RAM, live inventory and remote delivery

External DumpIt acquisition captures RAM first and pairs active pagefiles by
default. Live inventory supplies 59 structured datasets. SFTP streams disk
payloads with metadata staging; RAM additionally requires an explicit protected
staging parent. The receiver revokes its temporary credential and validates
stored/decoded hashes. See [RAM](memory-acquisition.md), [live inventory](live-info.md)
and [SFTP](SFTP.md).

[Amazon S3 delivery](S3.md) defaults to a hybrid workspace for volatile evidence
and upload receipts. Disk files stream to the bucket. Use `resume-s3` to publish
recoverable evidence after an interruption and `verify-s3` for independent
readback. `--s3-recovery-dir` stages the full case. `--s3-direct` streams a
collection without a restartable workspace.

The [published benchmarks](benchmarks/index.md) include 38 measured runs on
Windows 11 ARM64, including RAM/pagefiles, VSS, containers, entropy, YARA and
SFTP. These are qualified observations on that VM, not universal completeness
or performance claims.
