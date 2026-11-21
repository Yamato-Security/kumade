# Kumade implementation status

Updated 20 November 2026. The architecture document is the target design;
this file distinguishes it from the code actually implemented.

The first increment uses one Rust package with separate library modules for
catalogue matching, discovery, acquisition, NTFS access, Windows APIs and
verification. Splitting the stable modules into workspace crates remains possible.

## Commands

| Command | Current behavior |
|---|---|
| `collect` / collection options without a subcommand | Plan, acquire, hash-verify and seal a new local collection |
| No arguments | Display help without starting collection |
| `doctor` | Describe compiled capabilities and unfinished providers |
| `list` | List embedded or explicitly supplied acquisition definitions |
| `plan` | Discover matching files and write a fresh `Plan.json` without copying payloads |
| `verify` | Verify sealed metadata, observation accounting and every referenced payload |
| `forensic-copy` | Copy a logical partition to a verified image on a separate external drive; optional VSS |

`collect` also accepts `--vhdx FILE` and optional `--vhdx-size-gib GIB` on
Windows. The new dynamic NTFS image holds the acquisition directly. Available
source metadata is inventoried and restored, with explicit partial results for
losses. See [VHDX output](vhdx-output.md) for dependencies and fidelity limits.

Acquisition uses the available logical CPU count by default, capped at 128;
`-T, --threads` sets the maximum worker count within that limit. Workers are limited to the number of planned
files when there are fewer files than CPUs. `-v, --verbose` prints each source
file/stream being copied in full, one line per attempt, instead of displaying
the progress bar. Parallel copies can appear in any order; their final outcome
is recorded in the manifest. `--quiet` and `--verbose` are mutually exclusive.

No other proposed commands are exposed as working functionality.

`collect --e01 FILE` packages the same NTFS acquisition in compressed EWF1
segments. Conversion uses an owned temporary VHDX, read-only disk streaming,
full media-hash verification and a receipt. See [E01 output](e01-output.md) for
segment handling, temporary-space requirements and recovery limits.

`collect --vss` and `forensic-copy --vss` can create owned, crash-consistent
snapshots on native elevated Windows. Artifact collection supports repeated
`--volume` selection. Both normal reads and raw NTFS fallback use the snapshot;
unsupported volumes and snapshot-omitted paging files are explicit partial results,
never a live fallback. Snapshot provenance is retained and only this requester’s
set is cleaned up. Application writers and existing-snapshot enumeration remain
unimplemented. See [VSS acquisition](vss.md) for prerequisites and limitations.

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
   custom event-log locations and pagefile discovery.
2. Qualified memory-provider interface and paired acquisition with independent
   timing/range validation; no automatic untrusted helper download.
3. Existing VSS enumeration/collection and application-writer coordination.
4. Structural validation using existing Yamato parsers without altering originals.
5. Disk-backed planning, device-aware concurrency, durable resume/cancellation.
6. Portable definition import, streaming archives and cloud transport.

All proposed full-profile definitions should receive positive/versioned fixtures
and independent comparison before a release claims broad production coverage.


## High-entropy PE discovery

`--high-entropy` adds an optional full selected-source walk before collection.
The scanner recognizes PE32/PE32+ by header signatures regardless of filename,
measures logical on-disk bytes, hashes each analyzed PE and adds qualifying
unnamed streams to the existing acquisition plan. Directory, VHDX and E01
share that plan and sealed reports. An acquired-content mismatch is partial.
The default evaluates executable sections of at least 4096 bytes at 7.2
bits/byte; whole-file/either criteria and explicit resource limits are available.
It does not unpack binaries, validate Authenticode signatures, enumerate deleted
files or interpret entropy as a malware verdict. See [the guide](high-entropy.md).
