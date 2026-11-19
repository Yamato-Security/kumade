# Kumade implementation status

Updated 19 November 2026. The architecture document is the target design;
this file distinguishes it from the code actually implemented.

The first increment uses one Rust package with separate library modules for
catalogue matching, discovery, acquisition, NTFS access, Windows APIs and
verification. Splitting the stable modules into workspace crates remains possible.

## Commands

| Command | Current behavior |
|---|---|
| `collect` / no subcommand | Plan, acquire, hash-verify and seal a new local collection |
| `doctor` | Describe compiled capabilities and unfinished providers |
| `list` | List embedded or explicitly supplied acquisition definitions |
| `plan` | Discover matching files and write a fresh `Plan.json` without copying payloads |
| `verify` | Verify sealed metadata, observation accounting and every referenced payload |

`collect` also accepts `--vhdx FILE` and optional `--vhdx-size-gib GIB` on
Windows. The new dynamic NTFS image holds the acquisition directly. Available
source metadata is inventoried and restored, with explicit partial results for
losses. See [VHDX output](vhdx-output.md) for dependencies and fidelity limits.

No other proposed commands are exposed as working functionality.

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
3. Existing VSS collection and optional controlled creation of owned snapshots.
4. Structural validation using existing Yamato parsers without altering originals.
5. Disk-backed planning, device-aware concurrency, durable resume/cancellation.
6. Portable definition import, streaming archives and cloud transport.

All proposed full-profile definitions should receive positive/versioned fixtures
and independent comparison before a release claims broad production coverage.
