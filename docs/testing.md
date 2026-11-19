# Local validation

Validation date: 18 November 2026. Version: `0.1.0`.

## VHDX metadata round trips (19 November 2026)

The new `scripts/test_vhdx.ps1` creates synthetic NTFS files and validates a full
container round trip with independent Windows/.NET queries:

- Five payloads, including two native alternate streams and a 64 MiB sparse file.
- Six metadata records for files and their containing directories.
- All four NTFS basic timestamps at 100 ns precision, owner/group, protected and
  inherited ACL state, audit SACL, extended attributes and file attributes.
- Independent SHA-256 matches, native sparse allocation, refusal to overwrite an
  existing image, clean detach and read-only verification.
- An unchanged image SHA-256 after the complete read-only inspection.

The round trip passed with Windows x86 and x64 collectors on Windows CI and
with the ARM64 package on Windows 11 ARM64. The tests preserve observed source
access times; OS source reads can update access times before metadata capture.

A separate Windows 11 ARM64 live test collected the locked SYSTEM hive into a
VHDX through `RawNTFS`: **14,942,208 bytes**, five file/directory metadata records,
zero metadata errors, independent stored-payload hash agreement and successful
`kumade verify`. Live payloads and their metadata remain outside this repository.

On that Windows 11 VM, reading a read-only mount updated NTFS's cached access
times. Its image SHA-256 remained unchanged; remounting showed the saved times
again. The test therefore checks persisted timestamps before data reads and
compares the image hash after inspection, instead of treating cached values as
on-disk evidence modification.

Additional regression checks cover CLI conflicts, capacity arithmetic/overflow,
physical host reserves, extra sealed metadata inventories, native stream path
validation, file-generation identity checks, sparse raw-reader context and
existing/dangling-link image destinations. Existing directory acquisition and
verification tests continue to pass.

## Live Windows Server 2025 runs (19 November 2026)

Elevated live runs on a Windows Server 2025 system with two NTFS volumes
(`C:` 160 GB, `D:` 80 GB) checked the container path against the NTFS metafile
artifacts and `windows.registry.system`, with directory mode as the control.

Before the fixes in this branch, the metafile selection reported 6 discovery
errors and 19 metadata errors on 192 verified payloads: Win32 cannot open
`$MFT`, `$LogFile`, `$Boot`, `$Bitmap`, `$Secure` or `$Extend\$UsnJrnl` by
name, the registry hives carry the kernel-only `$KERNEL.CFDONOTCONVERT`
extended attribute, and the data volume root's non-auto-inherited DACL came
back protected. A 1 GiB container was filled by the 1,400,373,248-byte
`C:\$MFT` because no reserve applied inside the image, leaving 4,358,144 bytes.

After the fixes:

- Metafiles (`windows.ntfs.*`, both volumes): 12 collected, 2 legitimately
  absent, 0 discovery errors, 0 metadata errors,
  `CompleteWithinSelectedPrototypeScope`, exit 0. The 13 `RawBasic` rows had
  their destination creation/write FILETIMEs and attributes confirmed
  independently with .NET; `kumade verify` checked 14 payloads. Raw sizing
  reported 4.7 GiB (allocated clusters of `$MFT` and `$UsnJrnl:$J`), the
  automatic capacity was 7 GiB and the image used 1.5 GiB on the host.
- `windows.registry.system` plus `windows.ntfs.volume`: 0 metadata errors. The
  five hives with the kernel extended attribute and the `D:` root were
  `Restored` with notes; the remaining partial/failed records are the same
  reparse-point and changed-during-read cases that directory mode reports.
- `--vhdx-size-gib 1` for the metafiles is refused before the image is created,
  because the raw sizes exceed that capacity.

The branch's `scripts/test_vhdx.ps1` round trip passed on the same system with
the fixed tree.

Tested Windows versions for the container path: Windows Server 2025 (live and
CI), Windows Server 2022 (CI) and Windows 11 ARM64. Windows 10 builds before
1703 and Windows Server 2016 have not been exercised; the security capture falls
back to the information mask those kernels understand, but the fallback itself
is untested.

The following sections retain the initial release validation for context.

## Automated checks

- `cargo fmt --check`: passed.
- Local Linux `cargo test --all-targets`: 57 tests passed (49 core, 4 CLI,
  4 unit tests). Windows excludes three Unix-only symlink tests.
- Native Linux ARM64 and Windows x64 Clippy checks with `-D warnings`: passed.
- Release builds: Linux ARM64 and Windows x64 (MinGW cross-build).
- Windows executable imports were inspected: only Windows system libraries are
  required. This is an import-table check, not a Windows runtime test.

The release workflow builds Windows x86 (32-bit), x64 and ARM64 packages with Rust 1.100.0
and the locked dependency versions. Native CI covers Windows x64 plus Linux
and macOS for development testing. Windows ARM64 is cross-built. Windows MSVC
packages statically link the C runtime. Windows x86 tests run on the x64 Windows
runner through WOW64; this does not qualify live acquisition on a native 32-bit
Windows installation. Use the x64 package for live collection on x64 Windows.

Each platform publishes a standalone executable and a ZIP holding only that
executable. License notices are a separate `LICENSES.txt` release asset. The
packaging check verifies the ZIP's single member and its byte equality with
the standalone download. Checksums cover both formats and the license notices.

Release preparation caught and fixed a musl `renameat2` link failure, added
macOS descriptor-based source-path validation, and stopped treating zero NTFS
timestamps as real observations at the Windows epoch. Regression checks cover
exclusive commits, unset timestamps and real 100 ns timestamp precision.

The tests cover synthetic resident, nonresident and sparse NTFS data, bounded
copying, source-change handling, matching/pruning, path safety, destination
collisions, partial acquisition, manifest accounting and tamper rejection.
Fixture provenance and license notices are in `tests/fixtures/`.

## Six-host directory evidence test

The embedded 43-family catalogue was used to plan collection from six existing
Windows volume-directory exports. The full plans discovered **3,174 files,
5,209,459,592 bytes**. Planning reported no directory enumeration issues.

A focused acquisition then selected `windows.prefetch`, `windows.srum`,
`windows.recent` and `windows.amcache`. This avoids unnecessarily duplicating
all multi-gigabyte event-log payloads while exercising real artifact paths,
recovery companions, multiple profiles and both directory and file outputs.

| Host | Full-plan files | Focused payloads | Copied bytes | Independent SHA-256 matches |
|---|---:|---:|---:|---:|
| OSAKA | 474 | 15 | 1,580,595 | 15 |
| KOFU | 454 | 15 | 1,633,843 | 15 |
| HIROSHIMA | 404 | 15 | 1,752,611 | 15 |
| SHIRAKAWA | 486 | 15 | 2,503,219 | 15 |
| SAKAI | 460 | 15 | 1,977,891 | 15 |
| AZUCHI | 896 | 269 | 13,147,464 | 269 |
| **Total** | **3,174** | **344** | **22,595,623** | **344** |

Every focused run completed within its explicitly selected prototype scope.
`kumade verify` passed for all six runs. An independent Python standard-library
SHA-256 calculation also matched each original source file to its stored copy
and manifest hash. Private payloads, manifests, absolute evidence paths and
validation scripts remain outside this repository.

These checks establish discovery and byte-preserving copying for the tested
inputs. They do not establish complete coverage of every Windows artifact,
structural validity of the artifacts, an atomic snapshot, live locked-file
correctness, or performance on an active Windows endpoint. NTFS raw acquisition
was tested with the redistributable synthetic image, not a live Windows volume.

## Outstanding qualification

The initial validation could not reach the Windows VM. The targeted live tests
above now cover several of those gaps. Broader controlled-system testing remains
necessary before production use: privilege
adjustment, device geometry, locked hives/event logs, access-denied directories,
long names, destination ACLs and FAT/exFAT behavior all need live qualification.
Memory, VSS and cloud providers are not implemented and are not counted as
successful acquisition capabilities.

Rust also reports a future-compatibility warning for transitive dependency
`binrw 0.11.3` through `ntfs 0.4`; current checks and builds succeed.
