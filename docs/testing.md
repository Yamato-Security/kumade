# Local validation

Validation date: 18 November 2026. Version: `0.1.0`.

## Automated checks

- `cargo fmt --check`: passed.
- Local Linux `cargo test --all-targets`: 57 tests passed (49 core, 4 CLI,
  4 unit tests). Windows excludes three Unix-only symlink tests.
- Native Linux ARM64 and Windows x64 Clippy checks with `-D warnings`: passed.
- Release builds: Linux ARM64 and Windows x64 (MinGW cross-build).
- Windows executable imports were inspected: only Windows system libraries are
  required. This is an import-table check, not a Windows runtime test.

The release workflow builds eight platform packages with Rust 1.100.0 and the
locked dependency versions. Native CI covers Windows x64, Linux and macOS
ARM64; Windows ARM64 and macOS x64 packages are cross-built. Windows MSVC
packages statically link the C runtime; Linux musl packages are static.

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

The available Windows VM was unreachable during this run. Test the native
Windows executable on controlled systems before production use: privilege
adjustment, device geometry, locked hives/event logs, access-denied directories,
long names, destination ACLs and FAT/exFAT behavior all need live qualification.
Memory, VSS and cloud providers are not implemented and are not counted as
successful acquisition capabilities.

Rust also reports a future-compatibility warning for transitive dependency
`binrw 0.11.3` through `ntfs 0.4`; current checks and builds succeed.
