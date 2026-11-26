# Capabilities and limits

## Choose the right mode

| Capability | Current scope | Important limit |
|---|---|---|
| Live artifact collection | Native Windows, elevated for raw/locked evidence | Inaccessible directories and unsupported raw content remain explicit gaps |
| Offline collection | Mounted Windows directory trees | Does not automatically mount disk images or dump the analyst's RAM |
| Live inventory | Windows providers for current host state | Observations can change during collection; unavailable providers are recorded |
| Physical RAM | Separately supplied, hash-checked DumpIt | Requires native architecture, privileges, compatible driver/security policy and staging |
| VSS | New crash-consistent snapshots plus opt-in existing-copy collection/listing | No application-writer coordination; historical consistency is unknown; only selected artifact paths are copied |
| YARA | Readable live Windows process memory | Protected pages, exits, timeouts and rule semantics limit coverage |
| Entropy | Readable on-disk PE content | A high-entropy binary is a candidate, not a malware verdict |
| VHDX / E01 | Windows NTFS evidence containers | Additional space/finalization work; fidelity has explicit limits |
| SFTP | Concurrent collectors and automatic reconnect with the built-in receiver | Needs trusted receiver readback; RAM still needs staging |
| Partition imaging | Logical partition to `.dd` on a separate physical disk | Not a physical whole-disk image or an atomic live acquisition |

Use `kumade doctor` with the binary and architecture you intend to run.
A successful cross-build is not qualification of every Windows version.
The [validation history](../testing.md) and [benchmarks](../benchmarks/index.md)
state the actual tested environments.

## Integrity, consistency and completeness are different

**Integrity** asks whether the retained bytes match the recorded hashes.
**Consistency** asks whether the related evidence represents a coherent point
in time. **Completeness** asks whether the requested, applicable evidence was
actually obtained. A verified partial collection remains partial.

Live reads, inventory queries, memory acquisition and output writes can change
the endpoint. VSS is crash-consistent, not application-coordinated. Preserve
source evidence where possible and review the [acquisition order](../acquisition-order.md)
and [verification reports](../output/verification.md).

## Current development limits

General raw enumeration of inaccessible directories, structural validation by
artifact parsers, application-writer VSS coordination, resume after a process restart and cloud upload
are not implemented. Standard catalogue paths may miss custom application
stores. Raw compressed/encrypted/reparse-backed content is refused rather than
reported as correct logical content. See [implementation status](../implementation-status.md).
