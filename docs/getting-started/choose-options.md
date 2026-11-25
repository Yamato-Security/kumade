# Choose a collection

## Common jobs

| Goal | Start with | Guide |
|---|---|---|
| Normal unattended artifact collection | `collect --yes -o E:\Evidence` | [First collection](first-collection.md) |
| Current host state only | `live-info -o E:\Live-Inventory` | [Live inventory](../live-info.md) |
| Select a single disk family | `collect --yes --artifact windows.prefetch -o E:\Evidence` | [Catalogue](../collection/catalogue.md) |
| Read selected artifacts from a snapshot | `collect --yes --vss --volume C: -o E:\Evidence` | [VSS](../vss.md) |
| Acquire new RAM and active pagefiles | `collect --yes --memory --dumpit E:\Tools\DumpIt -o E:\Evidence` | [RAM](../memory-acquisition.md) |
| Native NTFS container | `collect --yes --vhdx E:\Evidence` | [VHDX](../vhdx-output.md) |
| Compressed forensic container | `collect --yes --e01 E:\Evidence` | [E01](../e01-output.md) |
| Stream to a remote evidence server | `collect --sftp SERVER ...` | [SFTP](../SFTP.md) |
| Add a process-memory hunt | `collect --yes --scan-processes -o E:\Evidence` | [YARA](../yara-process-scan.md) |
| Collect possible packed PE binaries | `collect --yes --high-entropy -o E:\Evidence` | [Entropy](../high-entropy.md) |
| Copy an entire logical partition | `forensic-copy -s C: -o E:\Evidence` | [Partition imaging](../forensic-copy.md) |

These are example argument sets for `kumade.exe`. The SFTP row is abbreviated;
use its complete setup guide for temporary credentials and the pinned host key.
Live inventory still runs with a narrow disk-artifact selection unless disabled.

## Options that add substantial work

RAM/pagefiles add source writes for staging and large payloads. Entropy discovery
walks selected source drives. YARA scans live process memory. E01 adds compression
and container readback. SFTP adds transport and receiver verification. Combining
features can cost more than adding their isolated timings.

The [benchmarks](../benchmarks/index.md) include both individual options and
combined runs. They are measurements on a specific VM, not completion-time
promises for other systems.

## Modes that cannot be combined

Directory output (`-o`), `--vhdx`, `--e01` and `--sftp` are alternative destinations.
SFTP streams objects rather than uploading a VHDX. `forensic-copy` is a separate
partition-imaging command. Offline directory collection does not run live RAM,
VSS or live process-memory scanning on the analyst's machine.
