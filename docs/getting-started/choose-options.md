# Choose a collection

## Common jobs

| Goal | Start with | Guide |
|---|---|---|
| Normal unattended artifact collection | `collect --no-wizard -o E:\Evidence` | [First collection](first-collection.md) |
| Current host state only | `live-info -o E:\Live-Inventory` | [Live inventory](../live-info.md) |
| Select a single disk family | `collect --no-wizard --artifact windows.prefetch -o E:\Evidence` | [Catalogue](../collection/catalogue.md) |
| Include hibernation in a restricted disk selection | `collect --no-wizard --hibernation -o E:\Evidence` | [Hibernation](../hibernation-acquisition.md) |
| Read selected artifacts from a snapshot | `collect --no-wizard --vss --volume C: -o E:\Evidence` | [VSS](../vss.md) |
| Collect from the newest existing snapshot on each selected volume | `collect --no-wizard --vss-existing newest -o E:\Evidence` | [Historical VSS](../vss-existing.md) |
| Acquire new RAM and active pagefiles | `collect --no-wizard --memory --dumpit E:\Tools\DumpIt -o E:\Evidence` | [RAM](../memory-acquisition.md) |
| Native NTFS container | `collect --no-wizard --vhdx E:\Evidence` | [VHDX](../vhdx-output.md) |
| Compressed forensic container | `collect --no-wizard --e01 E:\Evidence` | [E01](../e01-output.md) |
| Stream to a remote evidence server | `collect --sftp SERVER ...` | [SFTP](../SFTP.md) |
| Deliver to an S3 bucket with a protected workspace on `E:` | `collect --no-wizard --s3 s3://example-ir-evidence/cases/IR-042/ --s3-hybrid-dir E:\Evidence` | [S3 credentials and recovery](../S3.md) |
| Add a process-memory hunt | `collect --no-wizard --scan-processes -o E:\Evidence` | [YARA](../yara-process-scan.md) |
| Collect possible packed PE binaries | `collect --no-wizard --high-entropy -o E:\Evidence` | [Entropy](../high-entropy.md) |
| Copy an entire logical partition | `forensic-copy -s C: -o E:\Evidence` | [Partition imaging](../forensic-copy.md) |

These are example argument sets for `kumade.exe`. The SFTP row is abbreviated;
use its complete setup guide for temporary credentials and the pinned host key.
Live inventory still runs with a narrow disk-artifact selection unless disabled.

## Options that add substantial work

RAM/pagefiles add source writes for staging and large payloads. Entropy discovery
walks selected source drives. YARA scans live process memory. E01 adds compression
and container readback. Remote delivery adds network transfer and independent readback. Full S3 recovery also needs local space for the entire collection. Combining
features can cost more than adding their isolated timings.

The [benchmarks](../benchmarks/index.md) include both individual options and
combined runs. They are measurements on a specific VM, not completion-time
promises for other systems.

## Modes that cannot be combined

Directory output (`-o`), `--vhdx`, `--e01`, `--sftp` and `--s3` are alternative destinations.
SFTP streams objects rather than uploading a VHDX. `forensic-copy` is a separate
partition-imaging command. Offline directory collection does not run live RAM,
VSS or live process-memory scanning on the analyst's machine.
