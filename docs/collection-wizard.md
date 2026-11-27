# Collection wizard

A collection needs an output: `-o DIR`, or `--vhdx`, `--e01`, `--sftp` or `--s3`.
Once an output is given, `collect` runs the wizard. It asks which evidence and
optional features to use, shows estimated logical transfer sizes, and confirms
before snapshots, entropy analysis, process scanning or evidence output.
`collect` on its own shows help. `plan` remains a noninteractive planning command.

```powershell
# The wizard:
.\kumade.exe collect -o E:\Evidence

# Scripted collection: the defaults and explicit command-line options, without the wizard:
.\kumade.exe collect --no-wizard -o E:\Evidence
.\kumade.exe collect --no-wizard --paging --vss --vhdx E:\Evidence

# Optional process scan. The standard binary defaults to Core, bundled binaries to their embedded pack:
.\kumade.exe collect --no-wizard --scan-processes -o E:\Evidence
.\kumade.exe collect --no-wizard --scan-processes --yara-ruleset extended -o E:\Evidence
.\kumade.exe collect --no-wizard --scan-processes --yara-rules .\local.yar -o E:\Evidence
```

`--no-wizard` does not mean yes to every optional feature. It skips the questions
and uses the defaults plus explicit flags. The wizard also runs when stdin is
redirected, reading the answers from it. EOF, `q`, or a declined final
confirmation exits without starting collection. Invalid yes/no and numeric
answers are reprompted. `--quiet` and `--sftp-password-stdin` need `--no-wizard`.

## Defaults

| Feature | Default |
|---|---|
| Catalogue artifact categories | On, except the paging and dedicated hibernation families |
| Hibernation file only | Off; `--hibernation` or explicit `--artifact windows.hibernation` enables it |
| Paging/swap/hibernation/existing memory dumps | Off; `--paging` or explicit `--artifact windows.paging` enables them |
| Live inventory | On for live collection, with at most two query workers |
| Native/raw locked-file reads | Enabled where supported; not an optional integrity shortcut |
| SHA-256 and destination readback | Local copies are checked by the collector. Remote readback uses the SFTP receiver or `verify-s3` on the analyst workstation. |
| Full-drive PE entropy discovery | Off |
| Live process-memory YARA | Off; two workers by default, using Core on the standard binary or the embedded pack on bundled binaries |
| VSS | Off |
| Destination | Defaults to directory output. Windows also offers VHDX/E01. Select SFTP or S3 with explicit connection options. |
| Acquisition workers | Available logical CPUs, capped at four; `-T` accepts 1–128 |
| Full partition imaging | Off; a separate guided mode using `forensic-copy` |
| New physical RAM capture | Off; `--memory` requires a separately supplied DumpIt toolkit |
| Active pagefiles paired with new RAM | On when `--memory` is enabled; `--no-memory-pagefile` skips them |

The paging change also applies to unattended collection and ordinary `plan`.
The catalogue still defines paging paths. Existing explicit artifact selections
are preserved, including paging, and `--paging` adds the paging family to an
explicit scope when the catalogue contains it, and the preflight sizes that
added family as well. The wizard groups only those
explicitly scoped artifacts when `--artifact` was supplied, preventing an
explicitly narrow selection from expanding to unrelated artifacts.

`--hibernation` adds the dedicated hibernation family to an explicit scope as
well. Its separate wizard choice offers `hiberfil.sys` without other paging or
dump files. The broad Paging group still includes the hibernation file;
overlapping selections are counted and copied once. See
[hibernation acquisition](hibernation-acquisition.md) for the VSS exclusion and
full/reduced-file limitations.

Explicit feature flags become the wizard's initial answers. `--vhdx`, `--e01`,
`--sftp` and `--s3` fix the output mode. With directory output on Windows,
the wizard can offer VHDX and E01.
An explicit `-T` value is the initial worker count and can be adjusted. Offline
sources do not offer live inventory, VSS or process-memory YARA. VSS and YARA
are also disabled in the wizard when the binary cannot support the native host
architecture. Entropy scanning
and file collection still work offline; Windows can also package offline inputs
into a container.

## Example questions

The actual categories and values are generated from the selected catalogue and
source metadata. These numbers illustrate the display:

```text
Windows event logs (2GiB; 180 files/streams) (Y/n):
NTFS and file system artifacts (28GiB; 12 files/streams) (Y/n):
Hibernation file only (hiberfil.sys) (4GiB; 1 files/streams) (y/N):
Paging, swap, hibernation and existing memory dumps (16GiB; 3 files/streams) (y/N):
Live system inventory (output size unknown; two query workers) (Y/n):
VSS (30GiB selected evidence; snapshot growth unknown) (y/N):
Process-memory YARA scan (output size unknown; two scan workers) (y/N):
High-entropy PE scan (additional transfer size unknown until analysis) (y/N):
VHDX output (30GiB input; native NTFS metadata) (y/N):
E01 output (30GiB input; compressed size unknown) (y/N):
Acquisition workers [4]:
Estimated transfer: 30GiB / 192 files/streams, plus inventory, reports, additional ADS and any entropy candidates.
Start collection (Y/n):
```

A VSS snapshot is not a second evidence transfer. Its displayed byte count is
the evidence currently selected; additional snapshot growth depends on source
writes and collection duration and is unknown. VSS is crash-consistent and does
not coordinate application writers.

## Size estimation

Preflight discovers catalogue matches and reads sizes from normal filesystem
metadata. For locked/raw-only NTFS candidates it can read raw NTFS metadata to
obtain logical stream lengths. It does not hash or copy every payload just to
show a prompt. Missing/unreadable sizes remain explicit unknown items; they are
never presented as known zero-byte transfers. Genuinely absent raw candidates
contribute zero bytes.

Category sizes may overlap because a file can match several artifact families.
The final total deduplicates planned file/stream identities. Different source
paths, hard links, or identical file content collected from different locations
remain separate observations, consistent with normal acquisition.

These are logical input lengths, not a guarantee of physical I/O, network bytes
or output allocation. Sparse files can have very large logical sizes; VHDX/E01
headers, added ADS, live inventory and report files add overhead. Compression
and sparse allocation change physical output size. The entropy scan has not
run at prompt time, so additional binary payloads are unknown. Files may change
between preflight and acquisition. Native acquisition/container capacity and
free-space checks remain authoritative.

## Optional process-memory scanning

`--scan-processes` also works in unattended collection. Additional flags are
`--yara-ruleset core|extended|full`, `--yara-release <TAG>`, and
`--yara-rules <FILE>` for local rules without downloading. Local rules conflict
with explicit package/release selection. The embedded scan uses two process
workers, 16 MiB chunks and a 60-second per-process deadline, matching the
standalone defaults. Use standalone `scan-processes` for additional tuning or
selected PIDs.

Results are stored under the collection's `YaraScan/` directory, including
inside VHDX/E01. Its files are included in the outer integrity seal. Success,
partial coverage and failure are tracked in `Summary.json` as
`ProcessScanStatus`; partial/failed scans make the overall collection partial.
Fatal scan setup/compilation errors retain a sealed `YaraScan/Failure.json`
instead of silently becoming a clean scan. `verify` checks the scan completion
marker and hashes, and checks that its incomplete count agrees with the outer
status.

Fast live inventory runs first, then hot disk artifacts, then this embedded
process scan and slower configuration inventory. Optional entropy analysis is
deferred until the selected artifacts have been acquired. See
[acquisition order](acquisition-order.md) for the stage boundaries and protected
early-data staging. Matching YARA rules are hunting leads, not automatic
malware verdicts. See [process-scan semantics](yara-process-scan.md).

## Partition imaging

On live Windows, before artifact selection, the wizard can switch to full
partition imaging. This is an alternative to ordinary triage, not a silent
additional full-disk copy. It lists selected source volumes with estimated
capacity, asks for one source and optional VSS, then confirms. The existing
`forensic-copy` backend writes under the selected destination's `DiskImages/`
directory and enforces its physical-disk/external-destination/free-space rules.
It does not format the external destination or overwrite a source disk.
Imaging is not offered for offline directories or an explicitly selected
VHDX/E01 artifact-output mode. Standalone `forensic-copy` remains available.
