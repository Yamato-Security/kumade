# Collection wizard

Interactive `collect` runs ask which evidence and optional features to use,
show estimated logical transfer sizes, and confirm before snapshots, entropy
analysis, process scanning or evidence output. Running without arguments still
shows help. `plan` remains a noninteractive planning command.

```powershell
# Automatic wizard when stdin and stdout are terminals:
.\kumade.exe collect -o E:\Evidence

# Force the wizard, including explicitly piped answers:
.\kumade.exe collect --wizard -o E:\Evidence

# Scripted collection: accept safe defaults and explicit command-line options:
.\kumade.exe collect --yes -o E:\Evidence
.\kumade.exe collect --no-wizard --paging --vss --vhdx E:\Evidence

# Explicit optional process scan, using Core unless another pack is requested:
.\kumade.exe collect --yes --scan-processes -o E:\Evidence
.\kumade.exe collect --yes --scan-processes --yara-ruleset extended -o E:\Evidence
.\kumade.exe collect --yes --scan-processes --yara-rules .\local.yar -o E:\Evidence
```

`--yes` does not mean yes to every optional feature. It suppresses questions and
uses the defaults plus explicit flags. Piped/redirected invocations and `--quiet`
do not prompt automatically. `--wizard` and `--yes` conflict; `--wizard` also
conflicts with `--quiet`. When explicitly requesting `--wizard`, redirected stdin
is treated as an answer script. EOF, `q`, or a declined final confirmation exits
without starting collection. Invalid yes/no and numeric answers are reprompted.

## Defaults

| Feature | Default |
|---|---|
| Catalogue artifact categories | On, except the paging family |
| Paging/swap/hibernation/existing memory dumps | Off; `--paging` or explicit `--artifact windows.paging` enables them |
| Live inventory | On for live collection, with at most two query workers |
| Native/raw locked-file reads | Enabled where supported; not an optional integrity shortcut |
| SHA-256 and destination readback | Required |
| Full-drive PE entropy discovery | Off |
| Live process-memory YARA | Off; Core and two workers when selected |
| VSS | Off |
| Directory output | Default; VHDX/E01 selectable on Windows |
| Acquisition workers | Available logical CPUs, capped at four; `-T` accepts 1–128 |
| Full partition imaging | Off; a separate guided mode using `forensic-copy` |
| New physical RAM capture | Unavailable; no nonfunctional yes/no choice is offered |

The paging change also applies to unattended collection and ordinary `plan`.
The catalogue still defines paging paths. Existing explicit artifact selections
are preserved, including paging, and `--paging` adds the paging family to an
explicit scope when the catalogue contains it. The wizard groups only those
explicitly scoped artifacts when `--artifact` was supplied, preventing an
explicitly narrow selection from expanding to unrelated artifacts.

Explicit feature flags become the wizard's initial answers. `--vhdx`/`--e01`
fix the output mode; otherwise the wizard offers VHDX and E01 with No defaults.
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

Live inventory runs before this embedded process scan. Optional entropy
analysis still runs during planning, before inventory and YARA; use standalone
`live-info`/`scan-processes` first if volatile evidence must be captured before
lengthy drive analysis. Matching YARA rules are hunting leads, not automatic
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
