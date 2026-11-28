# Your first collection

Use an evidence destination with enough free space. The examples use `E:`;
replace it with your actual destination. Prefer an external disk to reduce
writes to the computer you are investigating.

## 1. Check the host and catalogue

```powershell
.\kumade.exe check-support --check
.\kumade.exe list --builtin
```

`check-support` describes available capabilities; it does not guarantee that every
protected file or memory page will be readable.

## 2. Start the wizard

```powershell
.\kumade.exe collect -o E:\Evidence
```

Review the artifact categories and estimated transfer sizes. Defaults collect
the supported catalogue families and live inventory; paging, new RAM, VSS,
entropy discovery and YARA are separate choices. `--no-wizard` skips the wizard using
defaults plus explicitly requested flags; it does not enable every feature.

To automate the same feature defaults:

```powershell
.\kumade.exe collect --no-wizard -o E:\Evidence
```

To limit the volume scope to `C:`:

```powershell
.\kumade.exe collect --no-wizard --volume C: -o E:\Evidence
```

Without `--volume`, live discovery checks local fixed volumes and mount points.
The destination volume is excluded unless it is also the running Windows volume.
See [directory output](../output/directory.md).

## 3. Read the result, including gaps

The new run folder is named with the computer and UTC start time, for example
`HOST01_2026-11-25_09-00-00`. Do not reuse an existing run directory.

Open `Summary.json` and `Coverage.csv`, then inspect `DiscoveryIssues.csv` and
`Errors.csv`. Exit code `3` means a partial result. A stored file may be verified
while its source changed during the read.

## 4. Verify the retained collection

```powershell
.\kumade.exe verify E:\Evidence\HOST01_2026-11-25_09-00-00
```

Keep the manifests, seals, recovery companions and original payloads together.
Read [verification semantics](../output/verification.md) before treating a success
message as proof of coverage. Then [analyze the collection](../output/analysis.md).
