# Directory layout

A run creates a fresh `<Hostname>_YYYY-MM-DD_HH-MM-SS` directory using its UTC
start time. Existing collections are not overwritten. Files sit beneath their
source drive letter with original relative paths; unlettered volumes use a
stable `Volume-<id>` folder.

```text
HOST01_2026-11-25_09-00-00/
  C/
    Windows/System32/config/SYSTEM
    Windows/System32/drivers/etc/hosts
    $MFT
    $Extend/$UsnJrnl/$J
  D/
    $MFT
  LiveInfo/
  Memory/
  YaraScan/
  client_info.json
  Plan.json
  Manifest.csv
  Manifest.jsonl
  Coverage.csv
  DiscoveryIssues.csv
  Errors.csv
  Summary.json
  Seal.json
```

The example is illustrative. Only selected, applicable, successfully retained
paths exist. Optional feature directories depend on the command and its outcome.
Live collection normally checks all selected catalogue families on every fixed
source volume; `D:` is not intrinsically restricted to NTFS metadata.

## Source and destination volumes

The destination volume is excluded from live discovery unless it also hosts the
running Windows installation. A destination on that system volume remains a
live source: output writes change the endpoint. Prefer external storage and
review the source/destination notices.

## Names and timestamps

Windows-incompatible names are encoded reversibly. Very long directory-mode
paths can use a manifest-mapped hash path. Read `SourcePath`, `StreamName` and
`RelativeOutputPath` instead of guessing provenance from a shortened filename.

Ordinary directory copying restores source access/modified times where supported;
additional source timestamp/security observations remain in the manifests and
inventories. Do not assume the analyst-visible creation time or ACL is the
original source value. [NTFS containers](../vhdx-output.md) have a different
preservation model and documented limits.
