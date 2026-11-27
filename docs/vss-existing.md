# Historical VSS snapshots

Use **`--vss-existing`** to collect selected artifacts from current source
volumes **and existing historical shadow copies**. It is off by default.
Listing/reading existing snapshots does not create a new copy, delete one,
change its attributes or take ownership of it. Use elevated, native Windows.

## List before collecting

```powershell
.\kumade.exe list-vss --all
.\kumade.exe list-vss --volume C:
.\kumade.exe list-vss --volume C: -o E:\Snapshots.csv
.\kumade.exe list-vss --volume C: -t jsonl
```

The default is a table. `-o` writes a fresh file and refuses an existing one.
CSV is the default; `.json` and `.jsonl` are also inferred from the extension.
`-t csv`, `-t json` or `-t jsonl` selects the format explicitly. With `-t` and
no `-o`, stdout contains structured output without a banner.

| Field | Meaning |
|---|---|
| `SnapshotId` | Stable shadow-copy GUID |
| `SnapshotSetId` | Original set GUID; sets can span multiple volumes |
| `OriginalVolume` | Original volume GUID path used for matching sources |
| `VolumePaths` | Current drive letters/mount points, separated by semicolons; may be empty |
| `CreatedUtc` | Provider-reported creation time, in UTC |
| `DeviceObject` | Snapshot device path used to read files |
| `ProviderId` | Provider GUID |
| `Attributes` | VSS bitmask; not proof of application consistency |
| `RootReadable` | Whether the root can currently be enumerated; individual files may still fail |

Listing queries completed snapshots known to local VSS across all contexts.
Unfinished copies are skipped; `RootReadable` identifies currently accessible
local devices. Listing does not export a snapshot or guarantee it remains available for later collection.

## Select historical copies

```powershell
# Current artifacts plus all available snapshots of C:
.\kumade.exe collect --no-wizard --volume C: --vss-existing -o E:\Evidence

# Newest historical snapshot of each selected source volume:
.\kumade.exe collect --no-wizard --vss-existing newest -o E:\Evidence

# Newest three historical snapshots per selected volume:
.\kumade.exe collect --no-wizard --volume C: --vss-existing 3 -o E:\Evidence

# Select a SnapshotId obtained from list-vss:
.\kumade.exe collect --no-wizard --volume C: --vss-existing 01234567-89ab-cdef-0123-456789abcdef -o E:\Evidence

# Plan only; no payload copy or new snapshot:
.\kumade.exe plan --volume C: --vss-existing all --artifact windows.eventlogs -o E:\Plans\History
```

Values are `all` (the bare flag's default), `newest`, a positive count **per
volume**, or one snapshot GUID. `--volume` filters current and historical disk
sources. A requested GUID outside that scope is an error. Zero available
copies with `all`/`newest` is reported as zero; current-source collection continues.

The normal catalogue, `--artifact`, paging defaults and output options apply.
Only selected artifact paths are searched. This requires local live Windows
volumes; `--source` offline directories cannot enumerate VSS. It does not parse
historical shadow stores inside an offline disk image.

## Output and provenance

```text
<HOST>_<DATE>/
  C/Windows/...
  C-VSS-20261020T090000Z-<SNAPSHOT-GUID>/Windows/...
  C-VSS-20261021T090000Z-<SNAPSHOT-GUID>/Windows/...
```

The full GUID prevents same-second collisions. Labels reflect current volume
mapping, not necessarily historical drive letters. `Plan.json` records the
volume, snapshot/set/provider IDs, full creation time, device path and
`OwnedByCollector: false`. Historical consistency is `UnknownHistorical` and
`WritersParticipated` is `null`; attributes alone do not prove writer participation.
New Kumade snapshots have `OwnedByCollector: true`, `CrashConsistent` and
`WritersParticipated: false`. Older metadata without ownership remains readable.

Manifest rows identify the historical source and use `VssNativeRead` or
`VssRawNTFS`. **Identical versions from separate snapshots are retained separately.** Compare hashes to identify duplicates.
Many snapshots can substantially increase transfer/output size.

## Combining modes and limitations

`--vss` alone creates temporary snapshots for stable current reads; it does not
collect historical copies. `--vss --vss-existing all` supports both: historical
selection is fixed before the new set is created. Only the new set is cleaned
up; existing copies are never passed to deletion/ownership APIs.

Creating new snapshots consumes shadow storage and can cause Windows retention
to remove older copies. Copies may also disappear when another requester
releases them. Kumade cannot pin them and does not resize their storage.
Unavailable/disappearing sources are reported; live content is never silently
substituted. To prioritize history preservation, collect existing copies without
`--vss` before requesting a new snapshot in another run.

Historical copies can preserve cleared logs, replaced hives and files deleted
after snapshot creation. Availability depends on the retained copies and their
contents. Snapshot-omitted paging/hibernation content retains the limitations
in [VSS acquisition](vss.md).

[Microsoft: enumeration](https://learn.microsoft.com/en-us/windows/win32/api/vsbackup/nf-vsbackup-ivssbackupcomponents-query) ·
[Microsoft: snapshot contexts](https://learn.microsoft.com/en-us/windows/win32/vss/shadow-copy-context-configurations) ·
[Microsoft: snapshot properties](https://learn.microsoft.com/en-us/windows/win32/api/vss/ns-vss-vss_snapshot_prop)
