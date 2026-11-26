# NTFS VHDX output

Run Kumade as an administrator on Windows and choose a fresh image filename:

The default image name is `<Hostname>_YYYY-MM-DD_HH-MM-SS.vhdx` in UTC. Pass
an output directory to generate it, or omit the value to use the `Kumade-Results`
directory beside the executable (the `-o` default). A full `.vhdx` filename
remains an explicit override. The image contains that same run directory, with
`C/`, `D/`, etc. directly below it. Every local volume has the catalog scope;
NTFS volumes also contain their filesystem metadata files. The physical volume
holding the output is excluded unless it is the running Windows volume.

```powershell
.\kumade.exe --vhdx E:\Evidence
.\kumade.exe --vhdx E:\Evidence\HOST01.vhdx
.\kumade.exe --vhdx E:\Evidence\HOST01.vhdx --vhdx-size-gib 32
.\kumade.exe -d C:\OfflineVolume --computer HOST01 --vhdx E:\Evidence\HOST01.vhdx
```

`--vhdx` replaces the `-o` directory destination. `plan` continues to write a
plan with `-o DIR` and does not create containers. Existing images are never
overwritten or reformatted. Directory output remains the default.

## Container lifecycle

Kumade creates a **dynamically allocated VHDX** through Windows Virtual Disk
APIs. Windows PowerShell's built-in Storage cmdlets initialize and format only
the newly created, positively identified RAW virtual disk as GPT/NTFS. No drive
letter is assigned. Acquisition writes directly through its volume GUID path;
there is no second complete evidence directory or extraction spool on the host.
Windows PowerShell and the Storage cmdlets must be available; no third-party
mounting software is required.

The source plan is frozen before attachment, so the new volume cannot become a
source during that acquisition. The volume that holds the image is left out of
scope, as a directory destination is, unless it is the running Windows volume:
that volume is always acquired, and creating the image there changes it, as any
local collection does.
`Run.json` records `PhysicalHostDestination` and accounts for that path in
`DestinationOnLiveSource`, alongside the inner evidence destination.

Automatic virtual capacity includes known file sizes, the sizes of raw-only NTFS
metafiles read from the raw provider before the image exists, NTFS/metadata
headroom, the container reserve described below, and 1 GiB for every stream
whose size is still unknown. Sparse streams count their allocated clusters;
for `$UsnJrnl:$J`, which NTFS keeps allocated far beyond the written records,
the estimate is bounded by the live journal range (`NextUsn - FirstUsn` from
`FSCTL_QUERY_USN_JOURNAL`), because the sparse-aware copy stores only that.
The capacity is also at least the largest stream's logical size plus headroom:
the sparse copy keeps `$J` at its logical size, and The Sleuth Kit rejects an
NTFS run longer than the volume, so a smaller container would hold a journal
that Autopsy cannot read. `--vhdx-size-gib` overrides it (1–65536 GiB) and must
fit the known evidence estimate, the largest stream and the reserve. Virtual capacity is a ceiling, not an up-front
allocation. Unknown sizes can exceed an estimate; choose a larger capacity when
collecting large paging files or other unknown-size artifacts.

`--reserve-mib` applies to physical host free space. Inside the image Kumade keeps
a **container reserve** of 64 MiB plus 8 KiB per planned file and 16 MiB per
worker thread for the manifests, inventories and the seal. A payload that would
consume it stops with `Destination free-space reserve reached`; its partial bytes
are retained and recorded as failed, and the remaining payloads fail the same way
instead of filling the volume. If the host fills, failures are recorded and
retained too; Kumade does not silently omit payloads. Failed setup or interrupted
acquisition can leave a partial image for inspection; the volume is flushed and
dismounted before the disk is detached, so that retained image is consistent. A
normal completed run flushes, locks, dismounts and detaches the destination
before reporting the image as saved. If the lock is refused, for example because
an on-access scanner still holds a handle inside the new volume, the volume is
dismounted anyway after a notice: every evidence file is already closed and
flushed, and a complete, sealed result is not discarded over the lock.

## Data and metadata

The image contains the ordinary run directory, payloads, manifests, coverage,
errors and seal. Original filenames use the same reversible encoding for Windows
reserved characters. VHDX paths retain long directory hierarchies using Windows
volume GUID paths. NTFS component length limits still apply.

For collected files and their containing directories, Kumade captures and
attempts to restore:

- Creation, access, write and metadata-change timestamps as NTFS 100 ns FILETIME
  values. Directory metadata is restored deepest first, after child writes.
- Owner, primary group, DACL, SACL and protection state. SID values are preserved
  without substituting accounts from the analyst's machine. Reading auditing data
  and restoring owners/ACLs requires backup, restore and security privileges.
  Access-filter ACE information (Windows 10 1703 and later) is included when the
  kernel supports it; an older kernel that rejects the flag is read with the
  base information mask.
- Supported file attributes, including compression/sparse state, and extended
  attributes with their original names, flags and byte values.
- Named `$DATA` streams discovered on selected files, including their exact bytes.
  They are native NTFS alternate streams on the copied host file. Stream-only
  artifacts use an empty host file whose unnamed data is not claimed as acquired.
- NTFS system files acquired through the raw provider (`$MFT`, `$LogFile`,
  `$Boot`, `$Bitmap`, `$Secure`, `$Extend\$UsnJrnl` and the `$Extend` directory)
  are not exposed to Windows file APIs. Their basic times, attributes and file
  reference are read from the raw `$STANDARD_INFORMATION` (`CaptureStatus` =
  `RawBasic`); no security descriptor or extended attributes exist for them in
  the inventory, and their named streams come from the catalog rather than from
  stream enumeration.

Payload bytes are hash-verified before restrictive source permissions are
restored. Security is restored through Windows backup streams, preserving
inheritance/auditing control flags that ordinary ACL-setting APIs normalize.
Directory properties are restored top-down, and basic times are restored in a
final pass, deepest first. Metadata is applied only when its captured file
generation matches the acquired file. Restored basic timestamps, attributes, security descriptors and extended
attributes are read back. A capture/restore discrepancy makes the acquisition
**partial**, appears in `MetadataErrors` in `Summary.json`, and is recorded in:

- `NTFS-Metadata.jsonl`
- `NTFS-Metadata.csv`

Two Windows behaviors are recorded in the `Notes` column instead, because the
source bytes are kept in the inventory and user mode cannot reproduce them:
extended attributes in the `$Kernel.` namespace (for example
`$KERNEL.CFDONOTCONVERT` on registry hives), which `NtSetEaFile` accepts from
user mode without storing, and a DACL without the auto-inherited flag (a freshly
formatted data volume's root, for instance), which Windows stores as protected
and in canonical ACE order when it is written inside the container's
auto-inheriting tree. Owner, group, SACL and every ACE are still compared and
must match. Reordering is accepted only for ordinary allow-only DACLs; mixed
allow/deny, conditional and object-specific ACEs retain their order in the
comparison because reordering them can change effective access. A missing ACL
is distinguished from an empty one.

These inventories include source identity/path, relative output path, file or
directory type, raw FILETIME values, source attributes, source file identity,
self-relative security-descriptor bytes (hex), SDDL, extended-attribute bytes
(hex), capture time/status, restoration status, diagnostics and notes. Both
inventories are covered by `Seal.json`. CSV and JSONL retain the same metadata
values.

Native source ACLs can restrict browsing the copied files. Elevated backup access
can be required when inspecting or verifying them; Kumade does not replace these
ACLs with broad analyst access. Restored attributes include Hidden and System, so
the `<SourceId>` copy of a volume root is not listed by Explorer or
by `dir` without `/a`; use `Get-ChildItem -Force` or show protected operating
system files.

## Verification

Mount the completed image **read-only** using Windows Disk Management or
`Mount-DiskImage`, then point `kumade verify` at the run directory inside the
mounted volume. Verification checks the sealed metadata inventories and each
payload/alternate stream. Original directory acquisitions remain supported.

```powershell
Mount-DiskImage -ImagePath E:\Evidence\HOST01.vhdx -Access ReadOnly
# Replace X: and the run directory with the mounted location:
.\kumade.exe verify X:\HOST01_2026-11-25_09-00-00
Dismount-DiskImage -ImagePath E:\Evidence\HOST01.vhdx
```

With Windows access-time updates enabled, reading a read-only mount can change
its **cached** last-access values. In Windows 11 ARM64 testing, the image's
SHA-256 stayed unchanged and remounting showed the saved timestamps again.
Inspect timestamps before data reads, or use a raw NTFS reader to examine the
stored values. This behavior is separate from a change to the image bytes.

`verify` checks payload hashes and the sealed metadata reports. Native metadata
restoration is read back during acquisition; verification does not certify the
current mounted filesystem's metadata after later changes.

Native alternate-stream verification requires Windows and an NTFS-aware mount.
Cross-platform raw-container inspection can use an appropriate read-only VHDX
and NTFS reader.

## Fidelity limits

This is a **logical triage image**, not a sector clone. The destination has its
own MFT entries, file IDs, allocation layout, USN activity and `$FILE_NAME`
metadata. Hard-link topology, source directory indexes and original file-record
identities are not recreated. Original file identities are retained in the
inventory; collect the source `$MFT`, journals and other filesystem artifacts
when those original structures are needed. Analyze those collected source
artifacts under `Evidence`, rather than treating the container's newly created
NTFS metadata as the source machine's filesystem history.

An unset or unsupported timestamp, EFS state without the original key, an
unsupported attribute, a reparse-backed object or unavailable metadata is
reported explicitly. Stored source metadata remains available even when native
restoration cannot reproduce it. Collection is not an atomic snapshot; live
sources can change during planning and acquisition. For optional physical RAM
capture with an external DumpIt toolkit, see [RAM acquisition](memory-acquisition.md).

## References

- [CreateVirtualDisk](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-createvirtualdisk)
- [AttachVirtualDisk](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-attachvirtualdisk)
- [FILE_BASIC_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_basic_info)
- [SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)
- [File security and access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
