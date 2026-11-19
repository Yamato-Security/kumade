# NTFS VHDX output

Run Kumade as an administrator on Windows and choose a fresh image filename:

```powershell
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
source during that acquisition. The image's host volume may still be a live
source: creating the image changes that volume, as any local collection does.

Automatic virtual capacity includes known file sizes, NTFS/metadata headroom and
space for unknown-size streams. `--vhdx-size-gib` overrides it (1–65536 GiB) and
must fit the known evidence estimate. Virtual capacity is a ceiling, not an
up-front allocation. Unknown sizes can exceed an estimate; choose a larger
capacity when collecting large paging files or other unknown-size artifacts.

`--reserve-mib` applies to physical host free space. Writes also check remaining
space inside NTFS. If either fills, failures are recorded and retained; Kumade
does not silently omit payloads. Failed setup or interrupted acquisition can
leave a partial image for inspection. A normal completed run flushes, locks,
dismounts and detaches the destination before reporting the image as saved.

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
- Supported file attributes, including compression/sparse state, and extended
  attributes with their original names, flags and byte values.
- Named `$DATA` streams discovered on selected files, including their exact bytes.
  They are native NTFS alternate streams on the copied host file. Stream-only
  artifacts use an empty host file whose unnamed data is not claimed as acquired.

Payload bytes are hash-verified before restrictive source permissions are
restored. Restored basic timestamps, attributes, security descriptors and extended
attributes are read back. A capture/restore discrepancy makes the acquisition
**partial**, appears in `MetadataErrors` in `Summary.json`, and is recorded in:

- `NTFS-Metadata.jsonl`
- `NTFS-Metadata.csv`

These inventories include source identity/path, relative output path, file or
directory type, raw FILETIME values, source attributes, source file identity,
self-relative security-descriptor bytes (hex), SDDL, extended-attribute bytes
(hex), capture time/status, restoration status and diagnostics. Both inventories
are covered by `Seal.json`. CSV and JSONL retain the same metadata values.

Native source ACLs can restrict browsing the copied files. Elevated backup access
can be required when inspecting or verifying them; Kumade does not replace these
ACLs with broad analyst access.

## Verification

Mount the completed image **read-only** using Windows Disk Management or
`Mount-DiskImage`, then point `kumade verify` at the run directory inside the
mounted volume. Verification checks the sealed metadata inventories and each
payload/alternate stream. Original directory acquisitions remain supported.

```powershell
Mount-DiskImage -ImagePath E:\Evidence\HOST01.vhdx -Access ReadOnly
# Replace X: and the run directory with the mounted location:
.\kumade.exe verify X:\HOST01_<UTC>_<RUNID>
Dismount-DiskImage -ImagePath E:\Evidence\HOST01.vhdx
```

Native alternate-stream verification requires Windows and an NTFS-aware mount.
Cross-platform raw-container inspection can use an appropriate read-only VHDX
and NTFS reader.

## Fidelity limits

This is a **logical triage image**, not a sector clone. The destination has its
own MFT entries, file IDs, allocation layout, USN activity and `$FILE_NAME`
metadata. Hard-link topology, source directory indexes and original file-record
identities are not recreated. Original file identities are retained in the
inventory; collect the source `$MFT`, journals and other filesystem artifacts
when those original structures are needed.

An unset or unsupported timestamp, EFS state without the original key, an
unsupported attribute, a reparse-backed object or unavailable metadata is
reported explicitly. Stored source metadata remains available even when native
restoration cannot reproduce it. Collection is not an atomic snapshot; live
sources can change during planning and acquisition. VSS and RAM providers remain
outside the currently implemented collection scope.

## References

- [CreateVirtualDisk](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-createvirtualdisk)
- [AttachVirtualDisk](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-attachvirtualdisk)
- [FILE_BASIC_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_basic_info)
- [SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)
- [File security and access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
