# Raw partition imaging

`forensic-copy` creates an uncompressed, byte-for-byte image of **one logical
Windows partition**. It reads every byte Windows exposes for that volume,
including allocated files, filesystem metadata, slack and unallocated space.
This is separate from `collect`, which copies selected forensic artifacts.

## Usage

Run Kumade as Administrator. Attach an external destination disk with enough free space:

```powershell
.\kumade.exe forensic-copy -s C: -o E:\Evidence
```

`-s, --source <VOLUME>` accepts a drive letter (`C:` or `C:\`), a raw volume alias
(`\\.\C:`), or a volume GUID (`\\?\Volume{GUID}\`). It never accepts a physical
whole-disk device or an ordinary source file. Use a volume GUID for partitions
without a drive letter. Directory mount points and GUID aliases in the
**destination** are resolved to their actual volume and disk identities.

`-o, --output <DIR>` is a directory on the external disk. Kumade creates it if
necessary, then creates a fresh hostname/UTC-start directory. Repeating a run
with the same name fails instead of overwriting it. There is no raw-disk
write/format mode and no overwrite switch.

Other options:

- `--reserve-mib <MiB>`: leave this much space free (default: 2048 MiB).
- `-q, --quiet`: suppress the banner, progress and routine results; errors remain visible.

The command is sequential and uses bounded buffers; it does not allocate memory
proportional to the partition size. No installed runtime, imaging helper or mount
driver is required by the command.

## Output and verification

```text
E:\Evidence\HOST01_2026-11-20_15-23-12\
  C.dd
  ForensicCopy.json
```

GUID-only sources use `Volume.dd`. The image contains the logical volume, not an
outer MBR/GPT disk or other partitions. Volume-relative offsets start at zero in
the image; the original disk number, partition start and length are in the receipt.
Raw filesystem bytes retain their embedded timestamps, security descriptors and
other metadata; they are not reconstructed files with newly assigned metadata.

During acquisition the file is `C.dd.partial`. After copying, Kumade flushes the
image to the storage device and reads it back, comparing its length and SHA-256
against the bytes acquired from the source. Only then is it renamed to `C.dd`
without replacing any existing path. The command returns success only after
writing the final `Verified` receipt.

A read, write, flush, verification or finalization error stops acquisition and
returns nonzero. The partial image is retained; there is no silent bad-sector
zero filling. `ForensicCopy.json` records `Failed` and the number of bytes written
when possible. An interrupted/killed process or disconnected destination can
leave an `InProgress` receipt or prevent saving the final error. Treat anything
without the final successful receipt as incomplete until independently checked.
The receipt is not digitally signed and is not tamper-proof.

To independently check an image's hash:

```powershell
Get-FileHash -LiteralPath 'E:\Evidence\HOST01_<UTC>\C.dd' -Algorithm SHA256
Get-Content -Raw -LiteralPath 'E:\Evidence\HOST01_<UTC>\ForensicCopy.json' | ConvertFrom-Json
```

Compare the hash to `AcquiredSha256` and `ImageSha256`, and the file length to
`ExpectedBytes` and `BytesCopied`. The generic `kumade verify` command is for
artifact collections, not these raw-image receipts.

## Destination protection

The destination must be a different external physical disk, not merely a different
letter or partition on the source disk. Kumade queries Windows volume extents and
storage descriptors instead of comparing path strings. It rejects:

- The same volume, including GUID/drive-letter aliases.
- Any destination extent on a source physical disk, including a second partition.
- Internal destinations not reported as removable/hotplug storage.
- Network shares, unknown disk identities and unsupported storage topology.
- Insufficient free space, capacity arithmetic overflow, and images beyond FAT32's
  single-file size limit. Use NTFS or exFAT for large images.

External detection uses Windows-reported USB, FireWire, SD/MMC, removable or
hotplug characteristics. A misreported device can be refused; hardware reporting
is not proof of where an enclosure is physically located. There is no bypass flag.
The actual opened output file's volume is checked again before copying bytes.

This first implementation supports single-extent source partitions. RAID,
iSCSI, Storage Spaces, file-backed virtual disks and unknown/virtual storage
buses are refused where their backing-disk separation cannot be established.
It does not currently support splitting output, compression, resume or continuing
past unreadable sectors. Windows must expose the source volume through its local
volume APIs; this is not a recovery tool for unrecognized partition tables.

## Live-source consistency

Kumade opens the source for **read access only**, with sharing required for live
Windows volumes. It does not lock, dismount or snapshot the source. Windows and
applications can change a writable source while it is being imaged. The output
therefore represents the sequentially observed bytes, not necessarily a single
point-in-time filesystem state. Hash verification proves that the saved image
matches the acquired byte stream; it does not prove the live source stayed static.
For consistent evidence, use an offline/read-only source or an appropriate
write-blocking workflow. This command does not provide VSS acquisition.

The image reflects bytes exposed by the Windows logical-volume stack. Encryption
filters can affect that view; it is not a guarantee of the original encrypted
physical-disk representation, and it is not a whole-disk image.

## Receipt fields

All JSON keys use PascalCase. `Source` and `Destination` include `VolumeName`,
`Extents` (`DiskNumber`, `StartingOffset`, `Length`) and `Disks` (`DiskNumber`,
`BusType`, `Removable`, `Hotplug`). `BusType` is the Windows `STORAGE_BUS_TYPE` value.

Other fields are `SchemaVersion`, `Version`, `Computer`, `StartedUtc`, `FinishedUtc`,
`Status`, `ExpectedBytes`, `BytesCopied`, `LogicalSectorSize`, `Image`,
`AcquiredSha256`, `ImageSha256`, `Verified`, `Consistency` and `Error`. `Image` is
relative to the run directory. `StartedUtc`/`FinishedUtc` are UTC timestamps.
`Verified` describes stored-byte integrity, not acquisition consistency or authenticity.

## Implementation references

- [Microsoft: CreateFile and raw volume handles](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [Microsoft: physical disk extents of a volume](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_get_volume_disk_extents)
- [Microsoft: access to a partition's final sectors](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_allow_extended_dasd_io)
