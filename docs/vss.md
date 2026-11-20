# VSS acquisition

Use `--vss` on **native, elevated Windows** to acquire files from Volume Shadow
Copy Service snapshots. Snapshots provide a stable logical-volume view, including
files that normal live reads cannot open because another process holds them locked.
This is an opt-in alternative; normal collection remains unchanged.

```powershell
.\kumade.exe collect --vss --volume C: -o E:\Evidence
.\kumade.exe collect --vss --volume C: --volume D: --vhdx E:\Evidence
.\kumade.exe collect --vss --volume C: --e01 E:\Evidence
.\kumade.exe forensic-copy --vss -s C: -o E:\Evidence
```

For artifact collection, `--volume` accepts repeated local drive roots or volume
GUIDs and filters the normal live fixed-volume discovery. The destination volume
is still excluded unless it is the running Windows volume. Without `--volume`,
VSS is requested for all discovered live sources. If a selected volume does not
support the provider, it is explicitly reported as `Unsupported` and not read live;
other supported sources can still be acquired, with a partial result. If no
supported sources remain, acquisition fails before output creation. Capability is
queried from the provider rather than inferred from a filesystem name; a supported
volume can still fail because its current shadow-storage configuration is inadequate.
Such snapshot-set creation failures stop acquisition.

Offline `--source` collection and `plan` cannot create VSS snapshots. Volume
selection without `--vss` is also available for normal live acquisition. An
unavailable or destination-excluded explicit volume causes an error rather than
silently collecting a different volume.

## Consistency and scope

Kumade uses the built-in **Microsoft Software Shadow Copy Provider** with
`VSS_CTX_FILE_SHARE_BACKUP`: a no-writer, auto-release context. All included
volumes are added to one snapshot set. It does not invoke application backup
writers, truncate application transaction logs, perform a system-state backup,
or promise an application-consistent database backup. Filesystem snapshots can
retain dirty application state and still require normal forensic recovery.

Snapshot-backed native file reads and raw NTFS fallback both use the snapshot
device, never the original live device. If a snapshot disappears, fills its
storage or cannot be read, the errors remain visible; there is no automatic
fallback to the live volume. Stored-byte hash verification has the same meaning
as other Kumade collections and does not validate every artifact's internal format.

Windows/VSS can omit content, including paging and hibernation data. Artifact
collection explicitly refuses to claim root `pagefile.sys`, `swapfile.sys` or
`hiberfil.sys` contents from VSS: their manifest rows are `Failed` with a reason
that explains the unsupported scope, they are listed in `Errors.csv`, and the
result is partial when those artifacts are selected; a paging file that does not
exist on a readable snapshot stays `NotPresent`. An unavailable snapshot or raw
provider is a failure, never proof that an artifact was absent. Run without
`--vss` to acquire paging contents from the live volume. Memory dumps that are ordinary files can still be collected. Other Windows/provider exclusion
policies can also affect the snapshot; VSS is not a RAM capture or a guarantee of
original unallocated/slack contents.

A `forensic-copy --vss` image is the logical view exposed by the snapshot, not a
bit-for-bit representation of the live physical medium. The original live volume
identity is retained for same-volume/same-physical-disk destination protection.

Live-response inventory (processes, connections, users, and similar state) is
still queried live and has its own observation times. It is not frozen by VSS.
For a quiet file-only acquisition, use `--no-live-info`.

## Provenance

In artifact collections, each included `Plan.json` source has a `Snapshot` object:

- `SnapshotId`, `SnapshotSetId`, `ProviderId`: identifiers for this owned set.
- `OriginalVolume`, `OriginalRoot`: live origin and original file-path root.
- `DeviceObject`: the actual snapshot device used for acquisition.
- `CreatedUtc`: provider-reported creation time, in UTC.
- `Attributes`, `Consistency` (`CrashConsistent`) and `WritersParticipated` (`false`).

The usual drive-based output layout is retained. Manifest `SourcePath` records
the actual snapshot path and `Method` is `VssNativeRead` or `VssRawNTFS`; use the
source ID to join the original-root mapping in the sealed plan. `Run.json` also
records `VssEnabled`. `ForensicCopy.json` carries the same snapshot metadata for
raw images. Ordinary non-VSS source metadata has no `Snapshot` object.

## Ownership, cleanup and source changes

Creating a snapshot itself changes the live system: VSS services run, events are
written, and copy-on-write storage is allocated. Changes to a busy live source
continue to consume shadow storage while the snapshot is held. Writing evidence
to that source can increase the pressure; a separate destination is preferable.
Kumade does not resize shadow-storage quotas or delete other snapshots to make room.

Only the current requester's set is deleted after acquisition, including error
paths. The auto-release context provides a service-managed cleanup safeguard on
requester disconnect/process termination. Explicit cleanup failures are reported
and return nonzero; a previously saved, verified output is not deleted. Its
snapshot IDs remain available in the evidence metadata. A service/provider failure
can still require administrator investigation; cleanup is not a promise against
all operating-system failures.

`--vss-timeout <SECONDS>` controls the asynchronous snapshot-creation wait (default
120, range 1–3600). A timed-out operation is cancelled and given up to another
30 seconds to settle. Other synchronous COM/service calls remain subject to
Windows service latency; this is not a wall-clock deadline for all acquisition.

## Architecture and prerequisites

Microsoft does not support VSS requesters running under WOW64. Use the native x64
binary on x64 Windows, ARM64 on ARM64 Windows, or x86 on native 32-bit Windows,
subject to that Windows edition's installed VSS/provider support. An emulated
requester is rejected before snapshot creation; there is no PowerShell-based
snapshot fallback. Unsupported hosts can still use normal collection.

The binary includes a small SDK-compiled C++ bridge because `IVssBackupComponents`
is a C++ SDK interface missing from the generated Rust Win32 metadata. Snapshot
policy and acquisition remain in Rust. Windows source builds need the C++ Windows
SDK/build tools in addition to Rust; release executables link their CRT statically
and need no separately installed runtime. `vssapi.dll` is loaded from System32
only when VSS is requested, so ordinary collection has no new startup VSS dependency.

## Further details

- [Microsoft: shadow-copy creation](https://learn.microsoft.com/en-us/windows/win32/vss/shadow-copy-creation-details)
- [Microsoft: snapshot contexts and writer participation](https://learn.microsoft.com/en-us/windows/win32/vss/shadow-copy-context-configurations)
- [Microsoft: VSS runtime architecture requirements](https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-portal)
- [Microsoft: accessing shadow-copy device paths](https://learn.microsoft.com/en-us/windows/win32/vss/exposing-and-surfacing-shadow-copied-volumes)
