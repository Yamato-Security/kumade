# Acquisition order and volatility

Kumade acquires rapidly changing evidence first. The sequence below describes
directory, VHDX and E01 collection. With [recoverable S3 delivery](S3.md),
Kumade captures requested RAM first and publishes the smaller fast live-inventory
phase before uploading RAM. Metadata-only source discovery and wizard
size estimation happen before acquisition so the operator can choose scope;
they do not perform entropy analysis or copy evidence payloads.

After scope confirmation:

1. **Physical RAM acquisition.** With `--memory`, the separately supplied DumpIt
   provider runs first. Active paging files are copied concurrently by default;
   `--no-memory-pagefile` opts out. The RAM record appears first in the final manifest.
   Missing/blocked tools or invalid/truncated dumps produce a failed task and
   partial collection. See [RAM acquisition](memory-acquisition.md).
2. **Fast live state.** Processes first, then network connections, DNS cache,
   SMB sessions/open files, logon state and current network configuration. Each
   priority group completes before the next begins. Queries remain non-atomic.
3. **Disk snapshot/planning/setup.** Optional owned VSS snapshots are created
   after fast live capture. Necessary file metadata discovery and container
   initialization follow. VSS freezes a crash-consistent filesystem view; it
   does not freeze RAM or coordinate application writers.
4. **Hot disk artifacts**, with a completion barrier between these groups:
   - USN journal, including `$J` and `$Max`.
   - NTFS `$LogFile`.
   - `$MFT` and its mirror.
   - Windows event logs.
   - Registry hives, Amcache and recovery files.
   - Active databases/queues: SRUM, SUM, BITS, WMI, ActivitiesCache,
     notifications and browser profile stores.
5. **Optional process-memory YARA and remaining live inventory.** Slow software,
   Appx, DISM/patch inventories and other configuration queries do not postpone
   the hot disk groups above. YARA remains a live scan at its actual recorded
   time; it does not analyze a nonexistent saved RAM dump.
6. **Remaining disk evidence.** Execution traces, other artifacts, then bulk
   mail/chat/cache/recycle data and optional paging/hibernation/existing dumps.
   Existing dump files are disk artifacts, distinct from capturing current RAM.
7. **Optional full-drive entropy discovery and additional binary acquisition.**
   Core payloads are already preserved. Already acquired unnamed files are
   analyzed from their verified collected copies, including ones deleted from
   the source since acquisition. Reports label this method `CollectedCopy`.
   This avoids rereading a newer live version and incorrectly changing the
   interpretation/hash of the version actually preserved. Other new candidates
   are collected with the usual analysis/copy hash comparison.
8. **Metadata restoration, final manifests/seals and container encoding.** E01
   compression and container verification occur after artifact acquisition.

These are pragmatic priorities, not a universal ranking of every artifact.
Large journals/MFTs can take time. On a live filesystem, different artifacts can
still represent different times. VSS reduces that inconsistency when enabled.
Use actual provider/manifest timestamps when correlating evidence.

## Parallelism and named streams

Workers run in parallel **within a priority group**. Later groups cannot jump
in front through thread-pool work stealing. For native NTFS output, a base file
and its ADS share the earliest priority of their group, and the base is created
before its streams. The old global ordering of all unnamed files followed by
all named streams is removed: it could delay the USN journal behind unrelated
large files. Metadata is captured per batch, retaining the earliest snapshot
for each output path and restoring directory times after all payload writes.

Priority derives from artifact IDs and known file paths, not input vector order
or how many acquisition workers are used. Classification/report tags added
later do not rewrite the original acquisition reason/timestamps in the journal.
Final family coverage uses planned observation identities to include later
entropy classifications correctly.

## Protected early staging and recovery

Fast live state must precede disk planning, VSS and output-container creation.
Kumade therefore creates a private `.kumade-volatile-<UUID>` directory under the
chosen output parent **after confirmation**. It stores the RAM request state,
fast live tables, original acquisition timestamps and integrity seals. On Unix
the root is owner-only; Windows uses Kumade's private output ACL.

The final collection imports the fast data with readback SHA-256 checks, then
adds the remaining providers and writes a complete `LiveInfo` inventory. It
never silently reruns the early providers or relabels later samples as early
ones. Early staging is removed only after the output has sealed, the container
has finalized/verified and owned VSS cleanup has completed. On errors it is
retained and its location is printed. A completed retained staging directory
can be checked with:

```powershell
.\kumade.exe verify E:\Evidence\.kumade-volatile-<UUID>
```

That verifies the **early snapshot scope**, not a completed full acquisition.
An interrupted staging directory without its completion seal remains incomplete.
A failed RAM request makes this scope partial; a successful request includes a sealed, hash-checked dump.
No pre-existing directory is accepted as an owned staging capture.

## Deferred entropy and container capacity

With deferred discovery, `InitialPlan.json` records the initial selection and
`Plan.json` records the final plan. Both are sealed. `plan --high-entropy` remains
an explicit standalone analysis/planning action; it does not acquire live data.
Library callers supplying precomputed entropy results are identified separately
as `EntropyPreplanned` in `Run.json`; they control work done before collection.

Automatic native containers can expand **only Kumade's newly created writable
VHDX** when late candidates or report sizes require it. The owned virtual-disk
handle, image path, disk number, unique disk identity and NTFS volume are checked.
The operation increases its virtual capacity and extends its existing data
partition; it does not initialize/format another disk or touch source partitions.
An explicit `--vhdx-size-gib`/`--e01-size-gib` remains a limit. Physical host
reserves and E01 output headroom are rechecked; failures retain partial evidence.

Collector output paths and early staging are excluded from entropy discovery.
An output parent equal to a source root does **not** exclude the entire drive.
Automatic exclusions are recorded in `Settings.OutputExcludes`, keyed by
`SourceId`, and apply only to that volume or its snapshot projection. Saving to
`C:\Evidence` does not exclude an unrelated `D:\Evidence` directory. These
rules apply both to discovery and analysis of already preserved copies.
User-supplied `--entropy-exclude` patterns remain global across selected sources.

- [Microsoft `ResizeVirtualDisk`](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-resizevirtualdisk)
- [Microsoft `Resize-Partition`](https://learn.microsoft.com/en-us/powershell/module/storage/resize-partition)
