# Physical RAM acquisition with DumpIt

Use `collect --memory` (`-m`) on an elevated **live Windows** machine to acquire
RAM before live-response queries, VSS creation, container setup and disk acquisition.
It is off by default. The wizard also offers RAM capture, showing the approximate
physical RAM size. Planning and wizard size estimation read metadata before capture;
this is not an atomic machine snapshot.

## Supply the vendor tool separately

Obtain an authorized copy of [Magnet DumpIt](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/).
Kumade does **not** bundle, download or relicense its executable or driver. Comply
with the vendor's license. Supported toolkit layout:

```text
Comae-Toolkit/
  ARM64/DumpIt.exe
  x64/DumpIt.exe
  x86/DumpIt.exe
```

Pass that directory with `--dumpit`, or place the same three architecture
directories in `tools/DumpIt/` beside `kumade.exe`. An explicit executable path
also works. Kumade selects and checks the **native Windows** architecture, not the
architecture of an emulated collector. It never searches the current directory or PATH.

The initial trusted hashes are the supplied 2023-01-17 release:

| Architecture | DumpIt.exe SHA-256 |
|---|---|
| ARM64 | `13bca00d0042748780b761fb93768754dfd96f48944e6cec75618cad93b3b5d5` |
| x64 | `6a484c1db7718949c7027abde97e164c7e7e4e4214e3e29fe48ac4364c0cd23c` |
| x86 | `f4f353821178bdaf3e29b49db6e6d80c543081ac7a4312e5fdb5583b96815839` |

For another release, independently verify its authenticity and SHA-256, then
pass `--dumpit-sha256 <64-hex-characters>` together with `--dumpit`. Do not use a
hash from an untrusted copy as evidence of that copy's authenticity. Kumade holds
the checked executable open without write/delete sharing while it runs.

```powershell
.\kumade.exe collect -o E:\Evidence --memory --dumpit E:\Tools\Comae-Toolkit --yes
```

To include the catalog's paging, swap, hibernation and existing dump files too:

```powershell
.\kumade.exe collect -o E:\Evidence --memory --paging --dumpit E:\Tools\Comae-Toolkit --yes
```

RAM is acquired first; paging files are subsequently read as disk artifacts.
These are not a synchronized RAM/pagefile pair. Custom active pagefile discovery
remains a separate future improvement. Offline `--source` requests never acquire
the analyst computer's RAM: they record a failed RAM task and continue disk acquisition.

## Output, verification and failures

The owned collection contains:

- `Memory/Memory.dmp`: uncompressed Microsoft full-memory dump, including retained
  partial bytes if the tool failed after creating the file. Check the manifest status.
- `Memory/Acquisition.json`: UTC start/end, provider hash, exit code when available,
  dump-layout check, acquisition record and limitations.
- `Memory/DumpIt-stdout.txt` and `DumpIt-stderr.txt`: provider diagnostics, up to
  256 KiB per stream. Output beyond that limit is drained and discarded.
- First `Manifest.jsonl` / `Manifest.csv` row: `windows.memory`, with captured bytes,
  SHA-256, status, path and acquisition time bounds. `Coverage.csv` reflects that result.

Kumade requests `/QUIET /TYPE DMP /NOCOMPRESS /NOLYTICS /NOJSON /OUTPUT <file>`.
Usage analytics and vendor JSON sidecars are disabled. A successful task requires
exit success, a native-architecture full-dump header, ordered nonoverlapping
physical-memory runs, matching declared page counts, matching required/file
lengths and stored-byte SHA-256 verification. These structural checks do not prove
that every live page is coherent, accessible or usable by a particular memory analyzer.

The default deadline is 1,800 seconds; change it with `--memory-timeout <seconds>`.
Kumade monitors destination free space during capture and terminates its owned
process job on timeout/reserve exhaustion. A system call or driver operation can
still stall; stopping a provider does not guarantee immediate kernel cancellation
or driver unload. Nonzero provider NtStatus and failed/truncated/unsupported dumps remain **Failed**;
reported inaccessible pages make the task **Partial**, with partial
bytes and diagnostics retained when available; other selected evidence still runs.
No fake successful memory image is created.

Driver loading changes the live machine and can be refused by Windows security,
architecture/version restrictions or a security product. Kumade does not disable
these controls or reboot the machine. Secure the destination: RAM can contain
passwords, session tokens and other sensitive data.

## Staging, containers and SFTP

DumpIt requires a seekable output file. Kumade creates a protected
`.kumade-volatile-<UUID>` staging directory beside the chosen output, or beneath
`--memory-staging-dir <DIR>`. RAM is sealed there before any live providers run.
Use external storage where possible; do not choose the source disk simply for
convenience. The initial budget is physical RAM plus 64 MiB headroom and
`--reserve-mib`; runtime reserve checks still apply.

Directory output attempts a same-volume hard link into `Memory/Memory.dmp` to
avoid a second RAM-sized allocation. Cross-volume/unsupported links require a
bounded, hash-checked copy. VHDX/E01 output copies RAM into its NTFS container;
RAM contributes to capacity, largest-file and E01 staging estimates. The early
copy remains until the collection is sealed, VSS cleanup has completed and the
container is finalized/verified. Failures retain it and print its location.

SFTP plus live `--memory` **requires** an explicit `--memory-staging-dir` so a
multi-GiB local write cannot happen silently in metadata-only staging. For example,
add `--memory --dumpit E:\Tools\Comae-Toolkit --memory-staging-dir E:\RamStage`
to your existing pinned-host-key SFTP collection command. The staged dump is
streamed directly to SFTP (gzip unless `--sftp-no-compression`), before VSS/disk
collection. It is not copied into the metadata staging tree. The remote manifest
points to `Early/Memory/Memory.dmp`, with status **Transferred** and `Verified=false`
until trusted server readback. The early upload is reused, not sent twice.
Publication failure retains the original stage. The final delivery descriptor is
published before successful-run staging cleanup; keep that descriptor's SHA-256
and run `verify-delivery` on the trusted server as described in [SFTP delivery](SFTP.md).

You can independently verify a completed retained early directory with
`kumade verify <early-directory>`. This verifies the early capture's sealed bytes
and recorded acquisition outcome, not completion of the entire collection.

## Format references

- [Microsoft: complete memory dumps](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/complete-memory-dump)
- [Volatility Foundation: crash-dump layer](https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/layers/crash.py)
- [32-bit structure definitions](https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/symbols/windows/crash.json)
- [64-bit structure definitions](https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/symbols/windows/crash64.json)

The format documentation is a layout reference; no vendor executable, driver,
or third-party implementation source is included in Kumade.
