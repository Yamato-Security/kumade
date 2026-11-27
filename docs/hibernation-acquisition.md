# Hibernation-file acquisition

Use **`--hibernation`** to add the existing `hiberfil.sys` file to a collection.
It is off by default because it can be large. Kumade copies the saved bytes;
it does not enable or disable hibernation, change Fast Startup, suspend the
computer, resize the file or create a new hibernation image.

## Collect or plan

Run live acquisition from an elevated, native Windows terminal. Prefer an
external evidence destination:

```powershell
# Normal collection plus hiberfil.sys; other paging/dump files stay off:
.\kumade.exe collect --no-wizard --volume C: --hibernation -o E:\Evidence

# Just the hibernation family, without live-system inventory:
.\kumade.exe collect --no-wizard --volume C: --artifact windows.hibernation --no-live-info -o E:\Evidence

# Inspect the scope before copying any payload:
.\kumade.exe plan --volume C: --artifact windows.hibernation -o E:\Plans\Hibernation

# An existing hibernation file in an offline Windows volume directory:
.\kumade.exe collect --no-wizard -d D:\Case\C --artifact windows.hibernation -o E:\Evidence
```

`--hibernation` adds the family to the normal defaults or an explicit
`--artifact` scope; it does not restrict an otherwise broad collection to one
file. A custom `--catalog` must define `windows.hibernation` for the flag to work.

The wizard has a separate **Hibernation file only (hiberfil.sys)** question,
showing estimated logical bytes and file/stream count. Its default is No unless
the dedicated family is explicitly selected. `--paging` and
`--artifact windows.paging` retain their existing broad scope, including
`hiberfil.sys`; selecting both families still copies each source file once.
The wizard's broad Paging group also includes hibernation, as its label states.

## Acquisition and output

The file is normally at the root of the Windows operating-system volume.
Kumade matches the name case-insensitively and uses its normal verified copy
path, falling back to read-only raw NTFS access where available when native
reads are denied. Raw access requires elevation and a supported readable NTFS
stream. An unreadable source is a reported failure, not an empty substitute.

Directory output retains the drive-relative path, for example
`<HOST>_<DATE>/C/hiberfil.sys`. The family uses the same acquisition pipeline for
NTFS VHDX, compressed E01, SFTP and S3 delivery. Output metadata includes the source,
acquisition method, byte count, timestamps, SHA-256 and outcome. Review
`Manifest.csv` / `Manifest.jsonl`, `Coverage.csv` and any errors, then verify the
output. Remote readback uses the SFTP receiver or the analyst’s [`verify-s3`](S3.md).

## Interpretation and limitations

- A hibernation file is an earlier saved state, not a live RAM capture. Its bytes
  may have changed or become unusable since that state was saved.
- A **full** hibernation file supports hibernation and can contain user and kernel
  state. A **reduced** file supports Fast Startup and saves kernel state after
  user sessions are logged off. Do not assume every file contains user-process
  memory or that its allocated length is all meaningful saved memory.
- Kumade preserves the file as found. It does not decompress it, infer its type
  from its size, or promise that a particular memory-analysis tool can parse it.
- **VSS excludes `hiberfil.sys`. Collect it in a run without `--vss`.** Snapshot
  acquisition does not silently switch to the live volume for excluded files;
  absence from a snapshot does not establish absence from the live machine.
- Review absence and failure reports. Some systems do not support hibernation,
  and disabling it can remove the file. Kumade does not alter that configuration
  to obtain evidence.

[Microsoft: power states and hibernation file types](https://learn.microsoft.com/en-us/windows/win32/power/system-power-states) ·
[Microsoft: hibernation-file location and behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/disable-and-re-enable-hibernation) ·
[Live RAM and paired pagefiles](memory-acquisition.md) ·
[VSS acquisition](vss.md)
