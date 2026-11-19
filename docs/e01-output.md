# E01 evidence containers

```powershell
.\kumade.exe --e01 E:\Evidence\HOST01.e01
.\kumade.exe --e01 E:\Evidence\HOST01.e01 --e01-size-gib 8
.\kumade.exe --e01 E:\Evidence\HOST01.e01 -v
```

E01 collection requires elevated Windows and the same built-in Virtual Disk
APIs and PowerShell Storage cmdlets as [VHDX output](vhdx-output.md). Compression
and verification use Yamato Security's Rust EWF writer. The collector needs no
installed Python, libewf, FUSE or external encoder. Windows x86, x64 and ARM64
builds include this capability.

`--e01 FILE`, `--vhdx FILE` and `-o DIR` are mutually exclusive. Directory output
remains the default. `plan` does not create containers. `--e01-size-gib` sets
the **uncompressed NTFS disk capacity**, with the same sizing checks as VHDX;
it does not set the compressed file size. Capacity is automatic when omitted.
Collection, compression and verification respect `-T, --threads`. Verbose mode
lists acquisition attempts without drawing progress bars.

## Contents and preservation

This is a logical triage acquisition inside a newly created GPT/NTFS disk,
encoded as genuine EWF1 physical media (`EVF` signature). It is **not an image
of the original machine's whole disk or its unallocated space**. Collected
files, native NTFS named streams, manifests, metadata inventories and the seal
are inside it. Windows creates new MFT records and filesystem history here.

The [VHDX preservation limits](vhdx-output.md) apply: available basic timestamps,
permissions, auditing, attributes and supported extended attributes are restored
and checked. Unsupported or unavailable metadata is recorded explicitly.
Original timestamps, descriptors and filesystem artifacts in the collection
remain the evidence for the source machine.

## Segments and receipt

An E01 container is a **segment set**. Keep every segment together:

```text
HOST01.e01
HOST01.e02
HOST01.e03
HOST01.e01.json
```

Open the first `.e01` in Juntei, libewf, or another EWF1 reader. The encoder uses
32 KiB chunks, zlib compression and at most 16,375 chunks (about 512 MiB of
logical media) per segment. Splits follow logical chunk counts, so even a highly
compressible 1 GiB disk occupies three small segment files. Suffixes continue
after 99 using the EWF convention. Extension case follows the requested first
filename, including on Linux and macOS.

The `.e01.json` receipt is published **last**, after complete decoding and
verification. It records:

- `LogicalBytes`: uncompressed disk size;
- `MediaSHA256`: SHA-256 of the entire logical disk, not of one segment;
- `Verified`: container verification status;
- `Segments`: each relative filename, size and `SHA256` of that segment;
- `Collection`: the acquisition summary, including partial/failed records and
  metadata preservation errors.

EWF stores media MD5, SHA-1 and SHA-256. Kumade reopens and decodes the full set,
checks its stored digests and expected media SHA-256, and hashes each segment.
A verified container can still hold a **partial collection**; check
`Collection.Completeness`, internal `Summary.json` and error reports.
Acquisition exit status 3 remains partial after packaging.

`kumade verify DIR` still verifies a collection directory's seal and payloads;
it does not accept E01 filenames. Use an EWF verifier for later independent
container validation. Expose or extract the internal collection read-only to
verify that directory with Kumade.

## Temporary storage and failures

E01 is not a writable NTFS filesystem. Kumade collects into a temporary dynamic
VHDX in a new protected `.kumade-e01-ntfs-*` directory beside the destination.
It flushes and detaches that disk, then attaches **only that owned staging
image read-only**, without a drive letter, for sector streaming. This packaging
step does not image or mount the original source disks.

A separate protected `.kumade-e01-encode-*` directory holds compressed staging.
There is no additional full raw-disk spool. Encoding scratch holds at most one
segment plus its serialized copy (about 1 GiB worst case), with a bounded
parallel compression batch. Completed compressed segments coexist with the
NTFS staging image until publication. Peak disk usage can therefore exceed
the final compressed output size substantially.

Preflight reserves room for staging, estimated output and compression scratch.
Writes also check host free space. Live growth, unknown sizes and unexpectedly
poor compression can still exhaust an estimate. On success, owned staging is
removed. On acquisition, conversion or publication failure it is retained,
with its location in the error. No existing E01 family or receipt is overwritten,
including symlinks. Each published file uses an OS no-overwrite commit.

Publication of a set is not a single atomic filesystem operation. Failure can
leave some verified segments at the destination **without a completion receipt**,
with remaining files in retained staging. Do not treat that as a complete set.
Keep diagnostics and retained staging for inspection or recovery.

## Developer validation

`cargo test --all-targets` covers sector alignment, short/long input, segmented
round trips, digests, collisions and x86 read-size arithmetic. Elevated Windows
tests collect real files and an ADS, read the output's NTFS partition directly,
verify payload and seal hashes, and compare all four basic FILETIMEs with the
sealed metadata inventory.

An independent Linux check uses libewf's media-reading C API:

```bash
KUMADE_EWFVERIFY="$PWD/scripts/verify_e01_libewf.py" cargo test --lib e01::tests
python3 scripts/verify_e01_libewf.py HOST01.e01
```

This optional development script needs libewf. It verifies decoded media against
stored MD5/SHA-1 and compares size/SHA-256 with the receipt when present. The old
2014 `ewfverify` executable can fail while printing a valid SHA-256 additional
hash because its display buffer is too small; the C reader avoids that display
limitation.

References: [Yamato Security EWF library](https://github.com/Yamato-Security/ys-e01-parser),
[EWF specification](https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc).
