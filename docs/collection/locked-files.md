# Locked files and raw NTFS

Windows services can hold registry hives, logs and databases open while the
computer is running. Normal file APIs may refuse those reads. For supported
NTFS sources, Kumade can fall back to read-only volume access and obtain
resident/nonresident data, named streams and sparse logical content.

## What the fallback means

The manifest records the acquisition method. Raw reads require suitable
privileges, source access and a supported stream representation. They preserve
captured bytes; they do not make an active database transaction-consistent.
Compressed, encrypted or reparse-backed raw content is rejected rather than
returned as incorrectly decoded logical bytes.

Directory discovery still matters. Raw file fallback is not a general raw walk
of every inaccessible directory. If the normal walk never discovers a file,
that is a coverage gap to inspect in the discovery report.

## NTFS metadata

The catalogue includes `$MFT`, `$LogFile`, USN `$J`/`$Max`, `$Secure:$SDS`, `$Boot`
and `$Bitmap`. They are different from copying every file they describe.
A large sparse `$J` can have a much larger logical length than allocated data.
Keep original streams and manifests for parsers such as Juntei.

## Consider snapshots separately

`--vss` reads selected evidence from owned crash-consistent snapshots. It can
reduce live-file inconsistencies, but it does not coordinate application writers
or acquire every older restore point. Follow [VSS acquisition](../vss.md) and
review actual results rather than assuming an atomic machine image.
