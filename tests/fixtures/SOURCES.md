# Redistributable acquisition fixtures

`ntfs-testfs1.img` is the synthetic NTFS filesystem `testdata/testfs1` from
Colin Finck's `ntfs` crate, version 0.4.0 (MIT OR Apache-2.0).

- Source: https://github.com/ColinFinck/ntfs/tree/3110cafc0440a84f2593b5d3691e0b23b68ccb8f/testdata
- Included notice: `NTFS-LICENSE-MIT`
- Contains synthetic numeric strings, sparse data, empty files and directories;
  no private case evidence.

Kumade's tests read the fixture without mounting it or modifying its contents.

## Synthetic hibernation acquisition fixture

`hibernation-ntfs.img.gz` is a 16 MiB NTFS filesystem generated for Kumade with
`mkntfs -F -Q -L KUMADE-TEST` and `ntfscp -f`. Its sole user payload is
`/hiberfil.sys`: 131,089 synthetic bytes, with byte `i` equal to `i % 251`.
These are deliberately not a valid Windows hibernation image and contain no
case evidence or memory captured from a computer. The authored test data is
provided under this repository's RPL-1.5 license.

The test decompresses the fixture into a temporary file and reads its
nonresident NTFS data directly, without mounting a drive. The normal filesystem
view has no `hiberfil.sys`, forcing the same raw NTFS fallback used when native
reads are unavailable. This checks acquisition, not hibernation decompression.

- Gzip SHA-256: `d141f02a4f8adf383942d3630620b13ec8785f15cbb83e02a39a1e856faa7b7d`
- Decompressed image SHA-256: `b512c4389918d7044f724a7d25bdcd8ef13d7af2532156b115cf3bfca754efbd`
