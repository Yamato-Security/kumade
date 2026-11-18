# Redistributable acquisition fixtures

`ntfs-testfs1.img` is the synthetic NTFS filesystem `testdata/testfs1` from
Colin Finck's `ntfs` crate, version 0.4.0 (MIT OR Apache-2.0).

- Source: https://github.com/ColinFinck/ntfs/tree/3110cafc0440a84f2593b5d3691e0b23b68ccb8f/testdata
- Included notice: `NTFS-LICENSE-MIT`
- Contains synthetic numeric strings, sparse data, empty files and directories;
  no private case evidence.

Kumade's tests read the fixture without mounting it or modifying its contents.
