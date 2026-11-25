# Collect from offline directories

Offline mode accepts mounted Windows volume roots. The directory should contain
paths such as `Windows`, `Users` and `ProgramData` for that source volume.
Do not point it at an arbitrary parent folder and assume automatic image discovery.

```powershell
.\kumade.exe collect --yes -d D:\Case\C --computer HOST01 -o E:\Evidence
```

Repeat `--source` / `-d` for disjoint volume roots. Use `--profile-root` for
nonstandard profile paths that remain within a selected source.

```sh
./kumade collect --yes -d /cases/HOST01/C --computer HOST01 -o /cases/collected
```

Applicable directory acquisition works from source builds on Linux/macOS too.
Offline mode does not automatically read the analyst computer's Windows stores
or acquire its RAM. Live inventory, VSS and live process YARA are not offline
artifact analysis features. Entropy discovery can inspect offline PE files.

Kumade does not currently expose a VHDX/E01 **input** CLI. Mount or export an
image with an appropriate read-only forensic workflow, then supply its volume
root. VHDX/E01 **output** is a separate Windows capability.

Existing, overlapping or source-contained offline destinations are refused.
Keep the original evidence immutable and use a new output directory.
