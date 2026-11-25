# Benchmarks

The published measurements cover a Windows 11 ARM64 VM with four virtual CPUs
and 4 GiB RAM, restricted to `C:`. Kumade was pinned to source commit `aa86395`.
Timings are medians; durations are displayed as minutes/seconds and exact
seconds remain in the downloadable CSV files.

## What was measured

| Set | Runs | Coverage |
|---|---:|---|
| [Collection options](2026-11-25/README.md) | 30 | Default controls, RAM/pagefiles, VSS, directory/VHDX/E01, entropy, YARA packs, worker count and live inventory |
| [Combined scans and SFTP](2026-11-25/Kumade-Combined-Scans-SFTP-Benchmarks.md) | 8 | RAM/pagefile/VSS with entropy + YARA Full locally, and three SFTP configurations |

The original **2m 12s** combination included RAM, paired pagefile, VSS and VHDX,
with entropy/YARA off. The local combination with those scans enabled measured
**7m 19s**. The full SFTP combination measured **8m 14s** to collect/upload and
**8m 24s** through receiver verification. See the reports for repetitions,
ranges, source gaps and the exact option sets.

## How to interpret the numbers

- Feature interactions matter: do not add isolated timings to predict a combined run.
- File length, allocated disk space, compressed size, virtual capacity and peak temporary space differ.
- SFTP sender completion is not receiver verification. Both timing boundaries are shown.
- The receiver used an ext4 loop image backed by shared host storage on a private VM LAN. These are not WAN or dedicated-server throughput claims.
- RAM size, active pagefiles, artifact volume, background writes, caches, security controls and hardware affect results.
- Successful stored-byte checks do not erase partial acquisition or source-change reports.

Raw private payloads are not published. The reports include sanitized measurement
files and pinned environment details. [Validation history](../testing.md)
covers additional correctness checks separately from speed.
