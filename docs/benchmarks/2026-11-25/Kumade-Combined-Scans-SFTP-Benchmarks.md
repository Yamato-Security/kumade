# Combined scan and SFTP benchmarks

**Measured results.** Follow-up to the original 30-run matrix. Four configurations, two measured runs each. The same sender commit, C:-only scope, catalog, four acquisition workers and YARA Forge release `20261122` are used. “Maximum” below means RAM, paired pagefile and VSS, with optional standard entropy discovery and YARA Full as stated; it does not mean every CLI option or full partition imaging.

## Results

Durations are rounded independently to the nearest second. CSV files preserve exact seconds. All displayed values are medians.

| Configuration | Runs | Collect / upload time | Verified finish | Saved output (GiB allocated) |
|---|---:|---:|---:|---:|
| Local VHDX: RAM + pagefile + VSS + entropy + YARA Full | 2 | 7m 19s | 7m 19s | 7.859 |
| SFTP: default artifact and live-inventory options | 2 | 3m 16s | 3m 25s | 1.873 |
| SFTP: RAM + pagefile + VSS | 2 | 3m 53s | 4m 4s | 4.100 |
| SFTP: RAM + pagefile + VSS + entropy + YARA Full | 2 | 8m 14s | 8m 24s | 4.180 |

The local row ends at normal collector completion, including built-in hashing and container finalization. Additional read-only remount verification is excluded, as in the original matrix. For SFTP, “verified finish” ends only when the receiver has revoked upload credentials, re-read/decompressed the objects and written a successful readback receipt. The sender’s exit alone is not receiver verification. Timing boundaries differ by design and are shown separately.

SFTP and VHDX/E01 are mutually exclusive destinations. Remote cases stream files and NTFS metadata/ADS exports using default gzip; they do not upload a VHDX. The local VHDX row and SFTP rows are therefore practical mode comparisons, not identical-byte transport microbenchmarks. The same underlying selected artifact families are requested.

## Scan phases

| Configuration | Entropy phase | YARA phase (download / compile / scan) |
|---|---:|---:|
| Local VHDX: RAM + pagefile + VSS + entropy + YARA Full | 3m 46s | 48s |
| SFTP: RAM + pagefile + VSS + entropy + YARA Full | 3m 32s | 46s |

These phase timings are included in the collector total, not extra time to add again. The combined runs read entropy candidates through VSS and also enable RAM/container work; they are not a controlled test isolating VSS overhead from caching or other feature interactions.

## Storage and resource observations

| Configuration | File lengths (GiB) | Observed source free-space drop (GiB) | Collector CPU time | Collector peak working set (MiB) |
|---|---:|---:|---:|---:|
| Local VHDX: RAM + pagefile + VSS + entropy + YARA Full | 7.859 | 13.496 | 5m 46s | 290.7 |
| SFTP: default artifact and live-inventory options | 1.857 | 0.690 | 48s | 61.5 |
| SFTP: RAM + pagefile + VSS | 4.084 | 5.504 | 1m 57s | 66.6 |
| SFTP: RAM + pagefile + VSS + entropy + YARA Full | 4.164 | 5.654 | 6m 8s | 276.7 |

Free-space changes include concurrent OS writes and are approximate whole-volume observations, not exact process-owned peak usage. Collector CPU/memory excludes external DumpIt and child inventory providers. Memory acquisition still requires temporary RAM/pagefile staging on Windows, even with SFTP. Metadata staging is also required; disk payloads are streamed rather than first saved as a full local collection. The receiver keeps compressed objects and verifies in place without restoring another full copy.

## Coverage and verification

| Configuration | Collector time range | Collected, median | Partial, median | Failed, median | Discovery errors, median |
|---|---:|---:|---:|---:|---:|
| Local VHDX: RAM + pagefile + VSS + entropy + YARA Full | 7m 1s–7m 37s | 5887 | 20 | 4 | 2 |
| SFTP: default artifact and live-inventory options | 3m 11s–3m 20s | 5819.5 | 57.5 | 4 | 1 |
| SFTP: RAM + pagefile + VSS | 3m 43s–4m 3s | 5847 | 32 | 4 | 1 |
| SFTP: RAM + pagefile + VSS + entropy + YARA Full | 8m 9s–8m 19s | 5908 | 13.5 | 4 | 2 |

Integrity verification is separate from completeness. Partial or failed source reads remain visible; a valid receiver receipt does not turn them into complete acquisition. RAM acquisition must report success, paired pagefiles must be present, scan summaries must confirm the selected rule pack, and no benchmark-owned snapshot or temporary stage may remain for an accepted measurement. Synthetic connectivity/calibration pilots are excluded.

## Reproducing the options

Common prefix: `kumade collect --yes --volume C:`. Append one of the configurations below. For entropy tests, also exclude the tree holding prior benchmark copies so the collector does not scan its own accumulated outputs.

| Configuration | Arguments |
|---|---|
| Local VHDX: RAM + pagefile + VSS + entropy + YARA Full | `--memory --dumpit <TOOLKIT> --vss --high-entropy --scan-processes --yara-ruleset full --yara-release 20261122 --vhdx <OUTPUT>` |
| SFTP: default artifact and live-inventory options | `--sftp <SERVER> --sftp-port <PORT> --sftp-user <TEMP_USER> --sftp-host-key <PIN> --sftp-staging-dir <METADATA>` |
| SFTP: RAM + pagefile + VSS | `--memory --dumpit <TOOLKIT> --vss --memory-staging-dir <RAM_STAGE> --sftp <SERVER> --sftp-port <PORT> --sftp-user <TEMP_USER> --sftp-host-key <PIN> --sftp-staging-dir <METADATA>` |
| SFTP: RAM + pagefile + VSS + entropy + YARA Full | `--memory --dumpit <TOOLKIT> --vss --memory-staging-dir <RAM_STAGE> --high-entropy --scan-processes --yara-ruleset full --yara-release 20261122 --sftp <SERVER> --sftp-port <PORT> --sftp-user <TEMP_USER> --sftp-host-key <PIN> --sftp-staging-dir <METADATA>` |

Supply temporary SFTP passwords through the hidden prompt or `--sftp-password-stdin` from a secret manager, never in arguments/environment or logged files. The benchmark feeds the one-time password over an existing private SSH stdin channel. The receiver is restricted to the source VM address; credentials and keys are regenerated per case and revoked before verification.

## Test environment and limitations

- Native Windows 11 ARM64 sender: four virtual CPUs, 4 GiB RAM. Local output and RAM staging use its C: NTFS virtual disk.
- Linux ARM64 receiver: eight logical CPUs. Receiver storage is a 32 GiB ext4 loop image backed by host-shared storage, mounted with nodev/nosuid/noexec and owner-only access. This extra storage layer affects latency; results do not represent a native dedicated-server disk.
- The two VMs communicate directly over the same private virtual LAN. There is no SSH transport tunnel, WAN path or bandwidth shaping. Both VMs ultimately share the physical host and storage, so these are observed lab results, not general network-throughput guarantees.
- Existing benchmark outputs were retained. OS/log/MFT growth, caches, background activity and the existing snapshots can vary the data and timings. No reboot, cache flush, AV disabling or reset was performed. Two passes are a small sample.
- The original matrix’s default/control values are historical controls, not simultaneous paired tests for this follow-up. Avoid interpreting small size/time differences as isolated feature cost.
- Raw evidence, addresses, hostnames, account names, passwords, runtime paths and receiver credentials remain private. Only measurement aggregates and settings are published.

## Measurement files

- `Benchmark-Extended-Summary.csv`: medians, ranges, output sizes and resource observations.
- `Benchmark-Extended-Runs.csv`: flat per-run measurements.
- `Benchmark-Extended-Runs.json`: sanitized scan/coverage aggregates alongside per-run measurements.
- `Benchmark-Extended-Environment.json`: pinned binaries and test conditions.
