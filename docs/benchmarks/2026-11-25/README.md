# Kumade collection-option benchmarks

**Measured results.** Native Windows 11 ARM64 VM, four virtual CPUs, 4 GiB RAM, one NTFS source/destination disk. These are observed times on this VM, not throughput guarantees for other systems.

Kumade 0.1.0 at `aa86395`. YARA Forge release `20261122` is pinned. Values below are medians; optional configurations have two measured runs and the default has four controls. Timing and size deltas are differences from the default median, with percentages calculated from the unrounded values. Durations and range endpoints are rounded independently to the nearest second (for example, `1m 42s`); exact seconds remain in the CSV files.

## Documentation table

| Configuration | Runs | Time | Extra time | Time change | Output files (GiB) | Extra file size (GiB) | Disk used (GiB) | Extra disk used (GiB) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Default options (C: only) | 4 | 41s | 0s | 0.0% | 5.180 | 0.000 | 3.460 | 0.000 |
| Without live inventory | 2 | 23s | -17s | -42.3% | 5.157 | -0.024 | 3.459 | -0.001 |
| Single acquisition worker | 2 | 1m 7s | +27s | +65.4% | 5.211 | +0.031 | 3.463 | +0.004 |
| Add RAM, without paired pagefile | 2 | 1m 38s | +57s | +140.7% | 9.142 | +3.962 | 7.452 | +3.992 |
| Add RAM and paired pagefiles | 2 | 1m 42s | +1m 2s | +151.7% | 9.839 | +4.659 | 8.138 | +4.678 |
| Add paging/swap/hibernation artifacts | 2 | 47s | +6s | +15.0% | 5.891 | +0.710 | 3.616 | +0.156 |
| Read artifacts from VSS | 2 | 44s | +3s | +7.8% | 5.177 | -0.003 | 3.436 | -0.024 |
| Save as NTFS VHDX | 2 | 59s | +18s | +44.0% | 3.507 | -1.674 | 3.507 | +0.047 |
| Save as compressed E01 | 2 | 2m 5s | +1m 25s | +208.5% | 1.660 | -3.521 | 1.660 | -1.800 |
| Add high-entropy PE discovery | 2 | 1m 49s | +1m 9s | +169.1% | 5.401 | +0.220 | 3.671 | +0.211 |
| Add YARA Forge Core | 2 | 1m 16s | +36s | +87.8% | 5.199 | +0.019 | 3.467 | +0.008 |
| Add YARA Forge Extended | 2 | 1m 27s | +46s | +113.8% | 5.183 | +0.002 | 3.477 | +0.018 |
| Add YARA Forge Full | 2 | 1m 31s | +50s | +123.9% | 5.184 | +0.004 | 3.479 | +0.019 |
| RAM + pagefiles + VSS + VHDX | 2 | 2m 12s | +1m 31s | +223.5% | 7.680 | +2.499 | 7.680 | +4.220 |

`GiB = 1,073,741,824 bytes`. “Output files” sums final file lengths; “Disk used” sums NTFS allocated bytes. Sparse NTFS streams and dynamic VHDX files can have a much larger reported file size than allocated storage. E01 size counts all compressed segments and the final JSON container report. VHDX virtual capacity is not treated as its saved file size. Small size differences also include background file/log/MFT growth and are not isolated feature-payload sizes.

## Commands

Common baseline (standard catalog artifacts and live inventory, optional features off, restricted to C:):

```powershell
.\kumade.exe collect --yes --volume C: -o <OUTPUT>
```

For a single change, add the flags below to that baseline. VHDX/E01 replace `-o`. `<TOOLKIT>` is an authorized external DumpIt toolkit; Kumade does not bundle it. Every matrix run explicitly uses `--volume C:` for consistent source scope. Unlettered/recovery/other volumes are excluded. “Default” here means the feature defaults on C:, rather than unrestricted all-volume discovery.

| Configuration | Additional / replacement arguments |
|---|---|
| Default options (C: only) | `(none)` |
| Without live inventory | `--no-live-info` |
| Single acquisition worker | `-T 1` |
| Add RAM, without paired pagefile | `--memory --no-memory-pagefile --dumpit <TOOLKIT>` |
| Add RAM and paired pagefiles | `--memory --dumpit <TOOLKIT>` |
| Add paging/swap/hibernation artifacts | `--paging` |
| Read artifacts from VSS | `--vss` |
| Save as NTFS VHDX | `--vhdx <OUTPUT>` (replaces `-o`) |
| Save as compressed E01 | `--e01 <OUTPUT>` (replaces `-o`) |
| Add high-entropy PE discovery | `--high-entropy` |
| Add YARA Forge Core | `--scan-processes --yara-ruleset core --yara-release 20261122` |
| Add YARA Forge Extended | `--scan-processes --yara-ruleset extended --yara-release 20261122` |
| Add YARA Forge Full | `--scan-processes --yara-ruleset full --yara-release 20261122` |
| RAM + pagefiles + VSS + VHDX | `--memory --dumpit <TOOLKIT> --vss --vhdx <OUTPUT>` |

The high-entropy runs additionally exclude this benchmark’s generated output tree to avoid scanning accumulated copies of the same binaries. The default extension coverage, threshold, scope and size limits are otherwise unchanged. The currently written output is also excluded by the collector.

## Timing variation and source coverage

| Configuration | Time range | Collected payloads, median | Partial payloads, median | Failed payloads, median | Discovery errors, median |
|---|---:|---:|---:|---:|---:|
| Default options (C: only) | 41s–43s | 5836.5 | 20 | 4 | 0 |
| Without live inventory | 21s–26s | 5829.5 | 24 | 4 | 0 |
| Single acquisition worker | 1m 7s–1m 8s | 5830 | 28 | 4 | 0 |
| Add RAM, without paired pagefile | 1m 38s | 5839 | 17.5 | 4 | 0 |
| Add RAM and paired pagefiles | 1m 40s–1m 44s | 5831 | 26 | 4 | 0 |
| Add paging/swap/hibernation artifacts | 45s–48s | 5837.5 | 19.5 | 4 | 0 |
| Read artifacts from VSS | 44s | 5848.5 | 6.5 | 4 | 0 |
| Save as NTFS VHDX | 58s–1m 0s | 5826 | 28.5 | 4 | 1 |
| Save as compressed E01 | 2m 4s–2m 7s | 5831 | 25.5 | 4.5 | 1 |
| Add high-entropy PE discovery | 1m 44s–1m 54s | 5872.5 | 21.5 | 4 | 0 |
| Add YARA Forge Core | 1m 15s–1m 18s | 5828 | 26.5 | 4 | 0 |
| Add YARA Forge Extended | 1m 27s | 5827 | 26.5 | 4 | 0 |
| Add YARA Forge Full | 1m 30s–1m 32s | 5827 | 26.5 | 4 | 0 |
| RAM + pagefiles + VSS + VHDX | 2m 10s–2m 13s | 5843.5 | 13.5 | 4 | 1 |

Partial or failed artifacts are **not** silently counted as successful. Exit 3 / Partial records incomplete source coverage even when every retained output passes byte-integrity verification. Live files may change between planning and copying; VSS can change both consistency and what is readable. Therefore size differences are observed outcomes, not a promise of identical evidence coverage.

The detailed coverage audit confirmed four recurring Windows application-execution-alias failures: native acquisition refuses to follow their reparse points. The inspected partial records report source metadata changing since planning/during reading. The container plan additionally reports access denied while inventorying ADS on a Defender cache file. One E01 run reported a fifth failed payload; its aggregate count is retained rather than treated as complete. No metadata-write errors or live-inventory provider failures were reported.

The entropy runs each analyzed 33,439 PE files and selected 38 candidates (138,242,416 bytes); high entropy is not proof of malware. YARA Core/Extended/Full loaded 5,078 / 10,848 / 11,853 rules including private helper rules. Core and Extended reported zero matches; Full reported one hunt-rule match in PowerShell in each run. These performance tests are not a false-positive-rate study. The performance comparison does not treat inaccessible or protected processes as clean scans.

## Resource and temporary-space observations

| Configuration | Collector CPU time | Observed collector peak working set (MiB) | Observed C: free-space drop (GiB) |
|---|---:|---:|---:|
| Default options (C: only) | 29s | 45.6 | 3.463 |
| Without live inventory | 29s | 46.8 | 3.462 |
| Single acquisition worker | 27s | 40.8 | 3.502 |
| Add RAM, without paired pagefile | 1m 11s | 46.8 | 7.455 |
| Add RAM and paired pagefiles | 1m 19s | 46.4 | 8.139 |
| Add paging/swap/hibernation artifacts | 33s | 50.0 | 3.620 |
| Read artifacts from VSS | 29s | 52.2 | 3.440 |
| Save as NTFS VHDX | 32s | 56.4 | 3.520 |
| Save as compressed E01 | 2m 10s | 58.7 | 5.186 |
| Add high-entropy PE discovery | 2m 52s | 104.5 | 3.673 |
| Add YARA Forge Core | 1m 24s | 184.7 | 3.474 |
| Add YARA Forge Extended | 1m 47s | 238.2 | 3.481 |
| Add YARA Forge Full | 1m 52s | 258.4 | 3.482 |
| RAM + pagefiles + VSS + VHDX | 1m 25s | 62.2 | 12.387 |

CPU and memory here refer to the Kumade process, excluding external DumpIt and child PowerShell providers. The working-set peak is observed through the process counter; resource sampling runs at approximately 500 ms. The free-space drop is a whole-volume proxy including concurrent Windows writes and temporary VSS/container/staging allocations; it is **not** exact process-owned disk usage or a sufficient sizing rule. Provision the collector’s required reserves and additional room for memory/container staging.

## Method and interpretation

- Collection uses `--yes` to bypass human wizard delays. Standard output/error are captured outside the measured evidence output; those harness logs are excluded from output sizes.
- One elevated, native ARM64 release binary was used throughout. SHA-256 and the exact commit are in `Benchmark-Environment.json`.
- A validated pilot/warm-up was excluded from the table. An earlier instrumentation pilot was also excluded because its exit/verification fields were not recorded correctly; its timing does not enter the comparison.
- Two rounds start with a default control, followed by a reproducibly shuffled option order. An extra default control after a background snapshot and another at the end expose drift. No cache flushing, reboot, antivirus disabling or workload reset was used.
- Time runs from process launch through exit and includes ordinary acquisition hashing/readback, memory staging/import, VSS cleanup and container finalization. Additional independent verification and final size measurement happen afterwards and are excluded.
- Every directory output is independently verified. VHDX outputs are remounted read-only and verified, then detached. E01 built-in logical readback is supplemented by an independent segment size/SHA-256 check. No benchmark-owned VSS snapshots or staging directories may remain for a valid row.
- YARA runs include the normal pinned-release download, rule compilation and process scan. Two workers, 16 MiB chunks and a 60-second per-process deadline are unchanged. Protected/inaccessible processes are reported as incomplete, not clean. YARA-source files saved with the evidence contribute to output size.
- RAM is still opt-in; paired active pagefiles are on by default when RAM is selected. The memory-only row explicitly disables pagefiles. `--paging` is a different catalog option that can include swap, hibernation and existing dumps; actual additions depend on what exists.
- `--vss` collects the selected artifacts from an owned crash-consistent snapshot; it does not copy every byte of the disk or freeze live-response inventory. VHDX/E01 also preserve NTFS metadata and add selected ADS coverage, so they are not merely alternate compression of an identical directory export.
- Removing live inventory omits volatile process/network/logon state; faster collection is a coverage tradeoff. Optional entropy discovery can add binaries, while process YARA adds findings/report data rather than a physical RAM dump.
- During the second RAM/pagefile run, an unrelated persistent client-accessible VSS snapshot appeared at 23:20:07 UTC, matching the prior day’s snapshot time. The collector did not request VSS in that run. It was retained, ownership was checked separately, and an extra default control was added before continuing. This background event remains part of the measured run; it was not removed from its elapsed time.
- Outputs were retained on the same virtual disk as the source. This changes the live filesystem/MFT and can increase subsequent metadata sizes and AV/Windows activity. File counts, baseline controls and time ranges accompany the medians to make that limitation visible. These results do not model USB speed, remote SFTP throughput, full partition imaging or a busy production server.
- Raw evidence, hostnames, account details, addresses and credentials remain private. Shared files contain measurements, settings and aggregate coverage only.

## Files

- `Benchmark-Summary.csv`: per-option medians, changes, ranges, output sizes and resource observations.
- `Benchmark-Runs.csv`: flat per-run measurements for spreadsheets.
- `Benchmark-Environment.json`: binary, environment and measurement definitions.
