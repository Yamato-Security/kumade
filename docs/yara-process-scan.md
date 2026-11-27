# Live process-memory YARA scanning

Run a native-architecture Windows build from an elevated terminal:

```powershell
# Bundled binaries use their embedded pack offline; the standard build downloads Core.
.\kumade.exe scan-processes -o .\Yara-Core
.\kumade.exe scan-processes --ruleset extended --rules-release 20261115 -o .\Yara-Extended
.\kumade.exe scan-processes --ruleset full --rules-release 20261115 -o .\Yara-Full
# Offline/local rules; repeat --pid to select several processes.
.\kumade.exe scan-processes --rules .\my-rules.yar --pid 1234 -t jsonl -o .\Yara-Selected
```

This is opt-in. The standalone command remains available; `collect --scan-processes` or the collection wizard can also run it and seal the results inside the collection. It uses Boreal's Rust YARA evaluator with an instrumented Windows memory reader (`OpenProcess`, `VirtualQueryEx`, `ReadProcessMemory`). It does not suspend, inject into, terminate, remediate or write to scanned processes. Normal memory reads can fault pages into RAM. It requests SeDebugPrivilege on the collector token when available; protected processes can remain inaccessible even when elevated. Use the native ARM64 build on ARM64 Windows and x64 on x64 Windows. Emulated builds refuse the operation rather than silently missing address space.

## Rules

The standard binary defaults to Core. A bundled binary defaults to its embedded pack. Extended and Full include broader hunting rules that require more analyst review and resources. A matching embedded pack is used offline when `--rules` is absent. Standard binaries download the selected pack; requesting a different set or dated release also downloads that pack over HTTPS. `--rules-release YYYYMMDD` makes the release selection repeatable; `latest` is convenient but changes over time. Keep the original ZIP or bundled executable and the hashes recorded in `RuleSource.json` for reproducibility. Archives are size limited and only the expected rule member is read; no archive paths are extracted. Local UTF-8 rules have includes disabled, so one supplied rule file cannot cause reads of arbitrary local files. All rules must compile; an error aborts the scan and is saved in `CompilationError.txt`. Warnings are saved in `CompilationWarnings.txt`. Rule console output is suppressed without changing its return value or condition semantics.

Optional Core/Extended/Full binaries embed the exact compressed Forge ZIP. Rules retain their individual authors, source URLs and license notices; they are not relicensed under Kumade’s RPL. Bundled releases also provide the unmodified source ZIP and rule-notice metadata as separate assets.

## Compressed/offline rule inputs and updates

Choose an executable ending in `-yara-core.exe`, `-yara-extended.exe` or
`-yara-full.exe` for offline use. Each contains one complete, compressed ZIP.
The chosen pack is also that binary's default in the collection wizard. Use
`doctor --check` to inspect its exact embedded release and archive hash.

The ZIP member is decompressed **in RAM**, then compiled by Boreal. YARA cannot
evaluate compressed bytes directly. Kumade does not extract member paths, create
a rules directory, or write `Rules.yar` while scanning. Normal scan results and
provenance are still written to the requested results directory.

```powershell
# Offline collection with a bundled binary:
.\kumade-0.1.0-win-aarch64-yara-core.exe collect --yes --scan-processes -o E:\Evidence

# Download the latest selected pack as one versioned ZIP:
.\kumade.exe update-rules --ruleset core -o E:\YaraRules
.\kumade.exe update-rules --ruleset extended -o E:\YaraRules
.\kumade.exe update-rules --ruleset full -o E:\YaraRules

# Use the ZIP reported by update-rules (replace the date if newer):
.\kumade.exe scan-processes --rules E:\YaraRules\yara-forge-rules-full-20261122.zip -o E:\YaraResults
.\kumade.exe collect --yes --scan-processes --yara-rules E:\YaraRules\yara-forge-rules-full-20261122.zip -o E:\Evidence
```

`--rules` / `--yara-rules` accepts either one official Forge ZIP or local UTF-8
YARA source. The ZIP's ruleset is identified from its expected member path;
archives with multiple/mismatching packs or duplicate rule members are refused.
Includes stay disabled. Explicit local inputs take precedence over embedded rules.
No rule directories beside the executable or in the working directory are
silently loaded.

`update-rules` works on the analyst's machine as well as Windows. Without `-o`,
it writes the ZIP directly into the directory containing the executable; choose another destination if
that location is read-only. It resolves `latest` once, checks the download size
and GitHub release-asset SHA-256, validates the archive and compiles every rule
before saving it. Hash checking detects corruption and disagreement with release
metadata; it does not independently authenticate the rule authors. Failed updates
leave existing packs intact. Matching existing ZIPs are reused; different contents
under an existing versioned name are never overwritten. Older versions remain.

Updating does not rewrite the executable or automatically select a local file.
Use the exact ZIP path printed by the command. An embedded pack stays at its
recorded release until a newer bundled executable is downloaded. The word
`latest` in a scan's default options does not force a matching embedded pack to
contact the network.

## Building bundled binaries

The **Release packages** workflow can build the standard executable plus all
three Forge variants for Windows x86, x64 and ARM64. Enable `bundle_rules` and
select a date tag or `latest`; one resolved tag is used across every platform.
Each executable download also has a ZIP containing only that executable.

For a local build, run `scripts/prepare_yara_bundle.py --ruleset core --release
20261122 --output <DIR>`, set `KUMADE_YARA_FORGE_ZIP`,
`KUMADE_YARA_FORGE_RELEASE` and `KUMADE_YARA_FORGE_SHA256` from its output, and
build with `cargo build --release --features bundled-yara-core`. Replace `core`
with `extended` or `full` consistently. Features are mutually exclusive. Builds
verify the archive hash before embedding it and never download during compilation.

## Results

- `YaraDetections.csv` / `.jsonl`: one row per matching process/rule. Includes hostname, PID, verified image path, process creation time, rule/tags/metadata and up to 16 pattern/address/length/XOR-key locations (one first occurrence per pattern, so an early frequent pattern does not hide later patterns). XOR key 0 indicates no XOR transformation for that match. Raw process bytes are not saved.
- `YaraProcesses.csv` / `.jsonl`: every selected/enumerated process, including failures, exits, timeouts and the collector exclusion. Read counts/bytes include module refetches, not unique memory coverage. Guard regions are explicitly counted and excluded.
- `Summary.json`: completion marker, rule/source hashes, counts, compilation/scan/total elapsed time, collector CPU seconds and peak working set (including rule compilation). `RunStarted.json` without `Summary.json` indicates an interrupted or failed run. Tables can be empty while still containing CSV headers.
- `RuleSource.json`: input kind, pack/release, origin, archive SHA-256 and expanded rule-source SHA-256. Expanded rule source is not written to disk.

`Scanned` means the eligible readable pages were scanned under the recorded limits, not that the process is safe. `Partial` retains any rule matches already returned by the engine while recording read failures, deadline expiration or target exit. `Failed` means a process could not be opened/identified/scanned. Exit 0 means all in-scope processes completed, not that no rules matched. Exit 3 indicates incomplete process coverage; exit 2 indicates a setup, compile or output error. Matches alone do not change the exit code.

The collector is excluded by default because its own memory contains YARA source and copied target bytes. Explicit `--pid` allows self-scanning for diagnostics and records resulting matches normally.

## Memory rule semantics and limits

A process's virtual address space is not an executable file. Boreal uses YARA-compatible fragmented-memory semantics, with PE virtual layout enabled and `filesize` undefined. Rules requiring disk headers at offset zero, raw file offsets, file hashes or `filesize` can compile without detecting their file-only target in process memory. Loading every rule does not imply every rule is suitable for memory. File scanning is not a substitute result silently included in this command.

The default is two process workers (`-T 1..16`), a 60-second per-process deadline (`--timeout`), and 16 MiB read chunks (`--chunk-mib 1..256`). Strings spanning independent chunks may be missed. Larger chunks trade memory use for fewer artificial boundaries; they do not remove real gaps in the address space. Legacy module/offset evaluation is retained rather than using a fast mode that disables those conditions. Deadlines are checked by the memory adapter and evaluator; in-flight Windows calls and individual module operations are not forcibly interrupted, so this is not a hard wall-clock kill limit. Boreal caps recorded matches at 1,000 per pattern; count/offset conditions beyond that cap can be affected. This is live, changing memory, not an atomic snapshot.

Rules that match software strings, dual-use tooling, a security product's signatures, browser contents or scanned files held in RAM can alert in legitimate processes. Inspect the rule's source, matching pattern locations, image path, process generation and surrounding evidence. A match is a hunting lead, not proof of active malware. Test-set results do not establish a universal false-positive rate.

## Compatibility qualification

The manually invoked `yara_forge_compile` integration test compiles each exact unmodified pack and compares the engine's rule count with the pack header. Windows tests launch an inert child containing unique ASCII/UTF-16 markers and ensure both detections survive alongside an inaccessible-PID result. They also verify failed read accounting and deadline termination. Benchmark findings are recorded in the PR after live Windows 11 validation.

## References

- [YARA Forge packages and selection guidance](https://yarahq.github.io/)
- [Boreal](https://github.com/vthib/boreal)
- [Boreal fragmented scan semantics](https://docs.rs/boreal/latest/boreal/scanner/struct.FragmentedScanMode.html)
