# Live process-memory YARA scanning

Run a native-architecture Windows build from an elevated terminal:

```powershell
# Default: download YARA Forge Core, scan all processes except this collector.
.\kumade.exe scan-processes -o .\Yara-Core
.\kumade.exe scan-processes --ruleset extended --rules-release 20261115 -o .\Yara-Extended
.\kumade.exe scan-processes --ruleset full --rules-release 20261115 -o .\Yara-Full
# Offline/local rules; repeat --pid to select several processes.
.\kumade.exe scan-processes --rules .\my-rules.yar --pid 1234 -t jsonl -o .\Yara-Selected
```

This is opt-in and separate from `collect`. It uses Boreal's Rust YARA evaluator with an instrumented Windows memory reader (`OpenProcess`, `VirtualQueryEx`, `ReadProcessMemory`). It does not suspend, inject into, terminate, remediate or write to scanned processes. Normal memory reads can fault pages into RAM. It requests SeDebugPrivilege on the collector token when available; protected processes can remain inaccessible even when elevated. Use the native ARM64 build on ARM64 Windows and x64 on x64 Windows. Emulated builds refuse the operation rather than silently missing address space.

## Rules

Core is the default. Extended and Full include broader hunting rules that require more analyst review and resources. Packages are downloaded over HTTPS only when `--rules` is absent. `--rules-release YYYYMMDD` makes the release selection repeatable; `latest` is convenient but changes over time. Keep `Rules.yar` and its recorded SHA-256 for exact reproducibility. Archives are size limited and only the expected rule member is read; no archive paths are extracted. Local UTF-8 rules have includes disabled, so one supplied rule file cannot cause reads of arbitrary local files. All rules must compile; an error aborts the scan and is saved in `CompilationError.txt`. Warnings are saved in `CompilationWarnings.txt`. Rule console output is suppressed without changing its return value or condition semantics.

Kumade does not bundle or relicense Forge rules. The downloaded source retains its individual authors, source URLs and license notices. Review those terms before redistributing a rule pack.

## Results

- `YaraDetections.csv` / `.jsonl`: one row per matching process/rule. Includes hostname, PID, verified image path, process creation time, rule/tags/metadata and up to 16 pattern/address/length locations. Raw process bytes are not saved.
- `YaraProcesses.csv` / `.jsonl`: every selected/enumerated process, including failures, exits, timeouts and the collector exclusion. Read counts/bytes include module refetches, not unique memory coverage. Guard regions are explicitly counted and excluded.
- `Summary.json`: completion marker, rule/source hashes, counts, compilation/scan/total elapsed time, collector CPU seconds and peak working set (including rule compilation). `RunStarted.json` without `Summary.json` indicates an interrupted or failed run. Tables can be empty while still containing CSV headers.
- `Rules.yar`: exact rule source used. No sensitive process bytes are stored in it.

`Scanned` means the eligible readable pages were scanned under the recorded limits, not that the process is safe. `Partial` retains any rule matches already returned by the engine while recording read failures, deadline expiration or target exit. `Failed` means a process could not be opened/identified/scanned. Exit 0 means all in-scope processes completed, not that no rules matched. Exit 3 indicates incomplete process coverage; exit 2 indicates a setup, compile or output error. Matches alone do not change the exit code.

The collector is excluded by default because its own memory contains YARA source and copied target bytes. Explicit `--pid` allows self-scanning for diagnostics and records resulting matches normally.

## Memory rule semantics and limits

A process's virtual address space is not an executable file. Boreal uses YARA-compatible fragmented-memory semantics, with PE virtual layout enabled and `filesize` undefined. Rules requiring disk headers at offset zero, raw file offsets, file hashes or `filesize` can compile without detecting their file-only target in process memory. Loading every rule does not imply every rule is suitable for memory. File scanning is not a substitute result silently included in this command.

The default is two process workers (`-T 1..16`), a 60-second per-process deadline (`--timeout`), and 16 MiB read chunks (`--chunk-mib 1..256`). Strings spanning independent chunks may be missed. Larger chunks trade memory use for fewer artificial boundaries; they do not remove real gaps in the address space. Legacy module/offset evaluation is retained rather than using a fast mode that disables those conditions. Deadlines are checked by the memory adapter and evaluator; in-flight Windows calls and individual module operations are not forcibly interrupted, so this is not a hard wall-clock kill limit. This is live, changing memory, not an atomic snapshot.

Rules that match software strings, dual-use tooling, a security product's signatures, browser contents or scanned files held in RAM can alert in legitimate processes. Inspect the rule's source, matching pattern locations, image path, process generation and surrounding evidence. A match is a hunting lead, not proof of active malware. Test-set results do not establish a universal false-positive rate.

## Compatibility qualification

The manually invoked `yara_forge_compile` integration test compiles each exact unmodified pack and compares the engine's rule count with the pack header. Windows tests launch an inert child containing unique ASCII/UTF-16 markers and ensure both detections survive alongside an inaccessible-PID result. They also verify failed read accounting and deadline termination. Benchmark findings are recorded in the PR after live Windows 11 validation.

## References

- [YARA Forge packages and selection guidance](https://yarahq.github.io/)
- [Boreal](https://github.com/vthib/boreal)
- [Boreal fragmented scan semantics](https://docs.rs/boreal/latest/boreal/scanner/struct.FragmentedScanMode.html)
