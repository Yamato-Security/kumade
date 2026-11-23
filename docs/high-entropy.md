# Collect high-entropy binaries

Use `--high-entropy` to look beyond the normal artifact catalogue for PE binaries
that may be packed, encrypted or obfuscated. Qualifying files are added to the
normal acquisition plan and copied with their original relative paths and
SHA-256 verification. This is optional: ordinary collection does not scan every
binary on a drive.

High entropy means that byte values are relatively unpredictable. Packed code
can have high entropy, but so can legitimate software. Some packed/malicious
programs have low entropy. Treat these as **packing candidates**, not malware
verdicts or a complete malware scan. A clean result does not establish that the
machine is clean.

## Usage

Run live acquisition from an elevated PowerShell session, saving to a separate
evidence drive:

```powershell
# Normal artifacts plus high-entropy PE candidates on C:
.\kumade.exe collect --volume C: --high-entropy -o E:\Evidence

# Read artifacts and binaries from owned crash-consistent snapshots:
.\kumade.exe collect --volume C: --vss --high-entropy --vhdx E:\Evidence

# The same candidate acquisition also works inside E01 output:
.\kumade.exe collect --volume C: --high-entropy --e01 E:\Evidence

# Review the plan without copying evidence; analysis still reads source files:
.\kumade.exe plan --volume C: --high-entropy -o E:\EntropyPlan
```

Without `--volume` or `--source`, live mode uses Kumade's normal fixed-volume
selection, excluding the non-system destination volume. Entropy discovery
scans the selected roots, not just catalogue directories. A source explicitly
restricted to NTFS metadata is excluded and reported as such. Use `--volume`
to choose the drives to scan. No network, removable or excluded drive is added
to the selection by this option.

Offline collection from already mounted/copied Windows volume directories is
available on the usual supported hosts:

```bash
kumade collect -d /cases/HOST/C --computer HOST --high-entropy -o /cases/output
```

`--artifact` controls the regular catalogue. `--high-entropy` independently adds
packing candidates across each selected source root; it does not narrow its
search to those artifact paths. A file already selected by the catalogue is
copied once and receives both artifact identifiers.

### Which files are opened

The walk visits every regular file under the selected roots, but it only opens
files whose extension is on a built-in list: executable images (`.exe`, `.dll`,
`.sys`, `.scr`, `.cpl`, `.ocx`, `.com`, `.drv`, `.efi`, `.pyd`, …), scripts
(PowerShell, WSH, JavaScript, batch, HTA, Python, shell, …), shortcuts and
launchers, registry/configuration/XML text, web pages, Office and other
documents, mail, archives, installers and packages, disk images, mailboxes, and
the data and temporary names that payloads are hidden under (`.bin`, `.dat`,
`.tmp`, `.txt`, `.log`, `.bak`, `.old`, `.cache`, `.dmp`, `.raw`, …). The full
list is `DEFAULT_EXTENSIONS` in `src/entropy.rs`. The comparison ignores case
and looks at the final extension only. Recognition inside an opened file is
still by PE header, so a renamed executable is found under any listed name.

Files with other names, and files without an extension, are counted in
`EntropySummary.json` as `OtherExtension` and are not opened. Add names with
`--entropy-extension <EXT>` (repeatable), or open every regular file with
`--entropy-all-files`, which is the slower, exhaustive mode.

## Tuning

| Option | Default | Meaning |
|---|---|---|
| `--high-entropy` | Off | Enable discovery and collection |
| `--entropy-threshold <BITS>` | `7.2` | Shannon entropy in bits/byte, finite and greater than 0 through 8 |
| `--entropy-scope <SCOPE>` | `executable-sections` | `executable-sections`, `file`, or `either` |
| `--entropy-min-bytes <BYTES>` | `4096` | Minimum size of the measured file/section |
| `--entropy-max-file-mib <MiB>` | No cap | Skip analysis of larger PE files and record `SizeLimit` |
| `--entropy-max-candidates <COUNT>` | No cap | Limit additional selected binary files |
| `--entropy-max-collect-mib <MiB>` | No cap | Limit logical bytes of additional selected binary files |
| `--entropy-exclude <GLOB>` | None | Repeatable, case-insensitive source-relative exclusion |
| `--entropy-extension <EXT>` | None | Repeatable; also open files with this extension (dot optional, case ignored) |
| `--entropy-all-files` | Off | Open every regular file instead of only the built-in extension list |
| `-T, --threads <COUNT>` | Available logical CPUs, capped at 4; explicit maximum 128 | Parallel scan/acquisition workers |

Entropy options require `--high-entropy`. Limits must be positive. MiB values
are checked for 64-bit byte overflow. Limits on candidates/collection bytes
apply to **additional** collection, leaving ordinary catalogue collection
intact. They do not stop enumeration: all discovered candidates remain in the
report, with skipped selections marked `SelectionLimit`. Size/selection limits
and scan errors make entropy coverage partial rather than implying that every
qualifying binary was acquired. Intentional path/reparse exclusions are listed
as `Excluded`; their contents have not been checked.

```powershell
.\kumade.exe collect --volume C: --high-entropy --entropy-threshold 7.5 `
  --entropy-max-file-mib 2048 --entropy-max-candidates 500 `
  --entropy-max-collect-mib 10240 --entropy-exclude 'Windows/WinSxS/**' `
  --entropy-exclude 'Program Files/KnownVendor/**' -T 4 -o E:\Evidence
```

Use `/` in portable exclusion patterns, including on Windows. Exclusions
apply only to entropy discovery, not ordinary artifact collection.

### Why executable sections by default?

Whole-file entropy can be raised by compressed resources, certificates or
appended archives that are unrelated to packed code. The default selects a
file only when at least one PE section carrying `IMAGE_SCN_MEM_EXECUTE` has
at least 4096 on-disk bytes and reaches the threshold. `file` uses the entire
logical file instead, including headers, overlays and certificate bytes.
`either` accepts either criterion. Zero-filled virtual padding is not counted
as section data. All PE sections are reported with their sizes, offsets,
executable flag and individual entropy.

For example, validation with an inert generated Windows x64 program and UPX
4.2.4 produced:

| File | Whole-file entropy | Largest eligible executable-section entropy | Default result |
|---|---:|---:|---|
| Original benign PE | 7.953 | None (code section smaller than minimum) | BelowThreshold |
| UPX-packed copy, renamed `.dat` | 7.137 | 7.589 | Selected |

This illustrates the difference between scope choices; it is not an accuracy
benchmark or an estimate of real-world false positives. The input was never
executed. Thresholds should be tuned to the environment.

## Output and interpretation

Candidates use artifact ID `windows.binaries.high_entropy`. Normal manifests,
source metadata handling, readback verification, coverage and integrity seals
still apply. The original collection layout is preserved; binaries are not
executed or unpacked.

Three additional run-root files are sealed:

- `HighEntropyBinaries.csv`: one row per analyzed PE, scan error, cap or explicit
  path exclusion. Non-PE files contribute to counters rather than individual rows.
- `HighEntropyBinaries.jsonl`: equivalent rows for automated analysis. `Sections`
  contains a JSON-encoded section array, matching the CSV field.
- `EntropySummary.json`: settings, analysis start/end UTC times, counters and
  interpretation limits.

`Plan.json` stores the settings, the counters and the expected hash of every
selected file; the per-file inventory is only in the two report files, so the
plan stays small on drives with 100,000 or more PE files. `plan` mode writes
the same three report files beside `Plan.json`, without the acquisition columns,
and creates no collection. Default collections without the flag do not gain
entropy fields or report files.

| Field | Interpretation |
|---|---|
| `Computer`, `SourceId`, `RelativePath` | Source computer, selected volume/root and path within it |
| `Method` | `FileAPI`, `RawNTFS` or `CollectedCopy` for a successful analysis |
| `AnalysisStatus` | `Selected`, `AlreadyPlanned`, `BelowThreshold`, `Malformed`, `SizeLimit`, `SelectionLimit`, `Excluded`, `Error` or `EnumerationError` |
| `Reason` | Error, exclusion or limit explanation |
| `Size`, `SHA256` | Logical length and SHA-256 of the complete analyzed file |
| `FileEntropy`, `MaxExecutableEntropy` | Whole-file entropy and maximum executable-section entropy meeting minimum size; null/empty when unavailable |
| `Machine`, `IsDLL` | COFF machine code and DLL characteristic; PE signatures drive recognition, not `.exe` extensions |
| `HasCertificateTable` | A positive in-bounds certificate-table range exists; **not** signature validation or publisher trust |
| `Sections` | JSON array of `Name`, `RawOffset`, `RawSize`, `Executable`, `Entropy` |
| `ObservationId` | Join key to `Manifest.csv`/`Manifest.jsonl` for selected files |
| `AcquisitionStatus`, `CollectedSHA256`, `RelativeOutputPath` | Actual copy result and output location; unavailable if not selected |
| `HashMatchesAnalysis` | Whether the copied content matches the analyzed content; blank/null without an acquired hash |

The analysis SHA-256 belongs only to the unnamed `$DATA` stream. Named ADS
added by native NTFS preservation retain their own hashes and do not inherit
that expected digest. If the copied binary differs, its bytes are retained but
its acquisition is `Partial`; its report shows a hash mismatch. `verify`
checks the sealed reports and refuses an `Acquired` binary whose stored hash
disagrees with the analysis hash.

## Coverage and performance limits

- Header validation recognizes executable PE32/PE32+ images, including DLLs,
  drivers and files with unusual extensions. A file with the MZ and PE
  signatures but without the executable-image flag (.NET Native `.toc` tables,
  `.mibc` profile data) is a container the heuristic cannot score and is counted
  with the non-PE files. An image whose section table or optional header is
  truncated or out of range gets a `Malformed` row and counter; it is not an
  acquisition failure and does not make the run `Partial`. The scanner does not
  find scripts, ELF, archives, embedded PE payloads, deleted files, or PE content
  hidden only in named streams. It does not promise Windows loader validation.
- Only files with a listed extension are opened. A payload stored under a name
  outside the list, or without an extension, is counted but not inspected unless
  `--entropy-all-files` or `--entropy-extension` says otherwise.
- The directory walk skips symlinks and reparse points rather than traversing
  other volumes or aliases. Cloud-only placeholders and WOF/reparse files may
  therefore be excluded. Excluded directories count as one exclusion, not an
  inventory of every child.
- Enumeration/access errors are retained; they are not interpreted as a clean
  result. A file inaccessible to both normal reads and raw NTFS cannot be
  scored. Direct file reads can handle Windows-supported compression; raw
  NTFS fallback refuses compressed/encrypted data streams it cannot decode.
- Raw fallback opens the selected NTFS device read-only and analyzes logical
  file streams without a temporary extracted copy. It is used for file-I/O
  failures, not to hide malformed-PE or source-change failures. With VSS it
  uses the snapshot device and never retries against the original live drive.
- Live files can change. File identity/size/timestamps are compared across
  analysis, and hashes link analysis to acquisition. These checks do not make
  an unsnapshotted live read atomic. Prefer `--vss` when appropriate.
- During collection, entropy discovery runs after the selected artifacts have
  been acquired. Already captured files use their verified collected copies.
  Standalone `plan --high-entropy` still analyzes sources directly. See
  [acquisition order](acquisition-order.md).
- All valid discovered PEs are fully read and hashed, regardless of whether
  they pass the heuristic. Qualifying files are then read again for collection
  and readback verification. Large drives, slow disks and many PE files can
  add substantial time and I/O: on a 150 GB developer image with 156,000 PE
  files the scan read about 80 GB and took 42 minutes on two CPUs. The scanner
  has a count/spinner, not a percent, because the total file count is unknown
  during enumeration.
- Read buffers are approximately 1 MiB plus at most 96 section histograms per
  worker. In-memory inventory grows with the number of PE/error/exclusion
  records; it is not constant for an entire drive (about 190 MB of working set
  for the image above). Container sizing reserves space for the CSV/JSONL
  reports from the size of that inventory.

## References

- [Microsoft PE/COFF format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [YARA PE module](https://yara.readthedocs.io/en/stable/modules/pe.html)
- [Sysinternals Sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck)
