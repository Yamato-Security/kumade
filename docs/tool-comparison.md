# Kumade: comparison of Windows triage collection tools

**Yamato Security · Design research · 18 November 2026**

This compares three Windows evidence collectors used as design references. It accompanies [Kumade's system design and architecture](architecture.md).

The review covered public documentation, artifact definitions and selected acquisition/orchestration code. No collector was executed and no speed, memory or artifact-completeness benchmark was performed. “Not established” means a capability was not demonstrated by this review; it does not prove that a tool cannot provide it. Kumade's recommendations below describe the target design; see [implementation status](implementation-status.md) for current features.

## 1. What each project actually is

| Tool | Primary role | Most valuable characteristic | Main limitation for Kumade's goal |
|---|---|---|---|
| **Washizukami-Collector** | Rust Windows collector with raw NTFS access | Closest architectural reference: portable Rust collector, definitions, hashing, VSS and memory integration | Deliberately curated coverage; several completeness, memory and packaging behaviors need stronger guarantees |
| **CDIR Collector** | Native Windows first-response collector | Simple deployment and collection of locked artifacts, NTFS metadata and RAM | Smaller, comparatively fixed collection scope and older multi-component implementation |
| **herosi/triage-collector** | Expanded CDIR-derived collector | Broad practical artifact list, configurable recursion, RAM and paging-file collection | Legacy dependencies and path/acquisition assumptions need modernization |

Sources: [Washizukami](https://github.com/tadmaddad/Washizukami-Collector/blob/2a8b84eafc34bb95f5373f1157d41f756af6c164/README.md), [CDIR](https://github.com/CyberDefenseInstitute/CDIR/blob/b333b814fc3b32fe8800f73fcfd0413bf18e67fe/README_en.md), [triage-collector](https://github.com/herosi/triage-collector/blob/0cfe0affa7c62c65d1a5ecfb3429a7a2e00fc7c5/README.md).

## 2. Capability comparison

| Capability | Washizukami | CDIR | triage-collector |
| --- | --- | --- | --- |
| Acquire artifacts itself | Yes | Yes | Yes |
| Read locked files | Raw NTFS; standard-copy fallback | NTFSParserDLL raw access | NTFSParserDLL raw access |
| Change collection definitions without rebuilding | External YAML additions/overrides | INI toggles | INI plus user/system rules |
| Run existing processing tools | WinPmem/YARA-X integrations | Memory helper integration | Memory helpers and separate analysis helpers |
| VSS collection | Existing snapshots plus live volume | Not established | Not established |
| Physical RAM | External WinPmem with `--mem` | External WinPmem | WinPmem; configurable DumpIt alternative |
| Pagefile and swapfile | Supplied custom definitions; not core defaults | Not in the documented core list | Explicit acquisition support |
| Collection hashes | SHA-256 while copying | Hash logging in source | MD5/SHA-1/SHA-256 logging in source |
| Packaging | ZIP after directory collection | Directory output | Directory output |
| Cloud transfer | Not established | Not established | Not established |
| Rust implementation | Yes | C++ plus DLLs/helpers | C++ plus DLLs/helpers |

The project-specific sources below support the comparison. An external memory helper is distinct from a native acquisition implementation.

## 3. Washizukami-Collector

### Good

This is the closest reference for a Rust collector. It has a standalone executable, embedded artifact definitions, YAML customization, raw NTFS access, SHA-256 acquisition logs, existing-VSS collection, and external WinPmem integration. Its deliberate focus on a maintained core is understandable for first-response use. [Project overview](https://github.com/tadmaddad/Washizukami-Collector/blob/2a8b84eafc34bb95f5373f1157d41f756af6c164/README.md).

The reviewed core contains **40 definitions across seven YAML files**. It includes eleven event-log channels, Jump Lists, ActivitiesCache, scheduled tasks and user hive companions. It would be inaccurate to describe the current core as only Security/System/Application logs. [Core definitions](https://github.com/tadmaddad/Washizukami-Collector/tree/2a8b84eafc34bb95f5373f1157d41f756af6c164/artifacts/core).

### Tradeoffs and concerns

- Coverage is intentionally narrower than Kumade's objective. Core NTFS definitions omit `$LogFile` and `$UsnJrnl:$Max`; the SRUM definition selects `SRUDB.dat` rather than its whole recovery family. Paging files and Outlook examples are custom opt-ins. [NTFS definitions](https://github.com/tadmaddad/Washizukami-Collector/blob/2a8b84eafc34bb95f5373f1157d41f756af6c164/artifacts/core/windows_ntfs.yaml), [SRUM](https://github.com/tadmaddad/Washizukami-Collector/blob/2a8b84eafc34bb95f5373f1157d41f756af6c164/artifacts/core/windows_srum.yaml), [configuration](https://github.com/tadmaddad/Washizukami-Collector/blob/2a8b84eafc34bb95f5373f1157d41f756af6c164/config.yaml).
- Missing WinPmem and nonzero WinPmem exit status are logged, but `run_winpmem` returns `Ok(())` in those cases. An explicitly requested memory capture is therefore not enforced as a successful deliverable. [Memory adapter](https://github.com/tadmaddad/Washizukami-Collector/blob/2a8b84eafc34bb95f5373f1157d41f756af6c164/src/exttools.rs#L65).
- `create_zip` uses `std::fs::read` for each input, so its memory demand can grow with the largest file—especially a RAM dump. The main collection loop is sequential, and reported artifact failures do not themselves change its final `Ok(())`. [Main acquisition and ZIP code](https://github.com/tadmaddad/Washizukami-Collector/blob/2a8b84eafc34bb95f5373f1157d41f756af6c164/src/main.rs#L291).

**What Kumade should take:** the small deployment footprint, raw-read fallback, embedded catalog and straightforward operator experience. Add bounded streaming, paired-memory validation, richer completeness accounting and storage-aware concurrency. Its AGPL-3.0 license must be respected; independent design inspiration is not permission to relabel its code as RPL.

## 4. CDIR Collector

### Good

CDIR provides a simple incident-response collection flow with RAM, NTFS metadata, registry, Prefetch, event logs, WMI, SRUM and browser data. It supports `Windows.old` and uses NTFSParserDLL for raw acquisition. INI switches and a machine/time-named output directory make deployment understandable. [CDIR overview](https://github.com/CyberDefenseInstitute/CDIR/blob/b333b814fc3b32fe8800f73fcfd0413bf18e67fe/README_en.md).

### Tradeoffs and concerns

The documented package needs the executable, configuration, parser DLL, crypto libraries and architecture-specific memory helpers. Its fixed collection functions are less adaptable than a typed artifact catalog. The reviewed source includes legacy fixed-size path buffers and a vendored LibreSSL 2.5.5 directory; these warrant modernization and dependency review, not an unsupported claim of a specific exploitable vulnerability. [Acquisition source](https://github.com/CyberDefenseInstitute/CDIR/blob/b333b814fc3b32fe8800f73fcfd0413bf18e67fe/CDIR/CDIR.cpp), [repository components](https://github.com/CyberDefenseInstitute/CDIR/tree/b333b814fc3b32fe8800f73fcfd0413bf18e67fe/CDIR).

Resumable acquisition, signed catalogs, cloud transport and a machine-readable completeness contract were not established. The repository declares GPL-2.0; copying its implementation requires an appropriate licensing basis.

**What Kumade should take:** first-response simplicity and the established raw-acquisition model. Replace the scattered deployment components with a Rust core and explicitly versioned optional provider packages.

## 5. herosi/triage-collector

### Good

This CDIR-derived project expands collection to paging files, `$LogFile`, transaction logs, service profiles and configurable recursive user/system paths. Its supplied INI covers practical evidence such as SYSVOL, NTDS, BITS, PCA, RDP cache, shell history and scheduled tasks. RAM can use WinPmem or a separately supplied DumpIt binary. [Project description](https://github.com/herosi/triage-collector/blob/0cfe0affa7c62c65d1a5ecfb3429a7a2e00fc7c5/README.md), [default INI](https://github.com/herosi/triage-collector/blob/0cfe0affa7c62c65d1a5ecfb3429a7a2e00fc7c5/triage-collector/triage-collector.ini).

### Tradeoffs and concerns

- The package retains C++/DLL/crypto-helper and external-driver dependencies. Bundled older helper versions should not be assumed compatible with current Windows security policy.
- `get_analysisdata` acquires `pagefile.sys` and `swapfile.sys` using the OS-volume path. This does not demonstrate discovery of **all** active pagefiles on other volumes.
- The separate registry-reading function converts one `REG_MULTI_SZ` buffer into a single string; it is not evidence of complete multi-pagefile enumeration. These are source-level limitations, not results from an executed test. [Paging and memory code](https://github.com/herosi/triage-collector/blob/0cfe0affa7c62c65d1a5ecfb3429a7a2e00fc7c5/triage-collector/triage-collector.cpp#L507).
- Broad acquisition remains dependent on the supplied INI and commented entries. Resume, signed updates and future cloud upload were not established. The declared license is GPL-2.0.

**What Kumade should take:** the expanded real-world artifact coverage and memory/paging workflow. Improve actual volume/profile discovery, long-path handling, provider qualification and explicit validation.

## 6. Recommended foundation for Kumade

**Use an independent Rust implementation, a broad tested catalog, and the existing Yamato analysis tools.** Do not fork one collector and inherit all of its acquisition and licensing assumptions.

Kumade should collect original evidence; Juntei, Hayabusa and Takajo should remain independently usable processing stages. An explicitly requested processing stage can orchestrate approved tools when needed.

The strongest improvements are:

1. Discover every local volume and profile instead of relying on a handful of default paths.
2. Collect all supported acquisition definitions by default, including database recovery companions, with no silent maximum-size or date filter.
3. Preserve live/VSS origins, raw/derived distinctions, exact stream identities and original timestamps.
4. Make locked-file acquisition, RAM/pagefile pairing, partial reads and parser validation visible in manifests and exit codes.
5. Stream acquisition and packaging with bounded buffers; avoid reading a whole dump into RAM or requiring two complete copies on disk.
6. Prove parity through fixture comparisons and realistic Windows tests, rather than asserting that Rust or a larger artifact list guarantees completeness.

## 7. Reviewed revisions and licensing observations

| Repository | Reviewed commit | Licensing observed |
|---|---|---|
| Washizukami-Collector | `2a8b84eafc34bb95f5373f1157d41f756af6c164` | AGPL-3.0 |
| CDIR | `b333b814fc3b32fe8800f73fcfd0413bf18e67fe` | GPL-2.0 |
| triage-collector | `0cfe0affa7c62c65d1a5ecfb3429a7a2e00fc7c5` | GPL-2.0 |
| Juntei | `044ba8996ae1cc21f8565fa95868a836edce1c0b` | RPL-1.5 |

Kumade's requested license is **RPL-1.5**, matching the reviewed [current Juntei license](https://github.com/Yamato-Security/juntei/blob/044ba8996ae1cc21f8565fa95868a836edce1c0b/LICENSE). Treat reference projects as design sources unless their code/data has an approved reuse basis; preserve third-party notices and audit dependency/provider licenses individually.
