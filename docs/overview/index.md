# About Kumade

Kumade (熊手, a rake) is a Rust Windows evidence collector by Yamato Security.
It gathers the bytes and context needed for a later investigation. Hayabusa
analyzes Windows event logs, Takajo helps investigate Hayabusa timelines, and
Juntei parses other Windows forensic artifacts.

## What a collection does

Kumade discovers the selected volumes, profile roots and catalogue paths;
plans the work; acquires supported files or raw NTFS streams; and records
source observations, outcomes and hashes. The output includes payloads plus
manifests and coverage reports. Live Windows collections include live inventory
by default. Optional features add RAM with pagefiles and swapfile, VSS, YARA process scanning
and entropy-based PE collection.

Default live collection checks the selected catalogue families on all discovered
local fixed volumes. It is not a recursive backup of every file. Application
locations, access restrictions, host roles and Windows versions affect coverage.

## Design goals

- **Broad defaults:** Check all shipped applicable families except the broad paging family.
- **Volatility-aware order:** Acquire RAM first when requested, then fast live state and hot disk artifacts before slower work.
- **Explicit results:** Keep absent, excluded, partial and failed acquisition visible.
- **Standalone collector:** Windows packages use system DLLs and a statically linked C runtime. RAM capture requires an external DumpIt toolkit.
- **Bounded transfers:** Stream copying, hashing and SFTP payload compression; planning and inventories still scale with item count.
- **Useful handoff:** Keep original paths, host markers, manifests and database companions for analysis tools.

Read [capabilities and limits](capabilities.md), then choose a
[first collection](../getting-started/first-collection.md).
