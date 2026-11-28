# Collection guide

## What default collection includes

Kumade uses its embedded [artifact catalogue](catalogue.md) to discover supported
files across selected local fixed volumes and profiles. Live-system inventory
is included on a live host. Disk collection includes `hiberfil.sys`, an existing
`Windows/MEMORY.DMP`, and files under `Windows/Minidump` by default.
`--paging` adds disk paging and swap files. New RAM capture requires `--memory`,
which also reads active pagefiles and the Windows swapfile during the RAM phase.

The default scope does not mean every file on the computer. A catalogue match
is a collection candidate, not a conclusion about malicious activity.

## Plan a narrower collection

```powershell
.\kumade.exe collect-test --volume C: --artifact windows.prefetch -o E:\Plans\Prefetch
.\kumade.exe collect --no-wizard --volume C: --artifact windows.prefetch -o E:\Evidence
```

`collect-test` writes a fresh plan without copying payloads or creating VSS snapshots.
Files can change before a later collection. An explicit disk scope does not
implicitly turn off live inventory.

## Keep evidence families together

Registry hives can need transaction logs; ESE and SQLite databases can need
companions for recovery. Catalogue patterns generally select their containing
stores to preserve those relationships. Keep collected companions rather than
choosing only the most recognizable filename.

## Decide how to handle live data

Read [acquisition order](../acquisition-order.md), [locked files](locked-files.md),
[VSS](../vss.md) and [RAM/pagefiles](../memory-acquisition.md). Review each
collection's source limitations; neither raw access nor a snapshot guarantees
complete or structurally valid evidence.

For investigation concepts and artifact interpretation, use the
[Juntei artifact guides](https://yamato-security.github.io/juntei/) alongside
Kumade's collection reports.
