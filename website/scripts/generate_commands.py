"""Refresh command reference and exact help snapshots from a matching binary."""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PAGES = {
    'collect': ('Collect forensic artifacts', r'''Use an elevated, native Windows build for live/raw evidence. With no source,
Kumade discovers fixed volumes; `-d` selects explicit offline roots.

```powershell
.\kumade.exe collect -o E:\Evidence
.\kumade.exe collect --yes --volume C: --vss --vhdx E:\Evidence
.\kumade.exe collect --yes --volume C: --hibernation -o E:\Evidence
```

`--yes` selects feature defaults plus explicit flags. It does not enable RAM,
paging, hibernation, VSS or scans automatically. Directory (`-o`), VHDX, E01, SFTP and S3 are
alternative outputs. Read [the wizard](../collection-wizard.md),
[collection guide](../collection/index.md), [RAM](../memory-acquisition.md),
[hibernation](../hibernation-acquisition.md)
and [output guide](../output/index.md).

Acquisition defaults to available logical CPUs capped at four. `-T` accepts
1–128 workers, bounded by work items. `--reserve-mib` defaults to 2048.
More workers need not improve a constrained disk or network path.
'''),
    'doctor': ('Inspect compiled capabilities', r'''Use this before a collection to see platform capabilities and provider limits.
It does not acquire evidence or guarantee that every protected source is readable.

```powershell
.\kumade.exe doctor
```

Use the native package for the host architecture. See
[capabilities](../overview/capabilities.md) and [installation](../getting-started/index.md).
'''),
    'forensic-copy': ('Image a logical partition', r'''This is separate from artifact collection. It writes a logical partition image
and a receipt, not the physical whole disk and not only catalogue files.
Use a destination on a different external physical disk.

```powershell
.\kumade.exe forensic-copy -s C: -o E:\Evidence
.\kumade.exe forensic-copy -s C: --vss -o E:\Evidence
```

The command enforces source/destination separation, reserve checks and readback
hashing. Review [partition imaging](../forensic-copy.md) before running it;
live bytes can change and VSS remains crash-consistent.
'''),
    'list': ('List acquisition families', r'''Inspect the embedded catalogue before narrowing a collection. This lists
acquisition definitions, not every matching file on the computer.

```powershell
.\kumade.exe list
.\kumade.exe list --catalog .\custom-catalogue.yaml
```

Use an explicit `--catalog` to select custom definitions. Kumade does not
silently load a catalogue found beside the executable. See the
[generated catalogue reference](../collection/catalogue.md).
'''),
    'list-vss': ('List existing shadow copies', r'''List local VSS snapshots without creating or deleting them.

```powershell
.\kumade.exe list-vss
.\kumade.exe list-vss --volume C: -o E:\Snapshots.csv
.\kumade.exe list-vss --volume C: -t jsonl
```

Requires elevated, native Windows. The table includes volume paths, snapshot
IDs and UTC creation times. CSV/JSON/JSONL output has PascalCase fields;
`-t` without `-o` writes structured stdout without a banner.
See [historical collection](../vss-existing.md).
'''),
    'live-info': ('Capture current host state', r'''Collect current process, network, account, service, security and regional
configuration observations without ordinary disk-artifact acquisition.

```powershell
.\kumade.exe live-info --list
.\kumade.exe live-info -o E:\Live-Inventory
.\kumade.exe live-info --dataset Processes --dataset TcpConnections -t jsonl -o E:\Live-Network
```

Use a new output directory. Standalone query concurrency defaults to two
workers; the collection integration also uses at most two. Provider failures
are explicit rather than empty success. See [live inventory](../live-info.md)
and its [generated field reference](../collection/live-datasets.md).
'''),
    'plan': ('Inspect scope and size estimates', r'''Write a fresh `Plan.json` from the selected paths without copying payloads.
The plan is a point-in-time discovery result, not a frozen promise about a
future collection. `plan` does not create VSS snapshots.

```powershell
.\kumade.exe plan --volume C: --artifact windows.prefetch -o E:\Plans\Prefetch
.\kumade.exe plan -d D:\Case\C --computer HOST01 -o E:\Plans\Offline
```

Logical estimates can overlap by family. Locked/raw-only sizes may be unknown
or require metadata reads; planning does not hash every payload to estimate it.
Read [size estimation](../collection-wizard.md#size-estimation).
'''),
    'receive': ('Receive upload-only SFTP evidence', r'''Start one listener for a single collector or add `--sources N` for multiple
computers. Each source gets a temporary upload-only credential, separate storage
and independent readback verification. The receiver prints one host-key
fingerprint shared by all sources.

```powershell
.\kumade.exe receive --listen 0.0.0.0:2222 --allow-ip 192.0.2.20 --output D:\Evidence --expires 2h
```

Replace the example source address with the collector's actual address.
The password is printed once: do not put it in shared logs. Pin the displayed
host key on the collector. The default listen address is loopback; an explicit
interface is required for remote collection.

The receiver can also be built from source on Linux. Follow the complete
[receiver guide](../SFTP-Receiver.md) for quotas, expiry, receipts and recovery.
Keep both the collector and receiver running for automatic reconnect after a network interruption.
'''),
    'scan-processes': ('Hunt in live process memory', r'''Run a native Windows build with suitable privileges. This is a live memory
scan, not disk-file scanning or an offline RAM-image parser.

```powershell
.\kumade.exe scan-processes -o E:\Yara-Core
.\kumade.exe scan-processes --ruleset full --rules-release 20261122 -o E:\Yara-Full
.\kumade.exe scan-processes --rules .\local.yar --pid 1234 -t jsonl -o E:\Yara-Selected
```

Matching bundled packs load offline; standard binaries download Core. Pin a release or provide local ZIP/source rules for
repeatability. Protected/inaccessible processes, read gaps, exits and timeouts
remain visible. A match is a lead; no match is not a clean bill of health.
See [process-memory scanning](../yara-process-scan.md) for evaluator semantics,
chunk boundaries and rule-selection limitations.

Integrated collection uses `--scan-processes --yara-ruleset full`, not the
standalone `--ruleset` spelling. Its result files are sealed with the collection.
'''),
    'update-rules': ('Download compressed YARA Forge rules', r'''Download one versioned Core, Extended or Full ZIP and validate its release-asset
SHA-256 and compilation before saving it. Existing different contents are refused.

```powershell
.\kumade.exe update-rules --ruleset core
.\kumade.exe update-rules --ruleset extended
.\kumade.exe update-rules --ruleset full
```

Use the ZIP path printed by the command with `scan-processes --rules <ZIP>` or
`collect --scan-processes --yara-rules <ZIP>`. Without `-o`, download beside the
executable, without creating a subdirectory. Updating does not rewrite the embedded executable.
See [compressed/offline rules](../yara-process-scan.md#compressedoffline-rule-inputs-and-updates).
'''),
    'verify': ('Check a retained local collection', r'''Read the saved collection, validate seals/accounting and compare retained
payload hashes without reading original source evidence.

```powershell
.\kumade.exe verify E:\Evidence\HOST01_2026-11-25_09-00-00
```

For containers, inspect a read-only mounted run directory using the
[container guide](../output/index.md). For remote delivery, use the trusted
receiver or `verify-delivery`, rather than treating local upload metadata as
verified evidence. A verified partial collection remains partial.
Read [verification semantics](../output/verification.md).
'''),
    'verify-delivery': ('Verify or restore an SFTP delivery', r'''Use the trusted receiver's files after the upload credential is revoked.
Obtain the final delivery object's name and SHA256 independently from the
collector. A new receipt is required; restoration is optional and needs extra space.

```powershell
.\kumade.exe verify-delivery --incoming D:\Evidence\SESSION\incoming `
  --delivery UUID-delivery.json --sha256 COLLECTOR_PRINTED_SHA256 `
  --receipt D:\Evidence\NewReceipt.json --uploader-revoked
```

Add `--restore D:\Evidence\RestoredCase` for a separate working copy. Replace
all example identifiers and paths. Do not reconstruct files over the originals.
The verifier checks stored/decoded hashes and metadata bindings; it does not
prove source authenticity or atomic acquisition.

See [SFTP receiver verification/restoration](../SFTP-Receiver.md#independent-readback-and-restoration)
and [remote output](../SFTP.md).
'''),
    'resume-s3': ('Resume a phased S3 delivery', r'''Supply the protected workspace printed by the collector and the original S3 destination. The uploader reuses acknowledged chunks and never rereads a live source. See [phased S3 recovery](../S3.md#recoverable-phased-collection).
'''),
    'verify-s3': ('Verify or restore an S3 delivery', r'''Use a separate read role to verify the full delivery or an individual phase using its URI and SHA-256 printed
by the collector. Choose a new local receipt path. Add `--restore DIR` to
reconstruct the collection. See [S3 setup and verification](../S3.md).
'''),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    env = dict(os.environ, NO_COLOR='1', COLUMNS='100')
    def run(*options):
        result = subprocess.run([str(binary), *options], check=True, capture_output=True, text=True, env=env)
        return '\n'.join(line.rstrip() for line in result.stdout.splitlines()).strip()+'\n'
    version = run('--version').strip()
    destination = ROOT/'docs/commands'
    help_dir = destination/'help'
    help_dir.mkdir(parents=True, exist_ok=True)
    (help_dir/'kumade.txt').write_text(run('--help'))
    for name, (title, explanation) in PAGES.items():
        help_text = run(name, '--help')
        (help_dir/(name+'.txt')).write_text(help_text)
        page = '# `'+name+'`\n\n'+title+'.\n\n'+explanation.strip()+'\n\n'
        page += '## Full command help\n\n'
        page += 'Snapshot from `'+version+'`. Check your binary\'s `--help` when using a different source/release revision.\n\n'
        page += '??? info "Show full help"\n\n    ```text\n'
        page += '\n'.join(('    '+line if line else '') for line in help_text.splitlines())+'\n    ```\n\n'
        page += '[Download plain-text help](help/'+name+'.txt).\n'
        (destination/(name+'.md')).write_text(page)
    index = ['# Commands', '',
             'Run `kumade.exe --help` for the root menu, or `kumade.exe COMMAND --help` for a command. '
             'With no arguments, Kumade displays help without starting a collection. '
             'Collection flags also work without writing the `collect` subcommand.', '',
             '| Command | Purpose |', '|---|---|']
    for name, (title, _) in PAGES.items():
        index.append('| [`'+name+'`]('+name+'.md) | '+title+' |')
    index += ['', '[Root help snapshot](help/kumade.txt). '
              'These pages describe current source behavior. A release sharing the same version label may predate recent flags.', '',
              'Start with [installation](../getting-started/index.md) or [your first collection](../getting-started/first-collection.md).', '']
    (destination/'index.md').write_text('\n'.join(index))
    (ROOT/'website/command-reference.json').write_text(json.dumps({'Version':version, 'Commands':list(PAGES)},indent=2)+'\n')
    print('Generated',len(PAGES),'command pages and help snapshots from',version)


if __name__ == '__main__':
    main()
