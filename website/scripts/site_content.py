"""Build reference pages from versioned definitions, without duplicating sources."""
from collections import defaultdict
import html
import json
from pathlib import Path
import re

from mkdocs.structure.files import File
import yaml

ROOT = Path(__file__).resolve().parents[2]


def code(value):
    return '<code>' + html.escape(str(value)).replace('|', '&#124;') + '</code>'


def catalogue():
    data = yaml.safe_load((ROOT / 'artifacts/default.yaml').read_text())
    groups = defaultdict(list)
    for item in data['Artifacts']:
        groups[item['Category']].append(item)
    lines = ['# Artifact catalogue', '',
             f"Kumade currently ships **{len(data['Artifacts'])} acquisition families**. This reference is generated from "
             '[the embedded catalogue](https://github.com/Yamato-Security/kumade/blob/main/artifacts/default.yaml) on every documentation build.', '',
             'A family is a set of collection paths, not a parser or a promise that every host contains those files. '
             'All shipped families are selected by default except `windows.paging` and `windows.hibernation`. RAM capture, live inventory, entropy discovery and YARA are separate features.', '',
             '## How to read the paths', '',
             '- **Volume** paths are relative to each selected volume root, for example `Windows/Prefetch/**`.',
             '- **Profile** paths are relative to each discovered profile, including applicable service profiles. They are not restricted to the logged-on user.',
             '- **Raw NTFS** paths identify metafiles or named streams for the locked-file/raw reader. `:$J` identifies a named data stream.',
             '- Matching is case-insensitive. `**` covers descendant paths. Standard catalogue locations can miss custom application stores, inaccessible directories or remote/cloud-only data.',
             '- Database families include companion logs where the directory patterns match them. Retain those files together for recovery-aware parsers.', '',
             '```powershell', '.\\kumade.exe list-artifacts --builtin', '.\\kumade.exe collect --no-wizard --artifact windows.prefetch --artifact windows.srum -o E:\\Evidence', '```', '',
             'An explicit `--artifact` narrows disk scope. Live inventory still runs on a live host unless `--no-live-info` is supplied. '
             '`Coverage.csv`, `DiscoveryIssues.csv` and `Errors.csv` explain missing, skipped, partial and failed collection. '
             'See [collection guidance](index.md) and [verification](../output/verification.md).', '']
    for group, items in sorted(groups.items()):
        title = re.sub(r'(?<=[a-z])(?=[A-Z])', ' ', group)
        lines += ['## ' + title, '']
        for item in sorted(items, key=lambda i: i['Id']):
            lines += ['### ' + item['Id'], '', item['Name'] + '.', '', '| Source | Matching paths |', '|---|---|']
            for key, label in [('Patterns','Volume'), ('ProfilePatterns','Profile'), ('RawPaths','Raw NTFS')]:
                if item.get(key):
                    lines.append('| '+label+' | '+'<br>'.join(code(p)for p in item[key])+' |')
            if item['Id'] == 'windows.paging':
                lines += ['', 'Off by default. Add `--paging` or select `--artifact windows.paging`. '
                          'This is distinct from the active pagefiles paired with a new `--memory` capture.']
            if item['Id'] == 'windows.hibernation':
                lines += ['', 'Off by default. Add `--hibernation` or select `--artifact windows.hibernation`. '
                          'The broad paging family also includes this file; overlapping selections are deduplicated. '
                          'See [hibernation acquisition](../hibernation-acquisition.md) for VSS and saved-memory limitations.']
            lines += ['']
    return '\n'.join(lines)


def live_datasets():
    items = json.loads((ROOT / 'src/live_info/datasets.json').read_text())
    lines = ['# Live-inventory fields', '',
             f'The **{len(items)} datasets** and fields below are generated from '
             '[the shipped definitions](https://github.com/Yamato-Security/kumade/blob/main/src/live_info/datasets.json). '
             'See [live-system inventory](../live-info.md) for collection semantics, formats and failure reporting.', '',
             'Each dataset uses a matching filename, for example `Processes.csv` or `DnsCache.jsonl`. '
             'These are observations at collection time, not historical event records. A missing row is not proof that a process, connection or setting never existed.', '',
             '```powershell', '.\\kumade.exe live-info --list', '.\\kumade.exe live-info --dataset Processes --dataset TcpConnections -t jsonl -o E:\\Live-Inventory', '```', '']
    for item in sorted(items, key=lambda i: i['Name']):
        lines += ['## '+item['Name'], '', '**Fields:** '+', '.join('`'+v+'`'for v in item['Fields'])+'.', '',
                  '[Provider reference]('+item['Reference']+').', '']
    return '\n'.join(lines)


def on_files(files, config):
    pages = {'collection/catalogue.md': catalogue(),
             'collection/live-datasets.md': live_datasets(),
             'overview/changelog.md': (ROOT/'CHANGELOG.md').read_text().replace('](docs/', '](../')}
    for uri, content in pages.items():
        files.append(File.generated(config, uri, content=content))
    files.append(File.generated(config, 'assets/kumade-golden-waves.png', abs_src_path=str(ROOT/'art/KumadeGoldenWaves.png')))
    return files
