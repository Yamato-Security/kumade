#!/usr/bin/env python3
# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
"""Download a verified Forge ZIP without extracting it; emit reproducible build inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.request
import zipfile

LIMIT = 64 * 1024 * 1024


def get(url, limit):
    request = urllib.request.Request(url, headers={'User-Agent': 'Kumade'})
    with urllib.request.urlopen(request, timeout=120) as response:
        if not response.url.startswith('https://'):
            raise ValueError('HTTPS required')
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Download exceeds size limit')
    return data


def prepare(ruleset, release, directory):
    if release != 'latest' and not re.fullmatch(r'\d{8}', release, flags=re.ASCII):
        raise ValueError('Release must be latest or an eight-digit Forge tag')
    suffix = 'latest' if release == 'latest' else f'tags/{release}'
    metadata = json.loads(get(f'https://api.github.com/repos/YARAHQ/yara-forge/releases/{suffix}', 1024 * 1024))
    tag = metadata['tag_name']
    if not re.fullmatch(r'\d{8}', tag, flags=re.ASCII) or (release != 'latest' and tag != release):
        raise ValueError('Unexpected release tag')
    name = f'yara-forge-rules-{ruleset}.zip'
    assets = [asset for asset in metadata['assets'] if asset['name'] == name]
    if len(assets) != 1 or assets[0]['size'] > LIMIT:
        raise ValueError('Missing, ambiguous or oversized Forge asset')
    url = f'https://github.com/YARAHQ/yara-forge/releases/download/{tag}/{name}'
    data = get(url, LIMIT)
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != assets[0]['size'] or assets[0].get('digest') != f'sha256:{digest}':
        raise ValueError('Forge asset size/hash mismatch')
    import io
    member = f'packages/{ruleset}/yara-rules-{ruleset}.yar'
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if len(archive.infolist()) > 1024 or archive.namelist().count(member) != 1:
            raise ValueError('Invalid Forge archive layout')
        if archive.getinfo(member).file_size > 128 * 1024 * 1024:
            raise ValueError('Oversized rule source')
        source = archive.read(member)
        source.decode('utf-8')
        licenses = sorted({match.decode() for match in re.findall(rb'license\s*=\s*"([^"\r\n]+)"', source)})
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / f'yara-forge-rules-{ruleset}-{tag}.zip'
    if output.exists():
        if output.read_bytes() != data:
            raise FileExistsError('Existing bundle has different contents')
    else:
        with output.open('xb') as target:
            target.write(data)
    record = {'RuleSet': ruleset, 'Release': tag, 'ArchiveSHA256': digest,
              'SourceURL': url, 'ZIP': str(output.resolve()), 'LicensesInRuleMetadata': licenses}
    manifest = directory / f'{ruleset}-Bundle.json'
    manifest.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ruleset', choices=['core', 'extended', 'full'], required=True)
    parser.add_argument('--release', default='latest')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--github-env', type=Path)
    args = parser.parse_args()
    record = prepare(args.ruleset, args.release, args.output)
    if args.github_env:
        values = {'KUMADE_YARA_FORGE_ZIP': record['ZIP'], 'KUMADE_YARA_FORGE_RELEASE': record['Release'],
                  'KUMADE_YARA_FORGE_SHA256': record['ArchiveSHA256']}
        # Protect GitHub's line-oriented environment file from path injection.
        if any('\n' in value or '\r' in value for value in values.values()):
            raise ValueError('Invalid environment value')
        with args.github_env.open('a', encoding='utf-8') as target:
            for key, value in values.items():
                target.write(f'{key}={value}\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
