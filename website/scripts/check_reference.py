"""Check command/catalogue coverage and readable documentation source."""
import json
from pathlib import Path
import re
import tomllib

import yaml

ROOT = Path(__file__).resolve().parents[2]


def main():
    source = (ROOT/'src/main.rs').read_text()
    block = source.split('enum Command {',1)[1].split('\n}\n',1)[0]
    variants = re.findall(r'^    ([A-Z][A-Za-z0-9]*)\s*(?:[({,])', block, re.M)
    names = sorted(re.sub(r'(?<=[a-z])(?=[A-Z])','-',v).lower()for v in variants)
    reference = json.loads((ROOT/'website/command-reference.json').read_text())
    assert names == sorted(reference['Commands']), 'Refresh command pages after changing the command enum'
    version = tomllib.loads((ROOT/'Cargo.toml').read_text())['package']['version']
    assert reference['Version'] == 'kumade '+version, 'Refresh command help after changing the version'
    for name in names:
        assert (ROOT/f'docs/commands/{name}.md').is_file(),name
        help_path = ROOT/f'docs/commands/help/{name}.txt'
        assert 'Usage: kumade '+name in help_path.read_text(), name
    catalogue = yaml.safe_load((ROOT/'artifacts/default.yaml').read_text())['Artifacts']
    assert len({a['Id']for a in catalogue}) == len(catalogue)
    datasets = json.loads((ROOT/'src/live_info/datasets.json').read_text())
    assert len({d['Name']for d in datasets}) == len(datasets)
    for path in (ROOT/'docs').rglob('*.md'):
        value = path.read_text()
        assert not any(ord(c)<32 and c not in '\n\r\t'for c in value),path
    print(f'Checked {len(names)} commands, {len(catalogue)} artifact families and {len(datasets)} live datasets.')


if __name__ == '__main__':
    main()
