#!/usr/bin/env python3
# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
"""Build all three offline Forge variants, keeping downloaded archives compressed."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
from prepare_yara_bundle import prepare


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--platform', required=True)
    parser.add_argument('--release', required=True)
    parser.add_argument('--work-directory', type=Path, required=True)
    parser.add_argument('--native-tests', action='store_true')
    args = parser.parse_args()
    for ruleset in ['core', 'extended', 'full']:
        bundle = prepare(ruleset, args.release, args.work_directory)
        env = os.environ.copy()
        env.update(KUMADE_YARA_FORGE_ZIP=bundle['ZIP'], KUMADE_YARA_FORGE_RELEASE=bundle['Release'],
                   KUMADE_YARA_FORGE_SHA256=bundle['ArchiveSHA256'])
        feature = f'bundled-yara-{ruleset}'
        if args.native_tests:
            subprocess.run(['cargo', 'test', '--locked', '--target', args.target, '--features', feature,
                            '--lib', 'yara', '--', '--nocapture'], env=env, check=True)
        subprocess.run(['cargo', 'build', '--locked', '--release', '--target', args.target,
                        '--features', feature], env=env, check=True)
        subprocess.run([sys.executable, str(Path(__file__).with_name('package_release.py')),
                        '--target', args.target, '--platform', args.platform, '--ruleset', ruleset,
                        '--bundle-manifest', str(args.work_directory / f'{ruleset}-Bundle.json')], env=env, check=True)


if __name__ == '__main__':
    main()
