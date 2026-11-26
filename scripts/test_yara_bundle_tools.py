#!/usr/bin/env python3
# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
"""Offline release-tool regressions; no real download or compiler required."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import prepare_yara_bundle as bundle
import package_release


class Bundles(unittest.TestCase):
    def fixture(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('packages/core/yara-rules-core.yar', 'rule inert { meta: license="MIT" condition: true }')
            archive.writestr('../../not-extracted', 'ignored')
        return stream.getvalue()

    def metadata(self, data):
        return json.dumps({'tag_name': '20261122', 'assets': [{'name': 'yara-forge-rules-core.zip',
                            'size': len(data), 'digest': 'sha256:' + hashlib.sha256(data).hexdigest()}]}).encode()

    def test_verified_zip_stays_compressed_and_existing_different_zip_is_refused(self):
        data = self.fixture()
        with tempfile.TemporaryDirectory() as tmp, patch.object(bundle, 'get', side_effect=[self.metadata(data), data]):
            record = bundle.prepare('core', 'latest', Path(tmp))
            output = Path(record['ZIP'])
            self.assertEqual(output.read_bytes(), data)
            self.assertEqual(sorted(p.suffix for p in Path(tmp).iterdir()), ['.json', '.zip'])
            output.write_bytes(b'previous content')
            with patch.object(bundle, 'get', side_effect=[self.metadata(data), data]):
                with self.assertRaises(FileExistsError):
                    bundle.prepare('core', 'latest', Path(tmp))
            self.assertEqual(output.read_bytes(), b'previous content')

    def test_bad_digest_publishes_nothing(self):
        data = self.fixture()
        with tempfile.TemporaryDirectory() as tmp, patch.object(bundle, 'get', side_effect=[self.metadata(data), data + b'corrupt']):
            with self.assertRaises(ValueError):
                bundle.prepare('core', 'latest', Path(tmp))
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_packaged_binary_zip_contains_only_executable_and_source_zip_keeps_attribution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = self.fixture()
            with patch.object(bundle, 'get', side_effect=[self.metadata(data), data]):
                record = bundle.prepare('core', 'latest', root / 'rules')
            target = root / 'target'
            binary = target / 'aarch64-pc-windows-msvc/release/kumade.exe'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'fixture-executable-prefix' + data)
            metadata = json.dumps({'packages': [{'name': 'kumade', 'version': '0.1.0'}], 'target_directory': str(target)})
            output = root / 'dist'
            args = ['package_release.py', '--target', 'aarch64-pc-windows-msvc', '--platform', 'win-aarch64', '--ruleset', 'core',
                    '--bundle-manifest', str(root / 'rules/core-Bundle.json'), '--output', str(output)]
            with patch.object(sys, 'argv', args), patch.object(package_release.subprocess, 'check_output', return_value=metadata), contextlib.redirect_stdout(io.StringIO()):
                package_release.main()
            path = output / 'kumade-0.1.0-win-aarch64-yara-core.zip'
            with zipfile.ZipFile(path) as archive:
                self.assertEqual(archive.namelist(), ['kumade-0.1.0-win-aarch64-yara-core.exe'])
                self.assertEqual(archive.read(archive.namelist()[0]), binary.read_bytes())
            self.assertEqual((output / 'YARA-FORGE-core-20261122.zip').read_bytes(), data)
            notice = json.loads((output / 'YARA-FORGE-core-NOTICES.json').read_text())
            self.assertNotIn('ZIP', notice)
            self.assertEqual(notice['ArchiveSHA256'], record['ArchiveSHA256'])


if __name__ == '__main__':
    unittest.main()
