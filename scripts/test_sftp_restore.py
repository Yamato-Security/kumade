#!/usr/bin/env python3
# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import sftp_restore


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.incoming = self.root / "incoming"
        self.incoming.mkdir()
        self.case = "00000000-0000-4000-8000-000000000000"
        self.name = self.case + "-delivery.json"
        self.objects = []

    def object(self, path, logical=b"test", encoding="none"):
        stored = gzip.compress(logical) if encoding == "gzip" else logical
        name = self.case + f"-meta-{len(self.objects)}"
        (self.incoming / name).write_bytes(stored)
        obj = {
            "Name": name,
            "RelativePath": path,
            "Encoding": encoding,
            "LogicalBytes": len(logical),
            "StoredBytes": len(stored),
            "LogicalSha256": hashlib.sha256(logical).hexdigest(),
            "StoredSha256": hashlib.sha256(stored).hexdigest(),
        }
        self.objects.append(obj)
        return obj

    def delivery(self):
        value = {
            "SchemaVersion": 1,
            "Kind": "KumadeSftpDelivery",
            "DeliveryId": self.case,
            "CollectionName": "HOST_2026-11-23_00-00-00",
            "Objects": self.objects,
            "Summary": {"Completeness": "Partial"},
        }
        data = json.dumps(value).encode()
        (self.incoming / self.name).write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def restore(self, digest=None):
        return sftp_restore.restore(
            self.incoming,
            self.name,
            digest or self.delivery(),
            self.root / "restored",
            self.root / "receipt.json",
        )

    def assert_rejected(self):
        with self.assertRaises((ValueError, OSError, EOFError)):
            self.restore()
        self.assertFalse((self.root / "receipt.json").exists())

    def test_rejects_traversal_absolute_windows_paths_devices(self):
        for value in (
            "../bad",
            "/bad",
            "C:/bad",
            "a\\b",
            "a/./b",
            "a//b",
            "a/CON.txt",
            "a/CONIN$",
            "a/conin$.pf",
            "a/CONOUT$.txt",
            "a/Clock$.pf",
            "a/evil.",
            "a/evil ",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sftp_restore.relative(value)

    def test_encoded_device_names_remain_safe_and_distinct(self):
        paths = ("C/%43lock$.pf", "C/%2543lock$.pf", "C/%43ONIN$.pf", "C/%63onout$.pf")
        for path in paths:
            self.assertEqual(sftp_restore.relative(path), path.split("/"))

    def test_rejects_duplicate_casefold_and_prefix_collisions(self):
        for paths in (("C/A", "c/a"), ("C/A", "C/A/b"), ("C/A/b", "C/A")):
            self.objects = []
            for path in paths:
                self.object(path)
            self.assert_rejected()

    def test_rejects_tampered_delivery_digest(self):
        self.object("C/file")
        self.delivery()
        with self.assertRaisesRegex(ValueError, "Delivery SHA256"):
            self.restore("0" * 64)

    def test_rejects_tampered_stored_content(self):
        obj = self.object("C/file")
        digest = self.delivery()
        (self.incoming / obj["Name"]).write_bytes(b"evil")
        with self.assertRaisesRegex(ValueError, "Stored-object hash"):
            self.restore(digest)

    def test_rejects_wrong_decoded_hash_and_length(self):
        for key, value in (("LogicalBytes", 1), ("LogicalSha256", "0" * 64)):
            with self.subTest(key=key):
                self.objects = []
                obj = self.object("C/file", b"longer" * 10000, "gzip")
                obj[key] = value
                # Use a fresh path for each intentionally retained partial restore.
                previous = self.root / "restored"
                if previous.exists():
                    previous.rename(self.root / ("partial-" + key))
                self.assert_rejected()

    @unittest.skipUnless(hasattr(__import__("os"), "symlink"), "Requires symlinks")
    def test_rejects_symlink_and_hardlink_objects(self):
        import os

        obj = self.object("C/file")
        original = self.incoming / obj["Name"]
        external = self.root / "external"
        original.rename(external)
        try:
            original.symlink_to(external)
        except OSError:
            self.skipTest("Symlink privilege unavailable")
        self.assert_rejected()
        original.unlink()
        os.link(external, original)
        self.assert_rejected()

    def test_no_completion_marker_is_not_a_complete_delivery(self):
        with self.assertRaises(FileNotFoundError):
            self.restore("0" * 64)

    def test_keeps_partial_status_after_successful_readback(self):
        summary = json.dumps({"Completeness": "Partial"}).encode()
        manifest = b""
        self.object("Summary.json", summary)
        self.object("Manifest.jsonl", manifest)
        seal = json.dumps(
            {
                "MetadataSHA256": {
                    "Summary.json": hashlib.sha256(summary).hexdigest(),
                    "Manifest.jsonl": hashlib.sha256(manifest).hexdigest(),
                }
            }
        ).encode()
        self.object("Seal.json", seal)
        result = self.restore()
        self.assertTrue(result["PayloadHashesVerified"])
        self.assertEqual(result["AcquisitionState"], "Partial")


if __name__ == "__main__":
    unittest.main()
