#!/usr/bin/env python3
# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
"""Exercise the real SDK over HTTP, including a lost ACK after a part was stored."""
import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import re
import socket
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
from xml.etree import ElementTree as ET

MIB = 1024 * 1024


def checksum(data):
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


class Bucket(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def respond(self, status, body=b"", headers=None):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def error(self, status, code):
        self.respond(status, f"<Error><Code>{code}</Code></Error>".encode())

    def lose_ack(self):
        self.close_connection = True
        self.connection.shutdown(socket.SHUT_RDWR)

    def handle_request(self):
        path = urlsplit(self.path)
        key = unquote(path.path).removeprefix("/evidence-test/")
        params = parse_qs(path.query, keep_blank_values=True)
        data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        store = self.server
        auth = self.headers.get("Authorization", "")
        writer = "Credential=TEST-UPLOAD-" in auth
        if writer:
            host = auth.split("Credential=TEST-UPLOAD-", 1)[1].split("/", 1)[0]
            if not key.startswith(f"case/{host}_"):
                return self.error(403, "AccessDenied")
        if not path.path.startswith("/evidence-test/") or not (
            (writer and self.headers.get("X-Amz-Security-Token") == "test-token" and self.command != "GET")
            or ("Credential=TEST-ANALYST/" in auth and self.command == "GET")
        ):
            return self.error(403, "AccessDenied")
        with store.lock:
            if self.command == "GET":
                if store.restore_race and key == store.restore_race[0]:
                    destination = store.restore_race[1]
                    destination.mkdir()
                    (destination / "existing.txt").write_bytes(b"keep me")
                    store.restore_race = None
                if key not in store.objects:
                    return self.error(404, "NoSuchKey")
                return self.respond(200, store.objects[key])
            if "uploads" in params and self.command == "POST":
                store.pending[key] = {}
                return self.respond(200, b"<InitiateMultipartUploadResult><UploadId>unit-upload</UploadId></InitiateMultipartUploadResult>")
            if "uploadId" in params and self.command == "DELETE":
                store.pending.pop(key, None)
                return self.respond(204)
            if self.command == "PUT" and "partNumber" in params:
                sequence = int(params["partNumber"][0])
                if self.headers.get("x-amz-checksum-sha256") != checksum(data):
                    return self.error(400, "BadDigest")
                if store.deny and sequence == 2:
                    return self.error(403, "AccessDenied")
                prior = store.pending[key].get(sequence)
                if prior is not None:
                    assert prior == data, "Retried a part with different bytes"
                store.pending[key][sequence] = data
                store.attempts.setdefault(key, []).append(sequence)
                if sequence == 2 and not store.dropped:
                    store.dropped = True
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                headers = {"ETag": f'"part{sequence}"', "x-amz-checksum-sha256": checksum(data)}
                if store.fault and store.fault[0] == "part":
                    store.fault_key = key
                    if store.fault[1] == "wrong-checksum":
                        headers["x-amz-checksum-sha256"] = checksum(b"wrong")
                    elif store.fault[1] == "missing-etag":
                        del headers["ETag"]
                return self.respond(200, headers=headers)
            if self.headers.get("If-None-Match") != "*":
                return self.error(403, "AccessDenied")
            if self.command == "POST" and "uploadId" in params:
                stage = "complete"
            elif key.endswith("/started.json"):
                stage = "start"
            elif "/checkpoints/" in key:
                stage = "checkpoint"
            elif "-payload-" in key:
                stage = "payload"
            elif "-meta-" in key:
                stage = "metadata"
            elif key.endswith("-journal.jsonl"):
                stage = "journal"
            elif key.endswith("-delivery.json"):
                stage = "delivery"
            else:
                return self.error(400, "InvalidRequest")

            fault = None
            if store.fault and stage == store.fault[0] and store.fault_key in (None, key):
                store.fault_key = key
                store.fault_attempts += 1
                fault = store.fault[1]
                if store.fault_attempts == 1:
                    if fault == "collision-after-retry":
                        store.objects[key] = b"a different writer's object"
                        return self.error(503, "SlowDown")
                    if fault == "aborted":
                        store.pending.pop(key)
                        return self.error(503, "SlowDown")
                    if fault == "retry-before-store":
                        return self.error(503, "SlowDown")
                    if fault == "embedded-error":
                        return self.error(200, "InvalidPart")
                if fault in ("aborted", "lost-ack-404") and key not in store.pending:
                    return self.error(404, "NoSuchUpload")
            if key in store.objects or (store.collide and stage == "start"):
                return self.error(412, "PreconditionFailed")
            if self.command == "PUT":
                if self.headers.get("x-amz-checksum-sha256") != checksum(data):
                    return self.error(400, "BadDigest")
                store.objects[key] = data
                if fault == "lost-ack":
                    return self.lose_ack()
                headers = {"ETag": '"stored"', "x-amz-checksum-sha256": checksum(data)}
                if fault == "missing-etag":
                    del headers["ETag"]
                elif fault == "wrong-checksum":
                    headers["x-amz-checksum-sha256"] = checksum(b"wrong")
                return self.respond(200, headers=headers)
            if stage == "complete":
                parts = store.pending.pop(key)
                digests = []
                for entry in ET.fromstring(data).findall("{*}Part"):
                    number = int(entry.findtext("{*}PartNumber"))
                    assert entry.findtext("{*}ChecksumSHA256") == checksum(parts[number])
                    digests.append(hashlib.sha256(parts[number]).digest())
                store.objects[key] = b"".join(parts[i] for i in sorted(parts))
                if fault in ("lost-ack", "lost-ack-404"):
                    return self.lose_ack()
                xml = ET.Element("CompleteMultipartUploadResult")
                if fault != "missing-etag":
                    ET.SubElement(xml, "ETag").text = '"multipart"'
                ET.SubElement(xml, "ChecksumSHA256").text = (
                    checksum(b"wrong" if fault == "wrong-checksum" else b"".join(digests))
                    + f"-{len(parts)}"
                )
                return self.respond(200, ET.tostring(xml))
        self.error(400, "InvalidRequest")

    do_GET = do_PUT = do_DELETE = do_POST = handle_request


def main(binary):
    with ThreadingHTTPServer(("127.0.0.1", 0), Bucket) as server, tempfile.TemporaryDirectory() as directory:
        server.lock = threading.Lock()
        server.objects, server.pending, server.attempts = {}, {}, {}
        server.dropped = server.deny = server.collide = False
        server.fault = server.restore_race = None
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        endpoint = f"http://127.0.0.1:{server.server_port}"
        root = Path(directory)
        env = dict(os.environ, AWS_SECRET_ACCESS_KEY="test-example-secret",
                   AWS_SESSION_TOKEN="test-token", AWS_REGION="us-east-1", NO_COLOR="1")
        def run(args, expected_code=0, host=None):
            result = subprocess.run([str(binary), *map(str, args), "--s3-endpoint", endpoint],
                                    env=dict(env, AWS_ACCESS_KEY_ID="TEST-ANALYST" if host is None else "TEST-UPLOAD-" + host),
                                    capture_output=True, encoding="utf-8", timeout=90)
            assert result.returncode == expected_code, (result.returncode, result.stdout, result.stderr)
            return result

        def fields(result):
            return dict(line.split(": ", 1) for line in result.stdout.splitlines() if ": " in line)

        def collect(host, data, expected_code=0):
            source = root / host / "C"
            path = source / "Windows/Prefetch/A.pf"
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
            (path.parent / "Empty.pf").touch()
            stage = root / host / "stage"
            stage.mkdir()
            result = run(["collect", "--s3-direct", "--s3", "s3://evidence-test/case/", "--source", source,
                          "--computer", host, "--artifact", "windows.prefetch", "--yes",
                          "--s3-staging-dir", stage, "--s3-part-mib", "5", "--reserve-mib", "0"], expected_code, host=host)
            if expected_code == 0:
                assert not list(stage.iterdir())
            return result

        data = os.urandom(11 * MIB)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                a = executor.submit(collect, "HOST01", data)
                b = executor.submit(collect, "HOST02", b"second host")
                first, second = fields(a.result()), fields(b.result())
            assert server.dropped and list(server.attempts.values()) == [[1, 2, 2, 3]], server.attempts
            assert first["Remote delivery"] != second["Remote delivery"] and not server.pending
            for host, result, content in [("HOST01", first, data), ("HOST02", second, b"second host")]:
                uri, digest = result["Remote delivery"], result["Delivery SHA256"]
                key = uri.removeprefix("s3://evidence-test/")
                doc = json.loads(server.objects[key])
                prefix = key.rsplit("/", 1)[0]
                assert prefix.startswith(f"case/{host}_") and doc["Kind"] == "KumadeS3Delivery"
                checkpoints = [k for k in server.objects if k.startswith(prefix + "/checkpoints/")]
                assert len(checkpoints) == 2
                assert hashlib.sha256(server.objects[key]).hexdigest() == digest
                restored, receipt = root / (host + "-restored"), root / (host + "-receipt")
                verify = ["verify-s3", "--s3", uri, "--sha256", digest]
                run([*verify, "--receipt", receipt, "--restore", restored])
                assert (restored / "C/Windows/Prefetch/A.pf").read_bytes() == content
                assert (restored / "C/Windows/Prefetch/Empty.pf").read_bytes() == b""
                assert json.loads(receipt.read_text())["PayloadRecordsVerified"] == 2
                payload = next(o for o in doc["Objects"] if o["RelativePath"].endswith("/A.pf"))
                key = prefix + "/" + payload["Name"]
                # Modify gzip MTIME. Decoded evidence remains identical, but its stored hash changes.
                modified = bytearray(server.objects[key])
                modified[4] ^= 1
                server.objects[key] = bytes(modified)
                bad = root / (host + "-bad-receipt")
                rejected = root / (host + "-unverified")
                run([*verify, "--receipt", bad, "--restore", rejected], expected_code=2)
                assert not bad.exists() and not rejected.exists()
                assert not list(root.glob(".kumade-unverified-*"))
            # The same lost response can hide either a correct write or missing/wrong
            # evidence. An upload-only collector must never infer success from a retry.
            cases = [
                ("start", "lost-ack"), ("payload", "lost-ack"),
                ("checkpoint", "lost-ack"), ("metadata", "lost-ack"),
                ("journal", "lost-ack"), ("delivery", "lost-ack"),
                ("payload", "collision-after-retry"), ("delivery", "collision-after-retry"),
                ("complete", "lost-ack"), ("complete", "lost-ack-404"),
                ("complete", "aborted"), ("complete", "embedded-error"),
                ("complete", "wrong-checksum"), ("complete", "missing-etag"),
                ("part", "wrong-checksum"), ("part", "missing-etag"),
                ("delivery", "wrong-checksum"), ("delivery", "missing-etag"),
            ]
            for index, (stage, fault) in enumerate(cases):
                host = f"FAULT{index:02}"
                server.fault, server.fault_key, server.fault_attempts = (stage, fault), None, 0
                content = data if stage in ("complete", "part") else b"small evidence"
                result = collect(host, content, expected_code=2)
                info = fields(result)
                assert server.fault_key and not server.pending, (stage, fault)
                if fault.startswith("lost-ack") or fault in ("collision-after-retry", "aborted"):
                    assert server.fault_attempts >= 2, (stage, fault)
                assert "S3 delivery unconfirmed" in result.stderr, result.stderr
                assert "Remote delivery" not in info and "Delivery SHA256" not in info
                if stage == "start":
                    assert not list((root / host / "stage").iterdir())
                    continue
                assert list((root / host / "stage").rglob("Manifest.jsonl")), result.stderr
                uri = info["S3 delivery URI"]
                key = uri.removeprefix("s3://evidence-test/")
                if stage != "delivery":
                    assert key not in server.objects, (stage, fault)
                    if fault == "aborted":
                        assert server.fault_key not in server.objects
                    continue
                match = re.search(r"expected SHA-256 ([0-9a-f]{64})", result.stderr)
                assert match, result.stderr
                receipt = root / (host + "-receipt")
                verify = ["verify-s3", "--s3", uri, "--sha256", match[1], "--receipt", receipt]
                if fault == "collision-after-retry":
                    run(verify, expected_code=2)
                    assert not receipt.exists()
                else:
                    restored = root / (host + "-restored")
                    run([*verify, "--restore", restored])
                    assert (restored / "C/Windows/Prefetch/A.pf").read_bytes() == content

            # A transient error followed by an actual success acknowledgement is safe.
            server.fault, server.fault_key, server.fault_attempts = ("delivery", "retry-before-store"), None, 0
            retried = fields(collect("RETRIED", b"retry"))
            assert server.fault_attempts == 2
            run(["verify-s3", "--s3", retried["Remote delivery"], "--sha256", retried["Delivery SHA256"],
                 "--receipt", root / "retried-receipt"])
            server.fault = None

            # Another process claims the requested restore destination during verification.
            dest, receipt = root / "concurrent-restore", root / "concurrent-receipt"
            key = retried["Remote delivery"].removeprefix("s3://evidence-test/")
            first_object = json.loads(server.objects[key])["Objects"][0]["Name"]
            server.restore_race = (key.rsplit("/", 1)[0] + "/" + first_object, dest)
            run(["verify-s3", "--s3", retried["Remote delivery"], "--sha256", retried["Delivery SHA256"],
                 "--receipt", receipt, "--restore", dest], expected_code=2)
            assert server.restore_race is None and not receipt.exists()
            assert [p.name for p in dest.iterdir()] == ["existing.txt"]
            assert (dest / "existing.txt").read_bytes() == b"keep me"
            assert not list(root.glob(".kumade-unverified-*"))
            server.deny = True
            collect("DENIED", data, expected_code=2)
            assert not server.pending
            assert not any("/DENIED_" in k and k.endswith("-delivery.json") for k in server.objects)
            assert list((root / "DENIED/stage").iterdir()), "Failed upload discarded local metadata"
            server.collide = True
            collect("COLLISION", b"x", expected_code=2)
            assert not any("/COLLISION_" in k for k in server.objects)
        finally:
            server.shutdown()
            thread.join()
    print("PASS: concurrent sources, safe part replay, fail-closed S3 writes, retained staging, independent readback/restore")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    main(parser.parse_args().binary.resolve(strict=True))
