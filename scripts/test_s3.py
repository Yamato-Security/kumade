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
                return self.respond(200, headers={"ETag": f'"part{sequence}"', "x-amz-checksum-sha256": checksum(data)})
            if self.headers.get("If-None-Match") != "*":
                return self.error(403, "AccessDenied")
            if key in store.objects or (store.collide and key.endswith("started.json")):
                return self.error(412, "PreconditionFailed")
            if self.command == "PUT":
                if self.headers.get("x-amz-checksum-sha256") != checksum(data):
                    return self.error(400, "BadDigest")
                store.objects[key] = data
                return self.respond(200, headers={"ETag": '"stored"'})
            if self.command == "POST" and "uploadId" in params:
                parts = store.pending.pop(key)
                for entry in ET.fromstring(data).findall("{*}Part"):
                    number = int(entry.findtext("{*}PartNumber"))
                    assert entry.findtext("{*}ChecksumSHA256") == checksum(parts[number])
                store.objects[key] = b"".join(parts[i] for i in sorted(parts))
                return self.respond(200, b'<CompleteMultipartUploadResult><ETag>"multipart"</ETag></CompleteMultipartUploadResult>')
        self.error(400, "InvalidRequest")

    do_GET = do_PUT = do_DELETE = do_POST = handle_request


def main(binary):
    with ThreadingHTTPServer(("127.0.0.1", 0), Bucket) as server, tempfile.TemporaryDirectory() as directory:
        server.lock = threading.Lock()
        server.objects, server.pending, server.attempts = {}, {}, {}
        server.dropped = server.deny = server.collide = False
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        endpoint = f"http://127.0.0.1:{server.server_port}"
        root = Path(directory)
        env = dict(os.environ, AWS_SECRET_ACCESS_KEY="test-example-secret",
                   AWS_SESSION_TOKEN="test-token", AWS_REGION="us-east-1", NO_COLOR="1")
        def run(args, success=True, host=None):
            result = subprocess.run([str(binary), *map(str, args), "--s3-endpoint", endpoint],
                                    env=dict(env, AWS_ACCESS_KEY_ID="TEST-ANALYST" if host is None else "TEST-UPLOAD-" + host),
                                    capture_output=True, encoding="utf-8", timeout=90)
            assert (result.returncode == 0) == success, (result.stdout, result.stderr)
            return dict(line.split(": ", 1) for line in result.stdout.splitlines() if ": " in line)

        def collect(host, data, success=True):
            source = root / host / "C"
            path = source / "Windows/Prefetch/A.pf"
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
            (path.parent / "Empty.pf").touch()
            stage = root / host / "stage"
            stage.mkdir()
            result = run(["collect", "--s3", "s3://evidence-test/case/", "--source", source,
                          "--computer", host, "--artifact", "windows.prefetch", "--yes",
                          "--s3-staging-dir", stage, "--s3-part-mib", "5", "--reserve-mib", "0"], success, host=host)
            if success:
                assert not list(stage.iterdir())
            return result

        data = os.urandom(11 * MIB)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                a = executor.submit(collect, "HOST01", data)
                b = executor.submit(collect, "HOST02", b"second host")
                first, second = a.result(), b.result()
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
                run([*verify, "--receipt", bad], success=False)
                assert not bad.exists()
            server.deny = True
            collect("DENIED", data, success=False)
            assert not server.pending
            assert not any("/DENIED_" in k and k.endswith("-delivery.json") for k in server.objects)
            assert list((root / "DENIED/stage").iterdir()), "Failed upload discarded local metadata"
            server.collide = True
            collect("COLLISION", b"x", success=False)
            assert not any("/COLLISION_" in k for k in server.objects)
        finally:
            server.shutdown()
            thread.join()
    print("PASS: two sources, part retry after lost ACK, create-only writes, readback/restore, tampering and denied writes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    main(parser.parse_args().binary.resolve(strict=True))
