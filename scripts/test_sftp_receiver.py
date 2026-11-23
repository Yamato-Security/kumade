#!/usr/bin/env python3
# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
"""Portable real SSH/SFTP roundtrip using only Python's standard library.

The same test runs on the local Windows VM and CI. Generated credentials stay in
memory and are never printed into the test output.
"""

import argparse
import hashlib
import json
from pathlib import Path
import queue
import secrets
import shutil
import subprocess
import tempfile
import threading
import time


def receiver(binary, parent, expires="60s"):
    process = subprocess.Popen(
        [
            str(binary),
            "receive",
            "--listen",
            "127.0.0.1:0",
            "--output",
            str(parent),
            "--expires",
            expires,
            "--reserve-mib",
            "0",
            "--max-decoded-gib",
            "1",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    lines, events = [], queue.Queue()

    def read():
        for line in process.stdout:
            lines.append(line)
            events.put(line)
        events.put(None)

    threading.Thread(target=read, daemon=True).start()
    fields = {}
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        line = events.get(timeout=20)
        if line is None:
            raise AssertionError(
                "Receiver exited before publishing connection information"
            )
        for key in (
            "SFTP receiver",
            "Evidence directory",
            "Temporary username",
            "Temporary password",
            "SSH fingerprint",
        ):
            if line.startswith(key + ":"):
                fields[key] = line.split(":", 1)[1].strip()
        if len(fields) == 5:
            return process, fields, lines
    raise AssertionError("Receiver startup timed out")


def execute(binary):
    with tempfile.TemporaryDirectory(prefix="kumade-receiver-test-") as temp:
        root = Path(temp)
        source = root / "C"
        prefetch = source / "Windows/Prefetch"
        prefetch.mkdir(parents=True)
        contents = {
            "DATA.pf": secrets.token_bytes(1024 * 1024),
            "SPARSE.pf": bytes(8 * 1024 * 1024),
        }
        for name, data in contents.items():
            (prefetch / name).write_bytes(data)
        for compressed, partial in ((True, False), (False, False), (True, True)):
            mode = "partial" if partial else ("gzip" if compressed else "plain")
            expected_exit = 3 if partial else 0
            process, fields, lines = receiver(binary, root / mode)
            try:
                port = fields["SFTP receiver"].rsplit(":", 1)[1]
                staging = root / ("metadata-" + mode)
                staging.mkdir()
                arguments = [
                    str(binary),
                    "collect",
                    "-d",
                    str(source),
                    "--computer",
                    "TESTHOST",
                    "--artifact",
                    "windows.prefetch",
                    "--sftp",
                    "127.0.0.1",
                    "--sftp-port",
                    port,
                    "--sftp-user",
                    fields["Temporary username"],
                    "--sftp-host-key",
                    fields["SSH fingerprint"],
                    "--sftp-password-stdin",
                    "--sftp-staging-dir",
                    str(staging),
                    "--reserve-mib",
                    "0",
                    "--yes",
                    "-T",
                    "4",
                ]
                if partial:
                    arguments.append("--memory")
                if not compressed:
                    arguments.append("--sftp-no-compression")
                wrong = arguments.copy()
                wrong[wrong.index(fields["SSH fingerprint"])] = "SHA256:" + "A" * 43
                failed = subprocess.run(
                    wrong,
                    input=fields["Temporary password"] + "\n",
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                )
                assert failed.returncode == 2, "Wrong host pin accepted"
                failed = subprocess.run(
                    arguments,
                    input="wrong-password\n",
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                )
                assert failed.returncode == 2, "Wrong password accepted"
                result = subprocess.run(
                    arguments,
                    input=fields["Temporary password"] + "\n",
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=60,
                )
                if result.returncode != expected_exit:
                    raise AssertionError(
                        "Collection failed: "
                        + result.stderr.replace(
                            fields["Temporary password"], "[redacted]"
                        )
                    )
                assert fields["Temporary password"] not in result.stdout + result.stderr
                assert not list(staging.iterdir()), (
                    "Collector left local payload or metadata staging"
                )
                assert process.wait(timeout=60) == expected_exit, (
                    "Receiver failed its independent readback"
                )
                case = Path(fields["Evidence directory"])
                receipt = json.loads((case / "ReadbackReceipt.json").read_text())
                assert (
                    receipt["PayloadHashesVerified"]
                    and receipt["PayloadRecordsVerified"] == 2
                )
                assert receipt["AcquisitionState"] == (
                    "Partial" if partial else "CompleteWithinSelectedPrototypeScope"
                )
                assert receipt["DeliverySHA256"] in result.stdout, (
                    "Server/collector delivery digests differ"
                )
                assert (
                    fields["Temporary password"]
                    not in (case / "Receiver.json").read_text()
                )
                delivery = receipt["DeliveryId"] + "-delivery.json"
                restored = root / ("restored-" + mode)
                verified = subprocess.run(
                    [
                        str(binary),
                        "verify-delivery",
                        "--incoming",
                        str(case / "incoming"),
                        "--delivery",
                        delivery,
                        "--sha256",
                        receipt["DeliverySHA256"],
                        "--receipt",
                        str(case / "SecondReceipt.json"),
                        "--restore",
                        str(restored),
                        "--max-decoded-gib",
                        "1",
                        "--uploader-revoked",
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=60,
                )
                assert verified.returncode == expected_exit, verified.stderr
                for name, data in contents.items():
                    assert (
                        hashlib.sha256(
                            (restored / "C/Windows/Prefetch" / name).read_bytes()
                        ).digest()
                        == hashlib.sha256(data).digest()
                    )
                incoming = root / ("corrupt-" + mode)
                shutil.copytree(case / "incoming", incoming)
                payload = next(incoming.glob("*-payload-*"))
                with payload.open("r+b") as f:
                    f.write(b"damaged")
                rejected = subprocess.run(
                    [
                        str(binary),
                        "verify-delivery",
                        "--incoming",
                        str(incoming),
                        "--delivery",
                        delivery,
                        "--sha256",
                        receipt["DeliverySHA256"],
                        "--receipt",
                        str(root / "MustNotExist.json"),
                        "--uploader-revoked",
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                )
                assert (
                    rejected.returncode == 2
                    and not (root / "MustNotExist.json").exists()
                )
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)
        process, fields, lines = receiver(binary, root / "expired", "2s")
        try:
            assert process.wait(timeout=15) == 3
            case = Path(fields["Evidence directory"])
            assert not (case / "ReadbackReceipt.json").exists()
            assert (
                json.loads((case / "ReceiverInterrupted.json").read_text())["Status"]
                == "Expired"
            )
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
    print(
        "PASS: built-in SSH/SFTP gzip/plain roundtrips, host pin, password rejection, no local payload staging, native readback/restore, corruption rejection and expiry"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    execute(parser.parse_args().binary.resolve(strict=True))
