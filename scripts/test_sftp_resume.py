#!/usr/bin/env python3
# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
"""Collect from two loopback SFTP clients and interrupt one in the middle of a payload."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import tempfile

from test_sftp_receiver import receiver


MIB = 1024 * 1024


class InterruptOnce:
    """Forward encrypted SSH traffic, cutting the first connection after 3 MiB."""

    def __init__(self, receiver_port):
        self.receiver_port = receiver_port
        self.connections = 0
        self.bytes_after_drop = 0
        self.uploading = asyncio.Event()
        self.allow_drop = asyncio.Event()
        self.dropped = asyncio.Event()
        self.resume = asyncio.Event()

    async def forward(self, client, to_client):
        self.connections += 1
        first = self.connections == 1
        if not first:
            await self.resume.wait()
        server, to_server = await asyncio.open_connection(
            "127.0.0.1", self.receiver_port
        )

        async def relay(reader, writer, uploading):
            total = 0
            while data := await reader.read(32 * 1024):
                writer.write(data)
                await writer.drain()
                total += len(data)
                if uploading:
                    if not first:
                        self.bytes_after_drop += len(data)
                    elif total >= 3 * MIB:
                        await self.allow_drop.wait()
                        self.dropped.set()
                        return
                    elif total >= MIB:
                        self.uploading.set()

        pumps = [
            asyncio.create_task(relay(client, to_server, True)),
            asyncio.create_task(relay(server, to_client, False)),
        ]
        try:
            await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        finally:
            to_client.close()
            to_server.close()
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)


async def run_command(args, password=None, expected=0):
    process = await asyncio.create_subprocess_exec(
        *map(str, args),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        output, _ = await asyncio.wait_for(
            process.communicate((password + "\n").encode() if password else None),
            timeout=50,
        )
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
    output = output.decode(errors="replace")
    if password:
        assert password not in output, "Collector printed its password"
    assert process.returncode == expected, (
        f"Unexpected exit {process.returncode}: {output}"
    )
    return output


async def wait_for_file(directory, pattern):
    while not any(directory.glob(pattern)):
        await asyncio.sleep(0.01)


async def exercise(binary, root, *, parallel=False, retries=True):
    service, info, _ = receiver(binary, root / "received", expires="90s", sources=2)
    try:
        accounts = list(info["Sources"].items())
        (first, credentials), (other, other_credentials) = accounts
        assert (
            credentials["Temporary username"] != other_credentials["Temporary username"]
        )
        assert (
            credentials["Temporary password"] != other_credentials["Temporary password"]
        )
        receiver_port = int(info["SFTP receiver"].rsplit(":", 1)[1])
        case_dir = Path(info["Evidence directory"])
        # The same destination filenames must resolve to different source-specific bytes.
        data = {
            first: {"A.pf": b"first source", "Z.pf": os.urandom(8 * MIB)},
            other: {"A.pf": b"other source", "Z.pf": os.urandom(256 * 1024)},
        }
        if parallel:
            data[first]["Y.pf"] = os.urandom(4 * MIB)
            data[first]["X.pf"] = os.urandom(4 * MIB)
        for source, files in data.items():
            prefetch = root / source / "C/Windows/Prefetch"
            prefetch.mkdir(parents=True)
            for name, content in files.items():
                (prefetch / name).write_bytes(content)
            (root / source / "metadata").mkdir()

        async def collect(source, port, password=None, expected=0):
            account = info["Sources"][source]
            return await run_command(
                [
                    binary,
                    "collect",
                    "-d",
                    root / source / "C",
                    "--computer",
                    source,
                    "--artifact",
                    "windows.prefetch",
                    "--sftp",
                    "127.0.0.1",
                    "--sftp-port",
                    port,
                    "--sftp-host-key",
                    info["SSH fingerprint"],
                    "--sftp-user",
                    account["Temporary username"],
                    "--sftp-password-stdin",
                    "--sftp-staging-dir",
                    root / source / "metadata",
                    "--reserve-mib",
                    "0",
                    "--no-wizard",
                    "-T",
                    "4" if parallel else "1",
                    *(["--sftp-no-compression"] if parallel else []),
                    *(["--sftp-retries", "0"] if not retries else []),
                ],
                password or account["Temporary password"],
                expected=expected,
            )

        await collect(
            first, receiver_port, other_credentials["Temporary password"], expected=2
        )
        proxy = InterruptOnce(receiver_port)
        async with await asyncio.start_server(
            proxy.forward, "127.0.0.1", 0
        ) as listener:
            port = listener.sockets[0].getsockname()[1]
            interrupted = asyncio.create_task(
                collect(first, port, expected=0 if retries else 2)
            )
            try:
                await asyncio.wait_for(proxy.uploading.wait(), timeout=30)
                other_task = asyncio.create_task(collect(other, receiver_port))
                other_case = case_dir / other
                await asyncio.wait_for(
                    wait_for_file(other_case / "incoming", "*-payload-*"), timeout=20
                )
                proxy.allow_drop.set()
                await asyncio.wait_for(proxy.dropped.wait(), timeout=15)
                incoming = case_dir / first / "incoming"
                received = sum(
                    path.stat().st_size for path in incoming.glob("*-payload-*")
                )
                source_bytes = sum(map(len, data[first].values()))
                assert MIB < received < source_bytes, "No partially received payload"
                other_output = await other_task
                await asyncio.wait_for(
                    wait_for_file(other_case, "ReadbackReceipt.json"), timeout=20
                )
                assert service.poll() is None, (
                    "Completing one collection stopped the other source"
                )
                # A finalized source cannot start another delivery while the first is paused.
                await collect(other, receiver_port, expected=2)
            finally:
                proxy.allow_drop.set()
                proxy.resume.set()
                first_output = await interrupted
        if not retries:
            assert proxy.connections == 1, (
                "Retries disabled but the collector reconnected"
            )
            assert not (case_dir / first / "ReadbackReceipt.json").exists()
            assert not list(incoming.glob("*-delivery.json")), (
                "Incomplete delivery was finalized"
            )
            return
        assert proxy.connections >= 2, "Interrupted collector did not reconnect"
        # Re-uploading all incompressible source bytes would exceed this bound.
        assert proxy.bytes_after_drop < source_bytes - MIB, "Replayed the entire upload"
        assert await asyncio.to_thread(service.wait, 60) == 0
        deliveries = set()
        for (source, _), output in zip(accounts, (first_output, other_output)):
            case = case_dir / source
            receipt = json.loads((case / "ReadbackReceipt.json").read_text())
            assert receipt["PayloadHashesVerified"] and receipt[
                "PayloadRecordsVerified"
            ] == len(data[source])
            assert receipt["DeliverySHA256"] in output
            assert receipt["DeliveryId"] not in deliveries
            deliveries.add(receipt["DeliveryId"])
            restored = root / (source + "-restored")
            await run_command(
                [
                    binary,
                    "verify-delivery",
                    "--incoming",
                    case / "incoming",
                    "--delivery",
                    receipt["DeliveryId"] + "-delivery.json",
                    "--sha256",
                    receipt["DeliverySHA256"],
                    "--receipt",
                    root / (source + "-receipt.json"),
                    "--restore",
                    restored,
                    "--uploader-revoked",
                ]
            )
            for name, expected in data[source].items():
                assert (restored / "C/Windows/Prefetch" / name).read_bytes() == expected
            assert not list((root / source / "metadata").iterdir()), (
                "Local staging was left behind"
            )
    finally:
        if service.poll() is None:
            service.kill()
        service.wait(timeout=10)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    binary = parser.parse_args().binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="kumade-sftp-resume-") as directory:
        root = Path(directory)
        asyncio.run(exercise(binary, root / "compressed"))
        asyncio.run(exercise(binary, root / "parallel-uncompressed", parallel=True))
        asyncio.run(exercise(binary, root / "disabled-retries", retries=False))
    print(
        "PASS: independent sources, compressed and parallel uncompressed resume, byte-identical restores and retries disabled"
    )
