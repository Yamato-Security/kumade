#!/usr/bin/env python3
"""Hybrid S3 inode/stream, disk footprint, partial delivery and abrupt termination."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from collections import Counter
from http.server import ThreadingHTTPServer
from test_s3_phases import Store


def main(binary):
    with tempfile.TemporaryDirectory() as directory, ThreadingHTTPServer(("127.0.0.1", 0), Store) as server:
        root = Path(directory)
        server.objects = {}
        server.put_attempts = Counter()
        server.deny_all = server.drop_final = False
        server.deny_bytes = None
        server.blocked, server.release_block = threading.Event(), threading.Event()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        endpoint = ["--s3-endpoint", f"http://127.0.0.1:{server.server_port}"]
        target = ["--s3", "s3://evidence-test/hybrid/", *endpoint]
        env = dict(os.environ, AWS_SECRET_ACCESS_KEY="fixture", AWS_SESSION_TOKEN="fixture", AWS_REGION="us-east-1", NO_COLOR="1")
        def command(*args, reader=False):
            return subprocess.Popen([str(binary), *map(str, args)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=dict(env, AWS_ACCESS_KEY_ID="READER" if reader else "WRITER"), text=True, encoding="utf-8")
        def run(*args, code=0, reader=False):
            p = command(*args, reader=reader)
            out, err = p.communicate(timeout=80)
            assert p.returncode == code, (p.returncode, out, err)
        def restore(ws, phase, output, code):
            pub = json.loads((ws / (phase + "-published.json")).read_text())
            uri = next(k for k in server.objects if k.endswith("/" + pub["Name"]))
            run("verify-s3", "--s3", "s3:/" + uri, *endpoint, "--sha256", pub["Sha256"], "--receipt",
                root / (output.name + "-receipt.json"), "--restore", output, code=code, reader=True)
        source = root / "C"
        hot = Path("Windows/System32/winevt/Logs/Security.evtx")
        cold = Path("Windows/Prefetch/TOOLS.pf")
        event = os.urandom(6000)
        prefetch = os.urandom(5 * 1024 * 1024) + b"last distinct bytes"
        alternate = b"Stream contents"
        def prepare():
            for name, data in [(hot, event), (cold, prefetch)]:
                (source / name).parent.mkdir(parents=True, exist_ok=True)
                (source / name).write_bytes(data)
            if os.name == "nt":
                Path(str(source / hot) + ":Zone.Identifier").write_bytes(alternate)
        def collect(stage):
            stage.mkdir()
            return ["collect", "--s3-hybrid-dir", stage, *target, "--source", source, "--computer", "HOST",
                    "--artifact", "windows.eventlogs", "--artifact", "windows.prefetch", "--s3-part-mib", "5",
                    "--reserve-mib", "0", "--threads", "1", "--yes"]
        def no_disk_copies(ws):
            assert not list(ws.rglob("*.evtx")) and not list(ws.rglob("*.pf"))
            assert sum(f.stat().st_size for f in ws.rglob("*") if f.is_file()) < 1024 * 1024
        try:
            prepare()
            stage = root / "complete"
            run(*collect(stage))
            ws, = stage.iterdir()
            no_disk_copies(ws)
            assert json.loads((ws / "Session.json").read_text())["Hybrid"]
            shutil.rmtree(source)
            # Rebuild the final plan using the sealed metadata and acknowledged remote payloads.
            (ws / "collection-plan.json").unlink()
            (ws / "collection-published.json").unlink()
            before = set(server.objects)
            run("resume-s3", "--workspace", ws, *target)
            assert all("-phase-collection-" in k for k in set(server.objects) - before)
            restored = root / "restored"
            restore(ws, "collection", restored, 0)
            run("verify", restored)
            assert (restored / "C" / hot).read_bytes() == event
            assert (restored / "C" / cold).read_bytes() == prefetch
            if os.name == "nt":
                assert (restored / "_KumadeStreams/C" / hot / "Zone.Identifier").read_bytes() == alternate
            assert server.put_attempts[hashlib.sha256(prefetch[:5 * 1024 * 1024]).digest()] == 1

            prepare()
            stage = root / "partial"
            server.deny_bytes = b"last distinct bytes"
            run(*collect(stage), code=3)
            ws, = stage.iterdir()
            no_disk_copies(ws)
            server.deny_bytes = None
            (source / cold).write_bytes(b"later version that must never be substituted")
            restored = root / "partial-restore"
            restore(ws, "collection", restored, 3)
            assert (restored / "C" / hot).read_bytes() == event and not (restored / "C" / cold).exists()
            with (restored / "Errors.csv").open(newline="") as f:
                failed = list(csv.DictReader(f))
            assert len(failed) == 1 and failed[0]["SourcePath"].endswith("TOOLS.pf") and failed[0]["Status"] == "Failed"

            # Kill the collector during the cold file, before the acquisition seal.
            prepare()
            stage = root / "crash"
            server.block_bytes = b"last distinct bytes"
            p = command(*collect(stage))
            try:
                assert server.blocked.wait(35), "Cold upload was never reached"
                ws, = stage.iterdir()
                no_disk_copies(ws)
                p.kill()
            finally:
                if p.poll() is None:
                    p.kill()
                p.communicate(timeout=20)
                server.release_block.set()
            server.block_bytes = None
            shutil.rmtree(source)
            run("resume-s3", "--workspace", ws, *target, code=3)
            restored = root / "crash-restore"
            restore(ws, "recovered-disk", restored, 3)
            assert (restored / "C" / hot).read_bytes() == event and not (restored / "C" / cold).exists()
            report = json.loads((restored / "DiskRecovery.json").read_text())
            assert report["PlanAvailable"] and not report["AcquisitionComplete"]
            status = {r["SourcePath"]: r["Status"] for r in report["Files"]}
            assert status[next(k for k in status if k.endswith("Security.evtx"))] == "Transferred"
            assert status[next(k for k in status if k.endswith("TOOLS.pf"))] == "NotConfirmed"
            before = set(server.objects)
            run("resume-s3", "--workspace", ws, *target, code=3)
            assert before == set(server.objects)
            print("PASS: hybrid streamed disk files, bounded staging, complete/partial restores, process kill, confirmed-file salvage and repeatable resume")
        finally:
            server.release_block.set()
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    main(parser.parse_args().binary.resolve(strict=True))
