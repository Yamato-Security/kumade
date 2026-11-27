#!/usr/bin/env python3
"""Hybrid S3 inode/stream, disk footprint, partial delivery and abrupt termination."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
from collections import Counter
from http.server import ThreadingHTTPServer
from test_s3_phases import Store


class HybridStore(Store):
    def acknowledge(self, key, data):
        s = self.server
        digest = hashlib.sha256(data).digest()
        if digest == s.pause_digest:
            s.paused.set()
            assert s.continue_read.wait(40)
        if digest == s.lost_digest and len(s.lost_keys) < s.lose_replies:
            # The server committed the bytes but the client never sees the ACK.
            s.lost_keys.append(key)
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        super().acknowledge(key, data)


def main(binary):
    with tempfile.TemporaryDirectory() as directory, ThreadingHTTPServer(("127.0.0.1", 0), HybridStore) as server:
        root = Path(directory)
        # Launch the actual portable binary from an evidence-work drive, using a
        # different working directory so accidental current-directory staging fails.
        portable = root / binary.name
        try:
            os.link(binary, portable)
        except OSError:
            shutil.copy2(binary, portable)
        server.objects = {}
        server.put_attempts = Counter()
        server.deny_all = server.drop_final = False
        server.deny_bytes = None
        server.blocked, server.release_block = threading.Event(), threading.Event()
        server.lost_keys = []
        server.lose_replies = 0
        server.lost_digest = server.pause_digest = None
        server.paused, server.continue_read = threading.Event(), threading.Event()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        endpoint = ["--s3-endpoint", f"http://127.0.0.1:{server.server_port}"]
        target = ["--s3", "s3://evidence-test/hybrid/", *endpoint]
        env = dict(os.environ, AWS_SECRET_ACCESS_KEY="fixture", AWS_SESSION_TOKEN="fixture", AWS_REGION="us-east-1", NO_COLOR="1")
        def command(*args, reader=False, executable=portable):
            return subprocess.Popen([str(executable), *map(str, args)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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
        def collect(stage=None):
            if stage is not None:
                stage.mkdir()
            location = ["--s3-hybrid-dir", stage] if stage is not None else []
            return ["collect", *location, *target, "--source", source, "--computer", "HOST",
                    "--artifact", "windows.eventlogs", "--artifact", "windows.prefetch", "--s3-part-mib", "5",
                    "--reserve-mib", "0", "--threads", "1", "--no-wizard"]
        def no_disk_copies(ws):
            assert not list(ws.rglob("*.evtx")) and not list(ws.rglob("*.pf"))
            assert sum(f.stat().st_size for f in ws.rglob("*") if f.is_file()) < 1024 * 1024
        try:
            prepare()
            # A binary deployed inside the acquired tree must fail before it writes a workspace.
            on_source = source / portable.name
            try:
                os.link(portable, on_source)
            except OSError:
                shutil.copy2(portable, on_source)
            refused = command(*collect(), executable=on_source)
            _, error = refused.communicate(timeout=30)
            assert refused.returncode == 2 and "--s3-hybrid-dir" in error, error
            assert not list(source.glob("kumade-recovery-*")) and not server.objects
            # Lose the acknowledgement on the first full chunk. Only the new
            # key may enter the receipt, even though both writes reached S3.
            first_chunk = prefetch[:5 * 1024 * 1024]
            server.lost_digest = hashlib.sha256(first_chunk).digest()
            server.lose_replies = 1
            run(*collect())
            orphan, = server.lost_keys
            replacement, = [k for k, v in server.objects.items() if v == first_chunk and k != orphan]
            ws, = root.glob("kumade-recovery-*")
            no_disk_copies(ws)
            assert json.loads((ws / "Session.json").read_text())["Hybrid"]
            members = [json.loads(f.read_text())["Member"] for f in (ws / "Streamed").glob("*.json")]
            member, = [m for m in members if m["Path"].endswith("TOOLS.pf")]
            assert member["Chunks"][0]["Key"] == replacement.rsplit("/", 1)[1]
            del server.objects[orphan]
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
            server.lost_digest = None

            prepare()
            stage = root / "partial"
            server.deny_bytes = b"last distinct bytes"
            denied_digest = hashlib.sha256(server.deny_bytes).digest()
            prior = server.put_attempts[denied_digest]
            run(*collect(stage), code=3)
            ws, = stage.iterdir()
            no_disk_copies(ws)
            server.deny_bytes = None
            assert server.put_attempts[denied_digest] == prior + 1
            (source / cold).write_bytes(b"later version that must never be substituted")
            restored = root / "partial-restore"
            restore(ws, "collection", restored, 3)
            assert (restored / "C" / hot).read_bytes() == event and not (restored / "C" / cold).exists()
            with (restored / "Errors.csv").open(newline="") as f:
                failed = list(csv.DictReader(f))
            assert len(failed) == 1 and failed[0]["SourcePath"].endswith("TOOLS.pf") and failed[0]["Status"] == "Failed"

            # Losing both possible acknowledgements mid-write must fail the file.
            # No further fresh key, even when a previous chunk was acknowledged.
            prepare()
            mid = os.urandom(len(first_chunk))
            (source / cold).write_bytes(first_chunk + mid + b"never read again")
            server.lost_keys.clear()
            server.lost_digest = hashlib.sha256(mid).digest()
            server.lose_replies = 2
            stage = root / "lost-twice"
            run(*collect(stage), code=3)
            assert len(server.lost_keys) == len(set(server.lost_keys)) == 2
            assert {k for k, v in server.objects.items() if v == mid} == set(server.lost_keys)
            ws, = stage.iterdir()
            restored = root / "lost-twice-restore"
            restore(ws, "collection", restored, 3)
            with (restored / "Errors.csv").open(newline="") as f:
                row, = csv.DictReader(f)
            assert row["Status"] == "Failed" and not row["RelativeOutputPath"]
            assert not (restored / "C" / cold).exists() and not (restored / "_KumadePartial").exists()
            server.lost_digest = None

            # Shorten the open source while the collector is uploading chunk one.
            # copy_source must report early EOF, with a normal S3 ACK for the tail.
            prepare()
            original = first_chunk + os.urandom(2 * 1024 * 1024)
            prefix = original[:len(first_chunk) + 131075]
            (source / cold).write_bytes(original)
            server.pause_digest = hashlib.sha256(first_chunk).digest()
            stage = root / "short-read"
            p = command(*collect(stage))
            try:
                assert server.paused.wait(35), "First chunk was never uploaded"
                with (source / cold).open("r+b") as f:
                    f.truncate(len(prefix))
                server.continue_read.set()
                out, err = p.communicate(timeout=80)
                assert p.returncode == 3, (p.returncode, out, err)
            finally:
                server.continue_read.set()
                if p.poll() is None:
                    p.kill()
                    p.communicate(timeout=20)
                server.pause_digest = None
            ws, = stage.iterdir()
            no_disk_copies(ws)
            shutil.rmtree(source)
            (ws / "collection-plan.json").unlink()
            (ws / "collection-published.json").unlink()
            run("resume-s3", "--workspace", ws, *target, code=3)
            restored = root / "short-restore"
            restore(ws, "collection", restored, 3)
            run("verify", restored, code=3)
            with (restored / "Errors.csv").open(newline="") as f:
                row, = csv.DictReader(f)
            assert row["Status"] == "Partial" and row["SourcePath"].endswith("TOOLS.pf")
            assert "ended early" in row["Reason"] and int(row["LogicalSize"]) == len(original)
            assert int(row["BytesRead"]) == len(prefix) and row["SHA-256"] == hashlib.sha256(prefix).hexdigest()
            saved = "_KumadePartial/" + row["ObservationId"] + ".partial"
            assert row["RelativeOutputPath"] == saved and (restored / saved).read_bytes() == prefix
            assert not (restored / "C" / cold).exists()

            # Also restore this prefix from its receipt alone after a missing final seal.
            (ws / "collection-plan.json").unlink()
            (ws / "collection-published.json").unlink()
            case = next(ws.glob("HOST_*/Seal.json"))
            case.unlink()
            run("resume-s3", "--workspace", ws, *target, code=3)
            salvaged = root / "short-salvage"
            restore(ws, "recovered-disk", salvaged, 3)
            assert (salvaged / saved).read_bytes() == prefix and not (salvaged / "C" / cold).exists()
            recovery = json.loads((salvaged / "DiskRecovery.json").read_text())
            partial, = [r for r in recovery["Files"] if r["ObservationId"] == row["ObservationId"]]
            assert partial["Status"] == "Partial"

            # Kill the collector during the cold file, before the acquisition seal.
            prepare()
            existing = set(root.glob("kumade-recovery-*"))
            server.block_bytes = b"last distinct bytes"
            p = command(*collect())
            try:
                assert server.blocked.wait(35), "Cold upload was never reached"
                ws, = set(root.glob("kumade-recovery-*")) - existing
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
            print("PASS: hybrid streamed disk files, bounded staging, complete/partial restores, process kill, fresh-key retries, retained short reads and repeatable resume")
        finally:
            server.continue_read.set()
            server.release_block.set()
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    main(parser.parse_args().binary.resolve(strict=True))
