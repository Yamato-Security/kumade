#!/usr/bin/env python3
"""Exercise phased delivery with the real SDK and a create-only loopback service."""
import argparse
import hashlib
import json
import os
from collections import Counter
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit


class Store(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, code, data=b"", **headers):
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        assert "Credential=READER/" in self.headers["Authorization"]
        data = self.server.objects.get(unquote(urlsplit(self.path).path))
        self.reply(200, data) if data is not None else self.reply(404, b"<Error><Code>NoSuchKey</Code></Error>")

    def do_PUT(self):
        s = self.server
        key = unquote(urlsplit(self.path).path)
        assert "Credential=WRITER/" in self.headers["Authorization"]
        assert self.headers["If-None-Match"] == "*"
        data = self.rfile.read(int(self.headers["Content-Length"]))
        s.put_attempts[hashlib.sha256(data).digest()] += 1
        if key in s.objects:
            self.reply(412, b"<Error><Code>PreconditionFailed</Code></Error>")
            return
        if getattr(s, "block_bytes", None) == data:
            s.blocked.set()
            assert s.release_block.wait(45)
            s.objects[key] = data
            self.close_connection = True
            return
        if s.deny_all or (s.deny_bytes is not None and data == s.deny_bytes):
            self.reply(403, b"<Error><Code>AccessDenied</Code></Error>")
            return
        if "-phase-collection-" in key and s.drop_final:
            s.final.set()
            assert s.release.wait(40)
            s.objects[key] = data
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        s.objects[key] = data
        self.acknowledge(key, data)

    def acknowledge(self, key, data):
        self.reply(200, ETag='"stored"')


def main(binary):
    with ThreadingHTTPServer(("127.0.0.1", 0), Store) as server, tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        server.objects = {}
        server.deny_bytes = None
        server.put_attempts = Counter()
        server.final, server.release = threading.Event(), threading.Event()
        server.deny_all, server.drop_final = False, True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        original = ["--s3", "s3://evidence-test/cases/", "--s3-endpoint", f"http://127.0.0.1:{server.server_port}"]
        env = dict(os.environ, AWS_SECRET_ACCESS_KEY="local-only", AWS_SESSION_TOKEN="fixture", AWS_REGION="us-east-1", NO_COLOR="1")
        def invoke(args, code=0, reader=False):
            result = subprocess.run([str(binary), *map(str,args)], capture_output=True, encoding="utf-8", timeout=80,
                                    env=dict(env, AWS_ACCESS_KEY_ID="READER" if reader else "WRITER"))
            assert result.returncode == code, (result.returncode, result.stdout, result.stderr)
            return result.stdout
        def verify(ws, phase, restore, code=0, receipt=None):
            pub = json.loads((ws / (phase + "-published.json")).read_text())
            relative = next(k for k in server.objects if k.endswith("/" + pub["Name"]))
            args = ["verify-s3", "--s3", "s3:/" + relative, *original[2:], "--sha256", pub["Sha256"],
                    "--restore", restore, "--receipt", receipt or root / (restore.name + "-receipt")]
            return invoke(args, code, reader=True)
        try:
            source = root / "C"
            hot, cold = "Windows/System32/winevt/Logs/Security.evtx", "Windows/Prefetch/TOOLS.pf"
            for name in [hot, cold]:
                (source / name).parent.mkdir(parents=True)
                (source / name).write_bytes(name.encode())
            if os.name == "nt":
                # A Windows staged collection must retain the base file and each ADS separately.
                Path(str(source / cold) + ":Zone.Identifier").write_bytes(b"ZoneId=3")
            recovery = root / "stage"
            recovery.mkdir()
            collect = ["collect", "--source", source, "--computer", "HOST01", "--yes", "--artifact", "windows.eventlogs",
                       "--artifact", "windows.prefetch", "--reserve-mib", "0", "--s3-recovery-dir", recovery, *original]
            p = subprocess.Popen([str(binary), *map(str,collect)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 encoding="utf-8", env=dict(env, AWS_ACCESS_KEY_ID="WRITER"))
            try:
                if not server.final.wait(35):
                    server.release.set()
                    raise AssertionError(p.communicate(timeout=15))
                ws, = recovery.iterdir()
                assert "Another uploader" in subprocess.run([str(binary), "resume-s3", "--workspace", str(ws), *original],
                    env=dict(env, AWS_ACCESS_KEY_ID="WRITER"), encoding="utf-8", capture_output=True).stderr
                verify(ws, "hot-disk", root / "hot")
                assert (root / "hot/C" / hot).read_bytes() == hot.encode()
                assert not (root / "hot/C" / cold).exists()
                assert p.poll() is None
            finally:
                server.release.set()
                stdout, stderr = p.communicate(timeout=30)
            assert p.returncode == 2 and "expected SHA-256" in stderr, (stdout, stderr)
            assert (ws / "collection-plan.json").is_file()
            keys = set(server.objects)
            shutil.rmtree(source)  # No original evidence is accessible to either resumed process.
            resume = ["resume-s3", "--workspace", ws, *original]
            server.drop_final = False
            invoke(resume)
            added = set(server.objects) - keys
            assert len(added) == 1 and "-phase-collection-" in added.pop()
            keys = set(server.objects)
            invoke(resume)
            assert set(server.objects) == keys
            verify(ws, "collection", root / "restored")
            for name in [hot, cold]:
                assert (root / "restored/C" / name).read_bytes() == name.encode()
            invoke(["verify", root / "restored"])
            if os.name == "nt":
                assert (root / "restored/_KumadeStreams/C" / cold / "Zone.Identifier").read_bytes() == b"ZoneId=3"
                rows = [json.loads(row) for row in (root / "restored/Manifest.jsonl").read_text().splitlines()]
                assert all(row["SourceFileId"].startswith("win:") for row in rows)
                assert json.loads((root / "restored/Summary.json").read_text())["MetadataErrors"] == 0
            bad = json.loads((ws / "hot-disk-published.json").read_text())
            manifest = json.loads(next(v for k,v in server.objects.items() if k.endswith(bad["Name"])))
            key = next(k for k in server.objects if k.endswith(manifest["Files"][0]["Chunks"][0]["Key"]))
            saved = server.objects[key]
            server.objects[key] = b"bad"
            verify(ws, "hot-disk", root / "bad", code=2)
            assert not (root / "bad").exists() and not (root / "bad-receipt").exists()
            server.objects[key] = saved

            # Network unavailable for the *entire* acquisition. Resume with only staged bytes.
            (source / cold).parent.mkdir(parents=True)
            (source / cold).write_bytes(b"before outage")
            recovery2 = root / "outage"
            recovery2.mkdir()
            server.deny_all = True
            collect[collect.index(recovery)] = recovery2
            invoke(collect, code=2)
            ws2, = recovery2.iterdir()
            # Crash window between committing the ordinary collection seal and its delivery plan.
            (ws2 / "collection-plan.json").unlink()
            before = set(server.objects)
            invoke(["resume-s3", "--workspace", ws2, "--s3", "s3://evidence-test/wrong/", *original[2:]], code=2)
            assert set(server.objects) == before
            (source / cold).write_bytes(b"later observation")
            server.deny_all = False
            invoke(["resume-s3","--workspace",ws2,*original])
            verify(ws2,"collection",root / "after-outage")
            assert (root / "after-outage/C" / cold).read_bytes() == b"before outage"
            # Exercise the live/memory phase planning entry point in collect. An
            # offline source must record a partial memory request, never dump this runner.
            offline = root / "offline-memory"
            offline.mkdir()
            collect[collect.index(recovery2)] = offline
            invoke([*collect,"--memory"],code=3)
            offline_ws, = offline.iterdir()
            verify(offline_ws,"memory",root / "offline-ram",code=3)
            assert not (root / "offline-ram/Memory/Memory.dmp").exists()

            # Simulate a stopped acquisition just after the early seal was written.
            # These are synthetic providers, not a dump of the machine running CI.
            ws3 = root / "volatile-recovery"
            ws3.mkdir()
            session = json.loads((ws / "Session.json").read_text())
            session["Id"] = str(uuid.uuid4())
            (ws3 / "Session.json").write_text(json.dumps(session))
            for lock in ["Upload.lock", "Acquisition.lock"]:
                (ws3 / lock).touch()
            early = ws3 / (".kumade-volatile-" + str(uuid.uuid4()))
            (early / "Memory").mkdir(parents=True)
            (early / "LiveInfo").mkdir()
            def digest(data):
                return hashlib.sha256(data).hexdigest()
            def put(path, data):
                (early / path).write_bytes(data)
                return digest(data)
            def put_json(path, doc):
                return put(path, json.dumps(doc).encode())
            first_chunk = b"A" * (session["PartMib"] << 20)
            second_chunk = b"B" * len(first_chunk)
            ram = first_chunk + second_chunk + b"original RAM-only bytes"
            paged, live = b"original paging snapshot", b"Pid,Image\n17,original.exe\n"
            timestamp = "2026-11-26T01:02:03Z"
            # Use an actual collector Record as the schema for the synthetic provider.
            template = json.loads((root / "restored/Manifest.jsonl").read_text().splitlines()[0])
            def record(path, data, artifact):
                return dict(template, SourceId="Memory", ArtifactIds=artifact, RelativeOutputPath=path,
                            StartedUtc=timestamp, FinishedUtc=timestamp, BytesRead=len(data),
                            Status="Acquired", Verified=True, ObservationId=str(uuid.uuid4()), **{"SHA-256":digest(data)})
            mr = record("Memory/Memory.dmp", ram, "windows.memory")
            pr = record("Memory/Pagefile0.sys", paged, "windows.memory.pagefile")
            hashes = {mr["RelativeOutputPath"]:put(mr["RelativeOutputPath"],ram),
                      pr["RelativeOutputPath"]:put(pr["RelativeOutputPath"],paged),
                      "MemoryRequest.json":put_json("MemoryRequest.json",mr),
                      "Memory/Pagefiles.json":put_json("Memory/Pagefiles.json",[pr])}
            livefile = "LiveInfo/Processes.csv"
            livehash = put(livefile, live)
            entry = dict(Provider="Processes", Status="Success", Rows=1, StartedUtc=timestamp,
                         FinishedUtc=timestamp, ElapsedSeconds=0.01, OutputFile=livefile,
                         Bytes=len(live), Sha256=livehash, Message="")
            live_hashes = {livefile:livehash, "LiveInfo/Manifest.json":put_json("LiveInfo/Manifest.json",{"Entries":[entry]}),
                           "LiveInfo/Manifest.csv":put("LiveInfo/Manifest.csv",b"Provider\nProcesses\n")}
            hashes["LiveInfo/Seal.json"] = put_json("LiveInfo/Seal.json",{"SchemaVersion":1,"FileSHA256":live_hashes})
            put_json("Seal.json",{"SchemaVersion":1,"Kind":"KumadeEarlyVolatile","Computer":session["Computer"],"Hashes":hashes})
            command = ["resume-s3","--workspace",ws3,*original]
            server.deny_bytes = second_chunk
            invoke(command,code=2)
            assert not (ws3 / "memory-published.json").exists()
            verify(ws3,"live",root / "live")
            assert (root / "live" / livefile).read_bytes() == live
            marker = (ws3 / "live-published.json").read_bytes()
            server.deny_bytes = None
            invoke(command,code=3)
            verify(ws3,"memory",root / "memory")
            assert (root / "memory" / mr["RelativeOutputPath"]).read_bytes() == ram
            assert (root / "memory" / pr["RelativeOutputPath"]).read_bytes() == paged
            assert server.put_attempts[hashlib.sha256(first_chunk).digest()] == 1
            assert server.put_attempts[hashlib.sha256(second_chunk).digest()] == 2
            assert (ws3 / "live-published.json").read_bytes() == marker
            assert not (ws3 / "collection-published.json").exists()
            # Replay the same protected volatile capture using a hybrid session.
            hw = root / "hybrid-volatile"
            hw.mkdir()
            for lock in ["Upload.lock", "Acquisition.lock"]:
                (hw / lock).touch()
            (hw / "Streamed").mkdir()
            session.update(Id=str(uuid.uuid4()), Hybrid=True)
            (hw / "Session.json").write_text(json.dumps(session))
            shutil.copytree(early, hw / early.name)
            invoke(["resume-s3", "--workspace", hw, *original], code=3)
            verify(hw, "live", root / "hybrid-live")
            verify(hw, "memory", root / "hybrid-ram")
            assert (root / "hybrid-live" / livefile).read_bytes() == live
            assert (root / "hybrid-ram" / mr["RelativeOutputPath"]).read_bytes() == ram
            assert (root / "hybrid-ram" / pr["RelativeOutputPath"]).read_bytes() == paged
            print("PASS: original RAM, pagefile and live rows recover independently after a stopped acquisition")
            print("PASS: independent hot evidence during delivery, lost final ACK, repeated resume, cold-start outage, source removal/change and tamper rejection")
        finally:
            server.release.set()
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    main(parser.parse_args().binary.resolve(strict=True))
