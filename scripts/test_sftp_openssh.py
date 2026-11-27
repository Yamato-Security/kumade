#!/usr/bin/env python3
# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
"""Isolated localhost OpenSSH integration test. Requires Linux root; no main sshd edits."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs)


def exercise(binary):
    if os.geteuid() != 0:
        raise SystemExit("Run using sudo on an isolated Linux test host")
    root = Path(tempfile.mkdtemp(prefix="kumade-sftp-test-", dir="/run"))
    root.chmod(0o755)
    user = "kt" + secrets.token_hex(6)
    password = secrets.token_urlsafe(24)
    server = None
    user_created = False
    try:
        run(
            [
                "useradd",
                "--no-create-home",
                "--user-group",
                "--home-dir",
                "/incoming",
                "--shell",
                "/usr/sbin/nologin",
                user,
            ]
        )
        user_created = True
        run(["chpasswd"], input=f"{user}:{password}\n")
        uid = pwd.getpwnam(user).pw_uid
        chroot = root / "chroot"
        chroot.mkdir(mode=0o755)
        incoming = chroot / "incoming"
        incoming.mkdir(mode=0o1733)
        # Eliminate inherited default ACLs, even on unusual CI hosts.
        for p in (root, chroot, incoming):
            run(["setfacl", "-b", "-k", str(p)])
        incoming.chmod(0o1733)
        chroot.chmod(0o755)
        hostkey = root / "hostkey"
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(hostkey)])
        pub = hostkey.with_suffix(".pub").read_text().split()[1]
        pin = "SHA256:" + base64.b64encode(
            hashlib.sha256(base64.b64decode(pub)).digest()
        ).decode().rstrip("=")
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        config = root / "sshd.conf"
        base_config = f"""ListenAddress 127.0.0.1
Port {port}
HostKey {hostkey}
PidFile {root}/sshd.pid
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication no
UsePAM no
PermitRootLogin no
AllowUsers {user}
LogLevel VERBOSE
Subsystem sftp internal-sftp
Match User {user}
    ChrootDirectory {chroot}
    ForceCommand internal-sftp -d /incoming -u UMASK -p open,close,write,fsync,realpath,limits
    DisableForwarding yes
    PermitTTY no
    PermitUserRC no
"""
        Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
        log = (root / "server.log").open("w+")

        def start(umask):
            config.write_text(base_config.replace("UMASK", umask))
            run(["/usr/sbin/sshd", "-t", "-f", str(config)])
            process = subprocess.Popen(
                ["/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
                stdout=log,
                stderr=log,
            )
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError("Isolated sshd exited")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        return process
                except OSError:
                    time.sleep(0.02)
            raise AssertionError("Isolated sshd did not start")

        source = root / "C"
        prefetch = source / "Windows/Prefetch"
        prefetch.mkdir(parents=True)
        contents = {
            "ZEROS.pf": bytes(8 * 1024 * 1024),
            "DATA.pf": secrets.token_bytes(1024 * 1024),
        }
        for name, data in contents.items():
            (prefetch / name).write_bytes(data)
        staging = root / "staging"
        staging.mkdir()
        common = [
            str(binary),
            "collect",
            "-d",
            str(source),
            "--computer",
            "SFTP-TEST",
            "--artifact",
            "windows.prefetch",
            "--sftp",
            "127.0.0.1",
            "--sftp-port",
            str(port),
            "--sftp-user",
            user,
            "--sftp-host-key",
            pin,
            "--sftp-password-stdin",
            "--sftp-staging-dir",
            str(staging),
            "--reserve-mib",
            "0",
            "--no-wizard",
            "-T",
            "4",
        ]
        server = start("0777")
        wrong = common.copy()
        wrong[wrong.index(pin)] = "SHA256:" + "A" * 43
        result = subprocess.run(
            wrong, input=password + "\n", capture_output=True, text=True, timeout=60
        )
        assert result.returncode == 2 and not list(incoming.iterdir()), (
            "Incorrect host pin must fail before uploading"
        )
        result = subprocess.run(
            common, input=password + "\n", capture_output=True, text=True, timeout=90
        )
        if result.returncode != 0:
            log.flush()
            raise AssertionError(
                f"Collection failed: {result.stdout}\n{result.stderr}\n{(root / 'server.log').read_text()}"
            )
        assert password not in result.stdout + result.stderr
        assert not list(staging.iterdir()), "Successful delivery left staging"
        delivery_name = re.search(
            r"Remote delivery:\s*([a-f0-9-]+-delivery.json)", result.stdout
        ).group(1)
        digest = re.search(r"Delivery SHA256:\s*([a-f0-9]{64})", result.stdout).group(1)
        uploaded = list(incoming.iterdir())
        assert all(
            p.stat().st_uid == uid and p.stat().st_mode & 0o777 == 0 for p in uploaded
        )
        # Stop every uploader session before root-owned readback.
        run(["usermod", "--lock", user])
        subprocess.run(["pkill", "-KILL", "-u", str(uid)], check=False)
        restore = Path(__file__).with_name("sftp_restore.py")
        output = root / "restored"
        run(
            [
                "python3",
                str(restore),
                "--incoming",
                str(incoming),
                "--delivery",
                delivery_name,
                "--sha256",
                digest,
                "--output",
                str(output),
                "--receipt",
                str(root / "receipt.json"),
                "--uploader-revoked",
            ]
        )
        for name, data in contents.items():
            assert (output / "C/Windows/Prefetch" / name).read_bytes() == data
        receipt = json.loads((root / "receipt.json").read_text())
        assert (
            receipt["PayloadHashesVerified"] and receipt["PayloadRecordsVerified"] == 2
        )
        # A weaker policy must fail despite EXCL and denied chmod/remove requests.
        server.terminate()
        server.wait(timeout=10)
        run(["chpasswd"], input=f"{user}:{password}\n")
        server = start("0022")
        weak = subprocess.run(
            common, input=password + "\n", capture_output=True, text=True, timeout=60
        )
        assert weak.returncode == 2 and "protection failed" in weak.stderr, weak.stderr
        assert all(
            "-delivery.json" not in p.name or p.name == delivery_name
            for p in incoming.iterdir()
        )
        print(
            "PASS: pinned SSH; wrong pin rejected; upload-only mutation/read probes; gzip+logical/stored hashes; no local payloads; trusted restore; weak server refused"
        )
    finally:
        if server:
            server.terminate()
            server.wait(timeout=10)
        if user_created:
            uid = pwd.getpwnam(user).pw_uid
            subprocess.run(["pkill", "-KILL", "-u", str(uid)], check=False)
            subprocess.run(["userdel", user], check=True, capture_output=True)
        shutil.rmtree(root)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    exercise(parser.parse_args().binary.resolve(strict=True))
