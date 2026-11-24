#!/usr/bin/env python3
# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
"""Root/systemd integration test: temporary credential expiry kills active sessions."""

import contextlib
import io
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
import time

import sftp_account


def main():
    if os.geteuid() != 0:
        raise SystemExit("Requires an isolated Linux systemd test host and root")
    base = Path(tempfile.mkdtemp(prefix="kumade-expiry-test-", dir="/run"))
    base.chmod(0o755)
    user, child = None, None
    try:
        # Capture the generated password so it never appears in CI/test logs.
        with contextlib.redirect_stdout(io.StringIO()) as output:
            sftp_account.provision(base, 60)
        user = output.getvalue().split("Username: ", 1)[1].splitlines()[0]
        info = pwd.getpwnam(user)
        unit = f"kumade-sftp-{user}-expiry"
        service = Path("/etc/systemd/system") / (unit + ".service")
        timer = service.with_suffix(".timer")
        assert "Persistent=true" in timer.read_text()
        subprocess.run(
            ["systemctl", "is-enabled", timer.name], check=True, capture_output=True
        )
        # Model an active upload connection: expiry must terminate existing UID
        # processes, not merely prevent a new password login.
        child = subprocess.Popen(
            ["/bin/sleep", "120"], user=info.pw_uid, group=info.pw_gid, extra_groups=[]
        )
        # Simulate the timer being down across its deadline (as during a server
        # reboot). Persistent=true must run the missed revocation when restarted.
        subprocess.run(["systemctl", "stop", timer.name], check=True)
        inactive_until = time.monotonic() + 62
        while time.monotonic() < inactive_until:
            time.sleep(0.25)
        assert child.poll() is None, "Test process exited before replaying expiry"
        subprocess.run(["systemctl", "start", timer.name], check=True)
        deadline = time.monotonic() + 20
        while child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.25)
        assert child.poll() is not None, "Expired uploader retained an active process"
        shadow = subprocess.run(
            ["getent", "shadow", user], check=True, capture_output=True, text=True
        ).stdout
        assert shadow.split(":")[1].startswith("!"), "Expired account was not locked"
        print(
            "PASS: persistent TTL replayed a missed deadline; credentials locked and active UID process terminated"
        )
    finally:
        if user is None:
            # Provisioning failures may leave a deliberately locked account;
            # the helper's own random directory names identify this test only.
            users = [p.name for p in base.iterdir() if p.name.startswith("ku")]
        else:
            users = [user]
        for user in users:
            try:
                uid = pwd.getpwnam(user).pw_uid
            except KeyError:
                continue
            subprocess.run(["usermod", "--lock", user], check=False)
            subprocess.run(["pkill", "-KILL", "-u", str(uid)], check=False)
            unit = f"kumade-sftp-{user}-expiry"
            subprocess.run(
                ["systemctl", "disable", "--now", unit + ".timer"],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                ["systemctl", "stop", unit + ".service"],
                check=False,
                capture_output=True,
            )
            for suffix in (".service", ".timer"):
                (Path("/etc/systemd/system") / (unit + suffix)).unlink(missing_ok=True)
            subprocess.run(["userdel", user], check=True, capture_output=True)
        if child:
            child.wait(timeout=5)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        for user in users:
            (
                Path("/var/lib/systemd/timers")
                / f"stamp-kumade-sftp-{user}-expiry.timer"
            ).unlink(missing_ok=True)
        shutil.rmtree(base)


if __name__ == "__main__":
    main()
