#!/usr/bin/env python3
# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
"""Provision/revoke one temporary Linux OpenSSH upload account (administrator only).

Writes a Match configuration fragment; does NOT edit/reload your SSH service.
Install the fragment and validate with sshd -t before enabling external access.
"""

import argparse
from datetime import datetime, timedelta, timezone
import grp
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess

ALLOW = "open,close,write,fsync,realpath,limits"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def provision(base, ttl):
    if os.geteuid() != 0:
        raise ValueError("Run as root on a dedicated Linux evidence server")
    base = Path(base).absolute()
    if any(c.isspace() or c in '"\\%$' for c in str(base)):
        raise ValueError(
            "Base path cannot contain whitespace, quotes, backslashes, % or $"
        )
    if not base.is_dir() or base.is_symlink():
        raise ValueError("Base must be an existing root-owned directory")
    for p in [base, *base.parents]:
        info = p.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(
                "Base and every ancestor must be root-owned, not group/other writable"
            )
    if not shutil.which("setfacl") or not shutil.which("systemctl"):
        raise ValueError("Install acl and use a systemd server for enforced TTL")
    username = "ku" + secrets.token_hex(6)
    case = base / username
    case.mkdir(mode=0o700)
    run("setfacl", "-b", "-k", str(case))
    chroot = case / "chroot"
    chroot.mkdir(mode=0o755)
    chroot.chmod(0o755)
    incoming = chroot / "incoming"
    incoming.mkdir(mode=0o1733)
    for directory in (chroot, incoming):
        run("setfacl", "-b", "-k", str(directory))
    incoming.chmod(0o1733)
    # No supplementary groups, no pre-existing UID/home, no interactive shell.
    run(
        "useradd",
        "--no-create-home",
        "--user-group",
        "--home-dir",
        "/incoming",
        "--shell",
        "/usr/sbin/nologin",
        username,
    )
    uid = pwd.getpwnam(username).pw_uid
    if uid == 0 or grp.getgrnam(username).gr_gid == 0:
        raise ValueError("Unsafe upload account identity")
    try:
        # OpenSSH requires all ChrootDirectory ancestors to be searchable for this user.
        case.chmod(0o755)
        configuration = case / "sshd-match.conf"
        configuration.write_text(
            f"""# Install under sshd_config.d; validate with sshd -t, then reload.
Match User {username}
    ChrootDirectory {chroot}
    ForceCommand internal-sftp -d /incoming -u 0777 -p {ALLOW}
    AuthenticationMethods password
    PasswordAuthentication yes
    PubkeyAuthentication no
    KbdInteractiveAuthentication no
    DisableForwarding yes
    PermitTTY no
    PermitTunnel no
    PermitUserRC no
    X11Forwarding no
    MaxSessions 1
Match all
""",
            encoding="utf-8",
        )
        configuration.chmod(0o600)
        revoke = case / "revoke.sh"
        revoke.write_text(
            f"#!/bin/sh\nset -eu\n/usr/sbin/usermod --lock {username}\n/usr/bin/pkill -KILL -u {uid} || [ $? -eq 1 ]\n",
            encoding="ascii",
        )
        revoke.chmod(0o700)
        # Install persistent expiry before unlocking credentials. Ending sessions matters: expiry
        # alone does not invalidate already-open writable SFTP file descriptors.
        expires = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        unit_name = f"kumade-sftp-{username}-expiry"
        units = Path("/etc/systemd/system")
        service = units / (unit_name + ".service")
        timer = units / (unit_name + ".timer")
        with service.open("x", encoding="ascii") as f:
            f.write(
                f"[Unit]\nDescription=Revoke temporary Kumade SFTP account\n"
                f"[Service]\nType=oneshot\nExecStart=/bin/sh {revoke}\n"
            )
        service.chmod(0o600)
        with timer.open("x", encoding="ascii") as f:
            f.write(
                f"[Unit]\nDescription=Expire temporary Kumade SFTP account\n"
                f"[Timer]\nOnCalendar={expires.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
                f"Persistent=true\nAccuracySec=1s\nUnit={unit_name}.service\n"
                f"[Install]\nWantedBy=timers.target\n"
            )
        timer.chmod(0o600)
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "--now", timer.name)
        # Coarse shadow expiry is a second, boot-independent upper bound if
        # systemd is disabled. The persistent timer supplies the precise TTL.
        shadow_expiry = (expires + timedelta(days=1)).date().isoformat()
        run("chage", "--expiredate", shadow_expiry, username)
        password = secrets.token_urlsafe(32)
        run("chpasswd", input=f"{username}:{password}\n", text=True)
        print(
            f"Username: {username}\nTemporary password: {password}\nExpires after: {ttl}s"
        )
        print(
            f"SSH configuration: {configuration}\nIncoming: {incoming}\nRevoke now: sudo /bin/sh {revoke}"
        )
        print(
            "Share credentials out of band. Pin the server host-key fingerprint separately. Do not reuse this account."
        )
    except BaseException:
        run("usermod", "--lock", username)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base",
        type=Path,
        required=True,
        help="Existing root-owned parent, e.g. /srv/kumade",
    )
    parser.add_argument("--ttl-seconds", type=int, default=3600)
    args = parser.parse_args()
    if not 60 <= args.ttl_seconds <= 86400:
        parser.error("TTL must be 60 through 86400 seconds")
    try:
        provision(args.base, args.ttl_seconds)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(2, f"Provisioning failed: {error}\n")


if __name__ == "__main__":
    main()
