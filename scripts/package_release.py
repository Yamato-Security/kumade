#!/usr/bin/env python3
# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
#
# Unless explicitly acquired and licensed from Licensor under another license, the contents of this
# file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
# allowed by the RPL, and You may not copy or use this file in either source code or executable
# form, except in compliance with the terms and conditions of the RPL.
#
# All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
# OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
# INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
# and limitations under the RPL.
"""Package an already built, version-checked binary with its license notices."""

import argparse
import json
import pathlib
import subprocess
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--output", default="dist")
    args = parser.parse_args()
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"],
        text=True,
    ))
    package = next(p for p in metadata["packages"] if p["name"] == "kumade")
    version = package["version"]
    # These values become filenames, never shell expressions or directory paths.
    for label in [version, args.target, args.platform]:
        if not label or any(not (c.isascii() and (c.isalnum() or c in ".-+_")) for c in label):
            raise ValueError("Unsafe package label")
    name = f"kumade-{version}-{args.platform}"
    suffix = ".exe" if "windows" in args.target else ""
    binary = pathlib.Path(metadata["target_directory"]) / args.target / "release" / ("kumade" + suffix)
    files = [
        (binary, name + suffix, 0o755),
        (pathlib.Path("README.md"), "README.md", 0o644),
        (pathlib.Path("LICENSE"), "LICENSE", 0o644),
        (pathlib.Path("COPYRIGHT"), "COPYRIGHT", 0o644),
        (pathlib.Path("CHANGELOG.md"), "CHANGELOG.md", 0o644),
        (pathlib.Path("THIRD_PARTY_NOTICES/crates.txt"), "THIRD_PARTY_NOTICES.txt", 0o644),
        (pathlib.Path("art/Kumade-Logo.png"), "art/Kumade-Logo.png", 0o644),
    ]
    files.extend((path, path.as_posix(), 0o644) for path in sorted(pathlib.Path("docs").glob("*.md")))
    for source, _, _ in files:
        if not source.is_file():
            raise FileNotFoundError(source)
    output = pathlib.Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    archive = output / (name + ".zip")
    # Refuse to silently replace an earlier package. Timestamps are normalized
    # and Unix permission bits retained, including when packaging on Windows.
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as z:
        for source, member, mode in files:
            info = zipfile.ZipInfo(member, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, source.read_bytes())
    print(archive)


if __name__ == "__main__":
    main()
