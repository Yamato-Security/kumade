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
"""Export a standalone executable, an executable-only ZIP, and license notices."""

import argparse
import json
import pathlib
import shutil
import subprocess
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--output", default="dist")
    parser.add_argument("--ruleset", choices=["core", "extended", "full"])
    parser.add_argument("--bundle-manifest", type=pathlib.Path)
    args = parser.parse_args()
    if bool(args.ruleset) != bool(args.bundle_manifest):
        parser.error("--ruleset and --bundle-manifest are required together")
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
    if args.ruleset:
        name += f"-yara-{args.ruleset}"
    suffix = ".exe" if "windows" in args.target else ""
    binary = pathlib.Path(metadata["target_directory"]) / args.target / "release" / ("kumade" + suffix)
    if not binary.is_file():
        raise FileNotFoundError(binary)
    bundle = None
    if args.bundle_manifest:
        import hashlib
        bundle = json.loads(args.bundle_manifest.read_text(encoding="utf-8"))
        archive_bytes = pathlib.Path(bundle["ZIP"]).read_bytes()
        if bundle["RuleSet"] != args.ruleset or hashlib.sha256(archive_bytes).hexdigest() != bundle["ArchiveSHA256"]:
            raise ValueError("Bundle manifest/hash mismatch")
        if archive_bytes not in binary.read_bytes():
            raise ValueError("Executable does not contain the exact compressed bundle")
    # Notices accompany all downloads as one separate release asset. Keeping
    # their text normalized also makes the file identical across matrix jobs.
    sections = [
        f"Kumade {version} — License Notices\n"
        "Source: https://github.com/Yamato-Security/kumade\n",
        pathlib.Path("COPYRIGHT").read_text(encoding="utf-8").strip(),
        pathlib.Path("LICENSE").read_text(encoding="utf-8").strip(),
        pathlib.Path("THIRD_PARTY_NOTICES/crates.txt").read_text(encoding="utf-8").strip(),
    ]
    notices = ("\n\n".join(sections) + "\n").encode("utf-8")
    output = pathlib.Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    archive = output / (name + ".zip")
    executable = output / (name + suffix)
    for path in [archive, executable]:
        if path.exists():
            raise FileExistsError(path)
    license_file = output / "LICENSES.txt"
    if license_file.exists():
        if license_file.read_bytes() != notices:
            raise FileExistsError("Existing LICENSES.txt contains different notices")
    else:
        with license_file.open("xb") as target:
            target.write(notices)
    with binary.open("rb") as source, executable.open("xb") as target:
        shutil.copyfileobj(source, target, length=1024 * 1024)
    executable.chmod(0o755)
    # Refuse to silently replace an earlier package. Timestamps are normalized
    # and Unix permission bits retained, including when packaging on Windows.
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as z:
        info = zipfile.ZipInfo(executable.name, date_time=(1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.external_attr = 0o100755 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        with executable.open("rb") as source, z.open(info, "w") as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
    if bundle:
        # Supply original compressed rule source and metadata as separate assets.
        # Executable ZIPs still contain only one .exe.
        rules_source = output / f"YARA-FORGE-{args.ruleset}-{bundle['Release']}.zip"
        if rules_source.exists() and rules_source.read_bytes() != archive_bytes:
            raise FileExistsError(rules_source)
        if not rules_source.exists():
            rules_source.write_bytes(archive_bytes)
        record = {key: value for key, value in bundle.items() if key != "ZIP"}
        (output / f"YARA-FORGE-{args.ruleset}-NOTICES.json").write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(executable)
    print(archive)
    print(license_file)


if __name__ == "__main__":
    main()
