#!/usr/bin/env python3
# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
"""Trusted, offline server readback. Revoke the uploader and end its sessions first.

Uses only Python's standard library. Never run as the uploading account. Does not
execute evidence, apply collected ACLs, or turn a partial acquisition into complete.
"""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

BLOCK = 1024 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[a-zA-Z0-9.-]{1,200}\Z")


def regular(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f"Not a single-link regular object: {path.name}")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("Invalid relative output path")
    parts = value.split("/")
    for part in parts:
        stem = part.split(".")[0].upper()
        if (
            not part
            or part in (".", "..")
            or part[-1:] in (" ", ".")
            or any(ord(c) < 32 or c in '<>:"|?*' for c in part)
            or stem in ("CON", "PRN", "AUX", "NUL")
            or re.fullmatch(r"(?:COM|LPT)[1-9]", stem)
        ):
            raise ValueError("Unsafe output component")
    if PurePosixPath(value).is_absolute():
        raise ValueError("Absolute output path")
    return parts


def hash_stream(stream):
    digest, size = hashlib.sha256(), 0
    while data := stream.read(BLOCK):
        digest.update(data)
        size += len(data)
    return size, digest.hexdigest()


def read_json_object(path, limit=128 * 1024 * 1024):
    # Explicit cap for operator-controlled metadata; payloads have no arbitrary cap.
    with regular(path) as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Delivery metadata exceeds 128 MiB")
    return data, json.loads(data)


def restore(incoming, delivery_name, expected_sha256, output, receipt):
    incoming = Path(incoming).resolve(strict=True)
    output, receipt = Path(output).absolute(), Path(receipt).absolute()
    # Resolve trusted parents before checking chroot containment; an alias must
    # not bypass the outside-incoming requirement.
    output = output.parent.resolve(strict=True) / output.name
    receipt = receipt.parent.resolve(strict=True) / receipt.name
    if not NAME.fullmatch(delivery_name) or not delivery_name.endswith(
        "-delivery.json"
    ):
        raise ValueError("Expected the collector's delivery object name")
    if not DIGEST.fullmatch(expected_sha256):
        raise ValueError("Expected the collector's 64-character Delivery SHA256")
    data, delivery = read_json_object(incoming / delivery_name)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("Delivery SHA256 mismatch; stop and investigate")
    if (
        delivery.get("SchemaVersion") != 1
        or delivery.get("Kind") != "KumadeSftpDelivery"
    ):
        raise ValueError("Unsupported delivery schema")
    delivery_id = delivery.get("DeliveryId", "")
    if (
        not re.fullmatch(r"[0-9a-f-]{36}", delivery_id)
        or delivery_name != delivery_id + "-delivery.json"
    ):
        raise ValueError("Delivery ID/name mismatch")
    relative(delivery.get("CollectionName"))
    if len(relative(delivery["CollectionName"])) != 1:
        raise ValueError("CollectionName must be one component")
    objects = delivery.get("Objects")
    if not isinstance(objects, list) or not objects:
        raise ValueError("No final object inventory; incomplete delivery")
    seen_names, seen_paths, parents = set(), set(), set()
    for obj in objects:
        name, path = obj.get("Name", ""), obj.get("RelativePath", "")
        parts = relative(path)
        folded = path.casefold()
        if (
            not NAME.fullmatch(name)
            or not name.startswith(delivery_id + "-")
            or name in seen_names
            or folded in seen_paths
            or folded in parents
        ):
            raise ValueError("Duplicate/conflicting/foreign object")
        for n in range(1, len(parts)):
            parent = "/".join(parts[:n]).casefold()
            if parent in seen_paths:
                raise ValueError("Output file/directory collision")
            parents.add(parent)
        seen_names.add(name)
        seen_paths.add(folded)
        if obj.get("Encoding") not in ("none", "gzip"):
            raise ValueError("Unsupported object encoding")
        for key in ("LogicalBytes", "StoredBytes"):
            if type(obj.get(key)) is not int or obj[key] < 0:
                raise ValueError("Invalid byte count")
        for key in ("LogicalSha256", "StoredSha256"):
            if not DIGEST.fullmatch(obj.get(key, "")):
                raise ValueError("Invalid object SHA256")
    # The destination and receipt must not exist. Keep them outside the chroot.
    for path in (output, receipt):
        if path.is_relative_to(incoming) or path.exists() or path.is_symlink():
            raise ValueError("Restore output/receipt must be new and outside incoming")
    if receipt.is_relative_to(output) or output.is_relative_to(receipt):
        raise ValueError("Receipt and restore directories must be separate")
    output.mkdir(
        mode=0o700
    )  # Parent must exist and be trusted; no arbitrary mkdir chain.
    receipt_written = False
    try:
        for obj in objects:
            source = incoming / obj["Name"]
            destination = output.joinpath(*relative(obj["RelativePath"]))
            with regular(source) as stored:
                size, digest = hash_stream(stored)
                if size != obj["StoredBytes"] or digest != obj["StoredSha256"]:
                    raise ValueError(f"Stored-object hash mismatch: {obj['Name']}")
                stored.seek(0)
                logical = (
                    gzip.GzipFile(fileobj=stored)
                    if obj["Encoding"] == "gzip"
                    else stored
                )
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                fd = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                    0o600,
                )
                digest, size = hashlib.sha256(), 0
                try:
                    with os.fdopen(fd, "wb") as out:
                        while chunk := logical.read(
                            min(BLOCK, obj["LogicalBytes"] - size + 1)
                        ):
                            size += len(chunk)
                            if size > obj["LogicalBytes"]:
                                raise ValueError("Decoded data exceeds declared length")
                            digest.update(chunk)
                            if not chunk.strip(b"\0"):
                                out.seek(len(chunk), os.SEEK_CUR)
                            else:
                                out.write(chunk)
                        out.truncate(size)
                        out.flush()
                        os.fsync(out.fileno())
                finally:
                    if logical is not stored:
                        logical.close()
                if (
                    size != obj["LogicalBytes"]
                    or digest.hexdigest() != obj["LogicalSha256"]
                ):
                    raise ValueError(
                        f"Logical-object hash mismatch: {obj['RelativePath']}"
                    )
        # Verify that collection metadata and recorded payload hashes agree.
        _, summary = read_json_object(output / "Summary.json")
        _, seal = read_json_object(output / "Seal.json")
        if summary != delivery["Summary"]:
            raise ValueError("Summary differs from delivery inventory")
        for name, digest in seal["MetadataSHA256"].items():
            with regular(output.joinpath(*relative(name))) as f:
                if hash_stream(f)[1] != digest:
                    raise ValueError(f"Collection metadata seal mismatch: {name}")
        payloads = {o["RelativePath"]: o for o in objects}
        count = 0
        with regular(output / "Manifest.jsonl") as records:
            for line in records:
                record = json.loads(line)
                path = record.get("RelativeOutputPath")
                if not path:
                    continue
                obj = payloads.get(path)
                if obj is None or record.get("SHA-256") != obj["LogicalSha256"]:
                    raise ValueError("Payload/record hash mismatch")
                if record["BytesRead"] != obj["LogicalBytes"] or record["Verified"]:
                    raise ValueError("Invalid remote acquisition record")
                count += 1
        result = {
            "SchemaVersion": 1,
            "Kind": "KumadeTrustedSftpReadback",
            "DeliveryId": delivery_id,
            "DeliverySHA256": expected_sha256,
            "CollectionName": delivery["CollectionName"],
            "ObjectsVerified": len(objects),
            "PayloadRecordsVerified": count,
            "PayloadHashesVerified": True,
            "AcquisitionState": summary["Completeness"],
            "Limitations": [
                "Readback integrity is not acquisition completeness or proof of source authenticity.",
                "Original timestamps/ACLs/ADS are retained as metadata/exported streams; not applied to this filesystem.",
            ],
        }
        with receipt.open("x", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        receipt_written = True
        return result
    finally:
        if not receipt_written:
            print(
                f"Verification failed. Untrusted partial restore retained: {output}",
                file=sys.stderr,
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--incoming", type=Path, required=True)
    parser.add_argument("--delivery", required=True)
    parser.add_argument(
        "--sha256", required=True, help="Delivery SHA256 copied from collector stdout"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="New trusted restore directory"
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        required=True,
        help="New readback receipt, outside incoming/output",
    )
    parser.add_argument(
        "--uploader-revoked",
        action="store_true",
        required=True,
        help="Confirm account locked and all uploader sessions terminated",
    )
    args = parser.parse_args()
    try:
        result = restore(
            args.incoming, args.delivery, args.sha256, args.output, args.receipt
        )
        print(json.dumps(result, indent=2))
    except (OSError, ValueError, KeyError, EOFError) as error:
        parser.exit(2, f"Verification failed: {error}\n")


if __name__ == "__main__":
    main()
