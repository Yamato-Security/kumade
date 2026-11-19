#!/usr/bin/env python3
# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
"""Independent, read-only E01 validation with libewf (development/CI only).

Uses its C media-reading API, avoiding the 2014 ewfverify executable's
40-character additional-hash printing buffer, which cannot print SHA-256.
The collector itself does not use Python or libewf.
"""
import argparse
import ctypes as c
import ctypes.util
import hashlib
import json
import os
from pathlib import Path


def verify(path):
    library = ctypes.util.find_library("ewf")
    if not library:
        raise RuntimeError("libewf is required for independent validation")
    lib = c.CDLL(library)
    error = c.c_void_p()
    handle = c.c_void_p()
    names = c.POINTER(c.c_char_p)()
    count = c.c_int()
    ptr = c.POINTER(c.c_void_p)
    signatures = {
        "libewf_glob": (c.c_int, [c.c_char_p, c.c_size_t, c.c_uint8, c.POINTER(c.POINTER(c.c_char_p)), c.POINTER(c.c_int), ptr]),
        "libewf_glob_free": (c.c_int, [c.POINTER(c.c_char_p), c.c_int, ptr]),
        "libewf_handle_initialize": (c.c_int, [ptr, ptr]),
        "libewf_handle_open": (c.c_int, [c.c_void_p, c.POINTER(c.c_char_p), c.c_int, c.c_int, ptr]),
        "libewf_handle_get_media_size": (c.c_int, [c.c_void_p, c.POINTER(c.c_uint64), ptr]),
        "libewf_handle_read_buffer": (c.c_ssize_t, [c.c_void_p, c.c_void_p, c.c_size_t, ptr]),
        "libewf_handle_get_md5_hash": (c.c_int, [c.c_void_p, c.c_void_p, c.c_size_t, ptr]),
        "libewf_handle_get_sha1_hash": (c.c_int, [c.c_void_p, c.c_void_p, c.c_size_t, ptr]),
        "libewf_handle_close": (c.c_int, [c.c_void_p, ptr]),
        "libewf_handle_free": (c.c_int, [ptr, ptr]),
        "libewf_error_backtrace_sprint": (c.c_int, [c.c_void_p, c.c_void_p, c.c_size_t]),
        "libewf_error_free": (None, [ptr]),
    }
    for name, (restype, argtypes) in signatures.items():
        fn = getattr(lib, name)
        fn.restype, fn.argtypes = restype, argtypes

    def checked(result):
        if result < 0:
            text = c.create_string_buffer(8192)
            lib.libewf_error_backtrace_sprint(error, text, len(text))
            raise RuntimeError(text.value.decode(errors="replace"))
        return result

    opened = False
    try:
        name = os.fsencode(path)
        checked(lib.libewf_glob(name, len(name), 0, c.byref(names), c.byref(count), c.byref(error)))
        if count.value < 1:
            raise RuntimeError("No E01 segments found")
        checked(lib.libewf_handle_initialize(c.byref(handle), c.byref(error)))
        checked(lib.libewf_handle_open(handle, names, count, 1, c.byref(error)))
        opened = True
        size = c.c_uint64()
        checked(lib.libewf_handle_get_media_size(handle, c.byref(size), c.byref(error)))
        digests = {"MD5": hashlib.md5(), "SHA1": hashlib.sha1(), "SHA256": hashlib.sha256()}
        buffer = c.create_string_buffer(1024 * 1024)
        total = 0
        while True:
            length = checked(lib.libewf_handle_read_buffer(handle, buffer, len(buffer), c.byref(error)))
            if not length:
                break
            for digest in digests.values():
                digest.update(buffer.raw[:length])
            total += length
        if total != size.value:
            raise RuntimeError("libewf decoded the wrong media size")
        for label, function, length in [("MD5", lib.libewf_handle_get_md5_hash, 16), ("SHA1", lib.libewf_handle_get_sha1_hash, 20)]:
            stored = c.create_string_buffer(length)
            if checked(function(handle, stored, length, c.byref(error))) != 1:
                raise RuntimeError(f"Missing stored {label}")
            if stored.raw != digests[label].digest():
                raise RuntimeError(f"Decoded media failed stored {label}")
        receipt = Path(str(path) + ".json")
        if receipt.exists():
            report = json.loads(receipt.read_text())
            if report["LogicalBytes"] != total or report["MediaSHA256"] != digests["SHA256"].hexdigest():
                raise RuntimeError("libewf media differs from Kumade's receipt")
        return {"Reader": "libewf", "Segments": count.value, "Bytes": total,
                "MD5": "matched", "SHA1": "matched", "SHA256": digests["SHA256"].hexdigest()}
    finally:
        if opened:
            lib.libewf_handle_close(handle, c.byref(error))
        if handle.value:
            lib.libewf_handle_free(c.byref(handle), c.byref(error))
        if names:
            lib.libewf_glob_free(names, count, c.byref(error))
        if error.value:
            lib.libewf_error_free(c.byref(error))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-q", action="store_true", help="Suppress explanatory output")
    parser.add_argument("image", type=Path)
    print(json.dumps(verify(parser.parse_args().image)))
