#!/usr/bin/env python3
"""HTFW container parser.

Layout taken from 5868USB.dll sub_180092eb0 (header reader) and sub_180092640
(isRealFirmware: validates magic + model only). Verified against stock
Firmware V1.3.3 (2,056,820 B) and PocketMaster_CFW0.9.8_base1.3.3 (2,125,752 B):
in both, field 0x23 == file_size - 136 and an 80-byte all-0xFF trailer follows.
"""
import struct
import hashlib
import json
import sys

MAGIC = b"HTFW"
HDR_LEN = 0x38
TRAILER_LEN = 80


def parse(path):
    with open(path, "rb") as fh:
        b = fh.read()
    if len(b) < HDR_LEN or b[:4] != MAGIC:
        raise ValueError("%s: not an HTFW container" % path)

    def u32(o):
        return struct.unpack_from("<I", b, o)[0]

    def u16(o):
        return struct.unpack_from("<H", b, o)[0]

    f = {
        "magic": b[0:4].decode("ascii", "replace"),
        "u04": u16(0x04),          # differs per image; nothing in the DLL compares it
        "u06": u16(0x06),          # 1 in every image seen
        "image_size": u32(0x08),   # == file length in both known images
        "model": b[0x0C:0x1C].split(b"\0")[0].decode("ascii", "replace"),
        "b1C": b[0x1C],            # 0x56 in every image seen
        "version": "%d.%d.%d" % (b[0x1D], b[0x1E], b[0x1F]),
        "b20_23": list(b[0x20:0x24]),
        "payload_len": u32(0x24),  # file_size - 136; header + payload + 80 = file_size
        "digest_slot": b[0x28:0x38].hex(),
        "file_size": len(b),
    }
    f["payload"] = b[HDR_LEN:HDR_LEN + f["payload_len"]]
    f["trailer"] = b[HDR_LEN + f["payload_len"]:]
    f["payload_sha256"] = hashlib.sha256(f["payload"]).hexdigest()

    w = f["warnings"] = []
    if f["image_size"] != f["file_size"]:
        w.append("0x08 (%d) != file length (%d)" % (f["image_size"], f["file_size"]))
    if HDR_LEN + f["payload_len"] + TRAILER_LEN != f["file_size"]:
        w.append("0x24 payload_len (%d): header+payload+trailer (%d) != file size (%d)"
                 % (f["payload_len"], HDR_LEN + f["payload_len"] + TRAILER_LEN, f["file_size"]))
    if len(f["trailer"]) != TRAILER_LEN:
        w.append("trailer is %d B, expected %d" % (len(f["trailer"]), TRAILER_LEN))
    elif f["trailer"].count(0xFF) != TRAILER_LEN:
        w.append("trailer is not all 0xFF")
    if f["u06"] != 1:
        w.append("u06 is %d, expected 1" % f["u06"])
    if f["b1C"] != 0x56:
        w.append("0x1C is %#x, expected 0x56" % f["b1C"])
    f["sane"] = not w
    return f


def check_model(f, expected):
    """Mirror isRealFirmware: the DLL's tag is literally 'equalsIgnoreCase'."""
    return f["model"].lower() == expected.lower()


def main(argv):
    if not argv:
        print("usage: htfw.py FILE.bin [FILE.bin ...]", file=sys.stderr)
        return 2
    rc = 0
    for p in argv:
        try:
            f = parse(p)
        except ValueError as e:
            print("%s\n  ERROR: %s" % (p, e), file=sys.stderr)
            rc = 1
            continue
        shown = dict((k, v) for k, v in f.items() if k not in ("payload", "trailer"))
        print(p)
        print(json.dumps(shown, indent=2))
        for w in f["warnings"]:
            print("  WARNING: %s" % w, file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
