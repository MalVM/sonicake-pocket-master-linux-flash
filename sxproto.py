#!/usr/bin/env python3
"""5868USB SysEx codec, recovered from 5868USB.dll.

  sub_180095210  encoder: [crc8][count][index][type] ++ payload, nibble-expanded
  sub_18008fca0  receiver: same, verified with the same CRC table
  sub_180095010  chunking: 42 B if type==0 else 19 B; terminator is F0 F7

Importing this module self-checks the CRC table against the constants read out
of the DLL, so a wrong table fails loudly instead of silently.
"""
import sys
import binascii


def _table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = ((c << 1) ^ 0x07) & 0xFF if c & 0x80 else (c << 1) & 0xFF
        t.append(c)
    return bytes(t)


CRC8_TABLE = _table()
# constants read directly from the table at 0x18013a400 in 5868USB.dll
assert CRC8_TABLE[0] == 0x00 and CRC8_TABLE[1] == 0x07 and CRC8_TABLE[2] == 0x0E \
    and CRC8_TABLE[3] == 0x09 and CRC8_TABLE[8] == 0x38 and CRC8_TABLE[9] == 0x3F, \
    "CRC-8 table does not match 5868USB.dll"


def crc8(data, crc=0):
    for b in data:
        crc = CRC8_TABLE[crc ^ b]
    return crc


def expand(b):
    """Each byte -> two wire bytes, high nibble first."""
    out = bytearray()
    for x in b:
        out.append(x >> 4)
        out.append(x & 0x0F)
    return bytes(out)


def collapse(b):
    return bytes((b[i] << 4) | b[i + 1] for i in range(0, len(b) - 1, 2))


def frame(count, index, type_byte, payload=b""):
    body = bytearray([0, count & 0xFF, index & 0xFF, type_byte & 0xFF])
    body += bytearray(payload)
    body[0] = crc8(body[1:])
    return b"\xF0" + expand(bytes(body)) + b"\xF7"


def chunk_size(type_byte):
    """cmove at 0x180095061: 0x2A when the type byte is zero, else 0x13."""
    return 42 if type_byte == 0 else 19


def terminator():
    """What sub_180095010 returns at end of transfer: a bare F0 F7."""
    return b"\xF0\xF7"


def parse(msg):
    if not msg or msg[0] != 0xF0 or msg[-1] != 0xF7:
        return None
    body = collapse(msg[1:-1])
    if len(body) < 4:
        return None
    return {
        "crc_ok": crc8(body[1:]) == body[0],
        "crc": body[0],
        "crc_calc": crc8(body[1:]),
        "count": body[1],
        "index": body[2],
        "type": body[3],
        "payload": body[4:],
        "len": len(body) - 4,
    }


def main(argv):
    if not argv:
        print("usage: sxproto.py HEXFRAME [HEXFRAME ...]", file=sys.stderr)
        print("       echo f0....f7 | sxproto.py -", file=sys.stderr)
        return 2
    lines = sys.stdin.read().splitlines() if argv == ["-"] else argv
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            p = parse(bytes.fromhex(line))
        except ValueError:
            print("not hex: %s" % line[:64])
            continue
        if p is None:
            print("not a framed SysEx: %s" % line[:64])
            continue
        print("crc=%s count=%3d index=%3d type=%#04x len=%3d %s" % (
            "ok " if p["crc_ok"] else "BAD", p["count"], p["index"],
            p["type"], p["len"], binascii.hexlify(p["payload"][:24]).decode()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
