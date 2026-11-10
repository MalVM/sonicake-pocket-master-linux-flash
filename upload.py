#!/usr/bin/env python3
"""Upload a firmware image to a 5868USB device using the recovered protocol.

DANGEROUS BY DESIGN GUARD: dry run unless --i-understand-the-risk is given.
The frame format, CRC, chunking and state machine are recovered from the DLL.
Two things are NOT known: which type byte marks a firmware image, and what the
device replies with (there is no ACK handling here - this paces blindly).
"""
import argparse
import sys
import time

import htfw
import sxproto


def announce(payload, type_byte, entry_id, flags):
    """sub_180092b70: 11 61 <flags> 00 00 00 <u32 entry+0x18> <u32 size>."""
    ann = bytes([0x11, 0x61, flags & 0xFF, 0, 0, 0])
    ann += entry_id.to_bytes(4, "little")
    ann += len(payload).to_bytes(4, "little")
    return sxproto.frame(1, 0, type_byte, ann)


def sequence(payload, type_byte, entry_id=0, flags=0, block=255):
    seq = [announce(payload, type_byte, entry_id, flags)]
    cs = sxproto.chunk_size(type_byte)
    idx = 0
    for off in range(0, len(payload), cs):
        if idx == block:
            idx = 0
        seq.append(sxproto.frame(0xFF, idx, type_byte, payload[off:off + cs]))
        idx += 1
    seq.append(sxproto.terminator())
    seq.append(sxproto.frame(1, 0, type_byte, b"\x6e\x00"))  # sub_180091a00
    return seq


def usb_packetise(sysex):
    """SysEx -> USB-MIDI 1.0 4-byte event packets."""
    out = bytearray()
    i = 0
    while i < len(sysex):
        c = sysex[i:i + 3]
        cin = 0x04 if len(c) == 3 else (0x06 if len(c) == 2 else 0x05)
        out += bytes([cin]) + c + b"\0" * (3 - len(c))
        i += 3
    return bytes(out)


def open_alsa(port):
    import rtmidi
    out = rtmidi.MidiOut()
    ports = out.get_ports()
    if isinstance(port, int):
        out.open_port(port)
    else:
        if port not in ports:
            sys.exit("port %r not found; available: %r" % (port, ports))
        out.open_port(ports.index(port))
    return lambda msg: out.send_message(list(msg))


def open_usb(vid, pid):
    import usb.core
    import usb.util
    dev = usb.core.find(idVendor=vid, idProduct=pid)
    if dev is None:
        sys.exit("device %04x:%04x not found" % (vid, pid))
    intf = ep = None
    for cfg in dev:
        for i in cfg:
            if i.bInterfaceClass == 0xFF:
                intf = i
                ep = next(e for e in i if not (e.bEndpointAddress & 0x80))
    if intf is None:
        sys.exit("no vendor-specific interface; the device is probably MIDI class "
                 "-> use --transport alsa instead")
    try:
        dev.detach_kernel_driver(intf.bInterfaceNumber)
    except Exception:
        pass
    usb.util.claim_interface(dev, intf.bInterfaceNumber)
    return lambda msg: dev.write(ep.bEndpointAddress, usb_packetise(msg), timeout=2000)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("firmware")
    ap.add_argument("--type", type=lambda s: int(s, 0), default=0,
                    help="type byte (UNKNOWN for firmware; 0 selects 42-byte chunks)")
    ap.add_argument("--entry-id", type=lambda s: int(s, 0), default=0,
                    help="u32 at entry+0x18 (UNKNOWN meaning)")
    ap.add_argument("--flags", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--transport", choices=["none", "alsa", "usb"], default="none")
    ap.add_argument("--port", default=None)
    ap.add_argument("--vid", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--pid", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--pace", type=float, default=0.002)
    ap.add_argument("--confirm-model", default=None)
    ap.add_argument("--i-understand-the-risk", action="store_true")
    a = ap.parse_args()

    raw = open(a.firmware, "rb").read()
    if raw[:4] == b"HTFW":
        fw = htfw.parse(a.firmware)
        print("HTFW: model %r, container claims v%s, %d B payload (%d B trailer dropped)"
              % (fw["model"], fw["version"], len(fw["payload"]), len(fw["trailer"])),
              file=sys.stderr)
        for w in fw["warnings"]:
            print("  WARNING: %s" % w, file=sys.stderr)
        if a.confirm_model and not htfw.check_model(fw, a.confirm_model):
            sys.exit("refusing: model %r != %r" % (fw["model"], a.confirm_model))
        payload = fw["payload"]
    else:
        if a.confirm_model:
            print("note: bare image, model check not possible", file=sys.stderr)
        payload = raw

    seq = sequence(payload, a.type, a.entry_id, a.flags)
    print("%d frames, %d wire bytes, %d B payload, %d B chunks"
          % (len(seq), sum(len(f) for f in seq), len(payload),
             sxproto.chunk_size(a.type)))

    if a.transport == "none" or not a.i_understand_the_risk:
        for i, f in enumerate(seq[:5]):
            print("  %4d %3dB %s" % (i, len(f), f.hex()))
        print("  ...")
        print("  %4d %3dB %s" % (len(seq) - 1, len(seq[-1]), seq[-1].hex()))
        print("dry run: nothing sent")
        return 0

    if a.transport == "alsa":
        send = open_alsa(a.port if isinstance(a.port, int) else a.port)
    else:
        if a.vid is None or a.pid is None:
            sys.exit("--vid and --pid are required for the usb transport")
        send = open_usb(a.vid, a.pid)

    t0 = time.time()
    for i, f in enumerate(seq):
        send(f)
        if a.pace:
            time.sleep(a.pace)
        if i % 500 == 0:
            print("  %d/%d (%.1fs)" % (i, len(seq), time.time() - t0), file=sys.stderr)
    print("done in %.1fs" % (time.time() - t0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
