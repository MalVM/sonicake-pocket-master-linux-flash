# Sonicake HTFW container + 5868USB wire protocol — validated on three images

Static analysis of `5868USB.dll` (MSVC x64, 2,437,120 B). Header layout confirmed by
reading the DLL's own reader, not by guessing from samples.

## 1. The header, as the DLL actually reads it

`sub_180092eb0` reads the 56-byte header through a stream object; `sub_180092640`
(`isRealFirmware`) validates it. The read sequence, exactly:

| offset | read as | field | in `isRealFirmware`? |
|---|---|---|---|
| `0x00` | u32 LE | magic, compared to `0x57465448` (`HTFW`) | **yes** — else tag `FirmwareFileType` |
| `0x04` | u16 | unknown, varies per image | stored, never compared |
| `0x06` | u16 | `1` in every image seen | stored, never compared |
| `0x08` | u32 | equals file length in both images | stored, never compared |
| `0x0C` | 16 B | model, NUL-padded | **yes** — via `sub_18010fda0`, tag `equalsIgnoreCase` |
| `0x1C` | 4 B **as one value** | `0x56` + three version bytes | stored |
| `0x20` | 1 B | `0x00` | stored |
| `0x21` | 1 B | `0x05` | stored |
| `0x22` | 1 B | `0x00` | stored |
| `0x23` | u32 | payload length | stored, never compared |
| `0x27` | 1 B | `0` | stored |
| `0x28` | 16 B | digest slot, all zero | stored |

**So the only things the DLL checks are the magic and the model string.** Size, `0x04`,
`0x23` and the digest slot are all carried and ignored. Field `0x04` therefore does *not*
gate an upload from the app's side — whether the *device* checks it cannot be seen here.
(The failure tags double as documentation: `FirmwareFileType` for a bad magic,
`equalsIgnoreCase` for the model compare — so the model match is case-insensitive.)

## 2. Test result on three images

| field | stock V1.3.3 | CFW0.9.8_base1.3.3 | same? |
|---|---|---|---|
| file size | 2,056,820 | 2,125,752 | — |
| `0x00` | `HTFW` | `HTFW` | yes |
| `0x04` | `0xAC24` | `0x342B` | **no** |
| `0x06` | `1` | `1` | yes |
| `0x08` | = file size | = file size | yes |
| `0x0C` | `Pocket Master` | `Pocket Master` | yes |
| `0x1C` | `0x56` | `0x56` | yes |
| version | 1.3.3 | **1.3.3** (file is named 0.9.8) | — |
| `0x23` | 2,056,684 | 2,125,616 | scales |
| **file − `0x23`** | **136** | **136** | **yes** |
| trailer at `0x38+0x23` | `0x1F6224`, 80 B `0xFF` | `0x206F68`, 80 B `0xFF` | yes |

`0x23` = file size − 136 in both: **payload length, followed by a fixed 80-byte all-`0xFF`
trailer.** The previous `htfw.py` used `b[0x38:]` and would have sent 80 bytes too many.

Payload: uncompressed in both (CFW entropy mean 5.59, 0 regions recognised).

## 3. What the CFW tells you

- **The container lies about provenance.** `0x1C..0x1F` says 1.3.3 on a file named
  `CFW0.9.8`. A parser can report "claims 1.3.3", never "is 1.3.3".
- **`V132` at file offset `0x90` is a constant** — it is at the identical offset in the
  stock image. Not a version marker.
- **The preludes are structurally identical**: 5 × 16-byte records with identical
  constant words (`0x00200000`, `0x00240000`, `0x00280000`, `0x00001900`, `0x0003D000`,
  a zero word), then `8 × 0xFF`, then `V132\0D\0`, differing only in their
  address/length/checksum-class fields. That makes the CFW a plausible 1.3.3 derivative
  **and** says the payload is a multi-segment image, not a flat blob (layout undecoded).
  Send it verbatim; never relocate or "fix" addresses.
- `0x04` varying while `0x06` stays `1` confirms they are two separate u16s, matching the
  reader. `0x04` is content-derived; since nothing in the DLL compares it, it is most
  likely for the device or the updater UI. Unknown algorithm.

## 4. Frame format (5868USB wire)

```
F0 | exp([crc8][count][index][type] ++ payload) | F7
exp: each byte -> (x>>4), (x&0x0F)      // high nibble first
```

Encoder `sub_180095210`, receiver `sub_18008fca0`. **CRC-8 poly 0x07, init 0**, table at
`0x18013a400` = `00 07 0e 09 1c 1b 12 15 38 3f…`, used by both. `crc` = CRC over bytes
1..end; `count` = packets or `0xFF` while streaming; `index` 0-based; `type` per-file.

Chunking (`sub_180095010`, `cmove` at `0x180095061`): **42 B** if type is 0, **19 B**
otherwise; `count = ceil(len/chunk)`, `index = offset/chunk`; terminator `F0 F7`.
Wire `1 + 2*(4+chunk) + 1` = 94 or 48 B.

Transport `sub_18003f420` = JUCE `sendMessageNow`: one blocking `midiOutLongMsg` per
frame, poll `MHDR_DONE`, no internal splitting.

## 5. Upload state machine (`sub_180092850`, 9,000-tick timeout)

1. **announce** (`sub_180092b70`): `11 61 <flags> 00 00 00 <u32 entry+0x18> <u32 size>`, count=1, index=0
2. **stream**: raw bytes, count pinned at `0xFF`, index incrementing
3. **next file or commit** `6E 00` (`sub_180091a00`), state 4 `all finish`

Unknown: which type byte means "firmware"; what `entry+0x18` is.

## 6. `htfw.py`

```python
#!/usr/bin/env python3
"""HTFW container parser. Layout per 5868USB.dll sub_180092eb0 (reader) and
sub_180092640 (isRealFirmware: checks magic + model only)."""
import struct, hashlib, sys, json

MAGIC, HDR_LEN, TRAILER_LEN = b"HTFW", 0x38, 80

def parse(path):
    b = open(path, "rb").read()
    if len(b) < HDR_LEN or b[:4] != MAGIC:
        raise ValueError(f"{path}: not an HTFW container")
    u32 = lambda o: struct.unpack_from("<I", b, o)[0]
    u16 = lambda o: struct.unpack_from("<H", b, o)[0]
    f = {
        "magic":       b[0:4].decode(),
        "u04":         u16(0x04),   # varies per image; nothing in the DLL compares it
        "u06":         u16(0x06),   # 1 everywhere seen
        "image_size":  u32(0x08),   # == file length in both known images
        "model":       b[0x0C:0x1C].split(b"\0")[0].decode("ascii", "replace"),
        "b1C":         b[0x1C],     # 0x56 everywhere seen
        "version":     "%d.%d.%d" % (b[0x1D], b[0x1E], b[0x1F]),
        "b20_22":      list(b[0x20:0x23]),
        "payload_len": u32(0x23),   # file_size - 136 in both known images
        "b27":         b[0x27],
        "digest_slot": b[0x28:0x38].hex(),
        "file_size":   len(b),
    }
    f["payload"] = b[HDR_LEN:HDR_LEN + f["payload_len"]]
    f["trailer"] = b[HDR_LEN + f["payload_len"]:]
    f["payload_sha256"] = hashlib.sha256(f["payload"]).hexdigest()
    w = f["warnings"] = []
    if f["image_size"] != f["file_size"]:
        w.append("0x08 != file length")
    if len(f["trailer"]) != TRAILER_LEN:
        w.append(f"trailer {len(f['trailer'])} B, expected {TRAILER_LEN}")
    elif f["trailer"].count(0xFF) != TRAILER_LEN:
        w.append("trailer not all 0xFF")
    if f["u06"] != 1:      w.append(f"u06={f['u06']}, expected 1")
    if f["b1C"] != 0x56:   w.append(f"0x1C={f['b1C']:#x}, expected 0x56")
    return f

def check_model(f, expected):
    """Mirror isRealFirmware: magic + case-insensitive model compare."""
    return f["model"].lower() == expected.lower()

if __name__ == "__main__":
    for p in sys.argv[1:]:
        f = parse(p)
        print(p)
        print(json.dumps({k: v for k, v in f.items()
                          if k not in ("payload", "trailer")}, indent=2))
        for x in f["warnings"]:
            print("  WARNING:", x, file=sys.stderr)
```

## 7. `upload.py` — the fix

```python
    payload = open(a.firmware, "rb").read()
    if payload[:4] == b"HTFW":
        fw = htfw.parse(a.firmware)
        payload = fw["payload"]          # payload_len bytes; 80-byte trailer dropped
        print(f"HTFW {fw['model']} claims v{fw['version']}: sending {len(payload)} B",
              file=sys.stderr)
```

## 8. Before flashing

- **Rate**: 2,125,616 B at 42 B/frame = 50,610 frames ≈ 4.8 MB at MIDI rate → 20+ min,
  against a 9,000-tick device timeout. The app must be ACKing per block; `upload.py`
  paces blindly. First run on a small file.
- `0x04` is unvalidated by the DLL but may be checked by the device. An image identical
  to what the vendor shipped is safe; a *modified* one is a risk.
- Keep the previous firmware and the Wine app as fallback.

## 9. Open items

1. Decompile `sub_18008fa80` (the `>0x13` receive handler) for an erase/boot byte.
2. One decoded capture: type byte, `entry+0x18`, chunk-reset rule, ACK behaviour.
3. `0x04`: test CRC-16 variants against the two known images.
4. `probe.py` in both device modes: MIDI class (`01/03`) vs vendor (`ff`).
