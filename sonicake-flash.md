# Sonicake Pocket Master — HTFW container + 5868USB wire protocol

Recovered from `5868USB.dll` (MSVC x64, 2,437,120 B, ImageBase `0x180000000`) and
validated on hardware. This supersedes the earlier draft: the container has a
segment table (not a flat payload + 80-byte trailer), the third body byte is a
payload **length** (not a type), and the device **ACKs** each frame.

## 0. Status

- Container parser: `htfw.py` — header + segment table, no trailer.
- Codec: `sxproto.py` — nibble expand/collapse, CRC-8 poly 0x07.
- Uploader: `upload.py` — rawmidi transport, ACK-paced, multi-segment.
- Dry run of `PocketMaster_CFW0.9.8_base1.3.3.bin`: **5 segments, 2,125,616 B,
  111,890 frames, 5,370,344 wire bytes, 19 B chunks.**
- Hardware: the init frame gets a **valid ACK** over rawmidi. rtmidi input does
  not receive; use rawmidi (`/dev/snd/midiC2D0`) or `amidi`.

## 1. Entering update mode

There is **no working software "enter bootloader"**:

- export `deviceStartBoot` (`0x94550`) is `mov eax,-1; ret`;
- export `deviceStartUpdate` (`0x94530`) is a thunk to the upload setup at
  `0x8f5b0`.

The Flutter UI tells the user:

> Press and hold the 1st and 2nd footswitch and the VOL/VALUE knob at the same
> time and turn on the device until the screen lights up to enter the update
> mode.

So the button combo is mandatory; then connect USB and start the update.

## 2. Transport

- USB `84ef:0285`, interface class `0x01` subclass `0x03` (MIDI streaming).
  `snd-usb-audio` owns it; do **not** use libusb.
- ALSA card 2: `hw:2,0,0`, `/dev/snd/midiC2D0`, port `Pocket Master MIDI 1`.
- **Use rawmidi with two fds**: one `O_RDONLY|O_NONBLOCK` for input and one
  `O_WRONLY|O_NONBLOCK` for output. A single `O_RDWR` fd wrote but never read.
- **rtmidi input never received device data**; only rawmidi / `amidi` did.
- Frames are ordinary SysEx: `F0 ... F7`, one frame per write/read.

## 3. HTFW container (as read by `0x92eb0`)

Header is `0x38` B, then `count` 16-byte segment records, then the data region.

| file offset | size | meaning |
|---|---|---|
| `0x00` | 4 | magic `HTFW` (`0x57465448`) |
| `0x04` | u16 | varies (`0x342b` in CFW) |
| `0x06` | u16 | `1` |
| `0x08` | u32 | file length |
| `0x0c` | 16 | model, NUL-padded (`Pocket Master`) |
| `0x1c` | u32 | `0x56` + version bytes (`56 01 03 03` = 1.3.3) |
| `0x20` | u8 | `0` |
| `0x21` | u8 | `0` |
| `0x22` | u8 | **segment count** (`5`) |
| `0x23` | u8 | `0` |
| `0x24` | u32 | **payload length** (`0x206f30`) |
| `0x28` | 16 | digest slot, zero |

The reader reorders a few bytes into its struct: `struct+0x22 = file[0x27]`,
`struct+0x23 = file[0x22]` (count), `struct+0x24 = u32 at file[0x23:0x27]`
(a misaligned read, unused). The authoritative count is **`file[0x22]`**.

`isRealFirmware` (`0x92640`) checks only the magic and the model string
(case-insensitive). Everything else is carried and ignored by the DLL.

### Segment record (16 B at `0x38 + i*0x10`)

| off | type | meaning |
|---|---|---|
| `0x0` | u16 | per-segment checksum (copied, not used by the host) |
| `0x2` | u8 | `0` |
| `0x3` | u8 | **flags** (`0x62`..`0x67`) |
| `0x4` | u32 | target address |
| `0x8` | u32 | offset into the data region |
| `0xc` | u32 | length |

Data region starts at `0x38 + count*16 = 0x88`. **Payload = `file[0x88:EOF]`;
there is no trailer.** For the CFW:

| # | flags | addr | dataoff | length |
|---|---|---|---|---|
| 0 | `0x63` | `0x00200000` | `0x000000` | 61424 |
| 1 | `0x67` | `0x00240000` | `0x00eff0` | 303088 |
| 2 | `0x66` | `0x00280000` | `0x058fe0` | 36864 |
| 3 | `0x62` | `0x00000000` | `0x061fe0` | 1474384 |
| 4 | `0x65` | `0x00190000` | `0x1c9f30` | 249856 |

Sum = 2,125,616 = `0x206f30` = file size − `0x88`.

## 4. Wire frame

```
F0 | exp([crc8][count][index][blen] ++ payload) | F7
exp: each byte -> (x>>4), (x&0x0F)      # high nibble first
```

- CRC-8 poly `0x07`, init `0`, over bytes 1..end (table at `0x13a400`).
- `blen` is the payload **length**, not a type.
- Encoder `0x95210`; receiver `0x8fca0`; collapse is `(b[i]<<4)|b[i+1]` with
  **no masking**.
- Chunk size (`0x95010`): **19 B** when expanded (firmware), **42 B** when raw.
- Host sends expanded frames; the device's replies are also expanded.

## 5. Entry builder (`0x92240`)

For each segment record it builds an entry:

- `+0x00` = rec u16; `+0x02` = rec u8@2; `+0x03` = flags; `+0x04` = addr;
  `+0x08` = dataoff; `+0x0c` = length.
- `+0x20` = buffer `11 <flags> <segment data>` (2 + length bytes).
- `+0x2c` = 2 + length.
- `+0x18` = `ceil((2+length)/chunk)` (chunk 19).
- `+0x30` = 1 (hardcoded).

The per-segment checksum is computed but not used on the wire.

## 6. Upload state machine (`0x92850`)

`state+0xc0`: 0 init, 1 announce, 2 stream, 3 next-segment/commit, 4 done.
Each acknowledged frame sets `state+0xc4=1`; the machine waits (9000 ticks).

1. **init** `11 60`, count=1 index=0 → ACK.
2. For each segment:
   - **announce** `11 61 <flags> 00 00 00 <frame_count u32> <size u32>`
     (count=1 index=0; `size = 2+length`; `frame_count = ceil(size/19)`) → ACK.
   - **stream** each 19-byte chunk as count=`0xFF`, index=`j & 0xFF` → ACK each.
   - **segment end** `11 6e <flags> 00` (count=1 index=0) → ACK.
3. **commit** `11 6e 6e 00` (count=1 index=0) — fire-and-forget, **no ACK**.

Verified frames for the CFW:

```
init     wire F0 0D 01 00 01 00 00 00 02 01 01 06 00 F7
         raw  D1 01 00 02 11 60
announce wire F0 0A 0C 00 01 00 00 00 0E 01 01 06 01 06 03 00 00 00 00 00 00
             0A 01 00 0C 00 00 00 00 0F 02 0E 0F 00 00 00 00 F7
         raw  AC 01 00 0E 11 61 63 00 00 00 A1 0C 00 00 F2 EF 00 00
              (frame_count 0x0CA1 = 3233, size 0xEFF2 = 61426)
chunk 0  raw  C2 FF 00 13 11 63 FF ... 56 31 33 32 00 44 00 00 00  ("V132")
seg-end  raw  7C 01 00 04 11 6E 65 00
commit   raw  EB 01 00 04 11 6E 6E 00
```

## 7. Replies / ACK format

Receiver `0x8fca0` parses `[crc][count][index][blen][payload...]`, drops CRC
failures, and dispatches on `payload[0]`:

- `0x13` / `0x14` → ACK handler `0x8f880`. The status is the first byte of the
  reassembled message body, which for a single frame is `payload[2]`.
  `0` = OK, nonzero = error.
- anything else → progress handler `0x8fa80` (uses `payload[1]`, calls the app's
  progress callback).

Empirically verified init ACK over rawmidi:

```
raw:      F0 0B 02 00 01 00 00 00 03 01 04 00 08 00 00 F7
collapse: B2 01 00 03 14 08 00
payload:  14 08 00      -> ACK type 0x14, status 0
```

An earlier capture had `0x34` in the `0x04` position; that collapses to
`... 34 ...` and fails CRC, so it was a non-ACK (normal-mode) reply and is
correctly dropped.

## 8. Tools

- `htfw.py FILE` — parse header + segment table; prints version, segments,
  warnings.
- `sxproto.py HEXFRAME...` — decode frames; also exposes `frame()` / `parse()`.
- `upload.py FILE --transport rawmidi [--probe] --i-understand-the-risk` —
  dry-runs by default; `--probe` sends only init and prints replies; otherwise
  sends the full ACK-paced sequence.
- `flash-firmware.sh` — convenience wrapper (always passes the risk flag).

Dry run:

```
HTFW 'Pocket Master' v1.3.3: 5 segments, 2125616 B payload,
111890 frames, 5370344 wire bytes, 19 B chunks
```

## 9. Cautions / open items

- Do not flash a modified image: the device may check fields the DLL does not
  (notably `0x04`).
- The upload is long (~112k ACKed frames). Keep the device powered and USB
  connected; a mid-upload abort can leave it unbootable.
- The init ACK is confirmed on hardware; the announce/stream ACKs are inferred
  from the state machine and should be confirmed by watching the first segment.
- The old notes' "`0x23` = payload length" and "80-byte trailer" are wrong; use
  `count @ 0x22` and `payload = file[0x88:]`.
