# sonicake-flash

Unofficial Linux tools to inspect and flash **Sonicake Pocket Master** HTFW
firmware over the pedal's MIDI SysEx protocol, recovered from `5868USB.dll`.

> **WARNING:** Experimental. Flashing the wrong image, or interrupting an
> upload, can brick the pedal. Use at your own risk and keep the stock firmware
> plus the official Sonicake Manager as a fallback.

## Files

| file | purpose |
|---|---|
| `htfw.py` | Parse an HTFW container (header, segment table, payload). |
| `sxproto.py` | Encode/decode the 5868USB SysEx frames (CRC-8, nibble expansion). |
| `upload.py` | ACK-paced multi-segment uploader; dry-runs by default. |
| `flash-firmware.sh` | Wrapper around `upload.py` using the rawmidi transport. |
| `sonicake-flash.md` | Full protocol/container reference and findings. |
| `probe.py` | Dump USB descriptors. |

## Requirements

- Linux with ALSA rawmidi (the pedal is a USB-MIDI device, `84ef:0285`).
- `uv` (or Python 3.10+) and membership in the `audio` group.
- The pedal must be **manually put into update mode** first.

## Enter update mode

Hold the **1st and 2nd footswitch** and the **VOL/VALUE knob** at the same time,
then power on and keep holding until the screen lights up. Connect USB after
that.

## Usage

Inspect a firmware file (no device access):

```sh
python3 htfw.py ~/Downloads/PocketMaster_CFW0.9.8_base1.3.3.bin
```

Dry run — shows the frame plan and sends nothing:

```sh
uv run --with python-rtmidi python upload.py FIRMWARE.bin
```

Probe — sends only the init frame and prints replies (confirms update mode):

```sh
uv run --with python-rtmidi python upload.py FIRMWARE.bin \
    --transport rawmidi --probe --timeout 5 --i-understand-the-risk
```

Flash:

```sh
./flash-firmware.sh FIRMWARE.bin
# or: uv run --with python-rtmidi python upload.py FIRMWARE.bin \
#       --transport rawmidi --i-understand-the-risk
```

The rawmidi node is auto-detected (`/dev/snd/midiC2D0`); override with
`--rawmidi /dev/snd/midiCxDy` if needed.

## Notes

- Use the **rawmidi** transport. `rtmidi` input does not receive the pedal's
  ACK frames.
- The upload is ACK-paced and long (~112k frames for a full image); keep the
  pedal powered and connected.
- Status: the container, frame format, and init ACK are verified on hardware;
  the full multi-segment upload has not yet been completed.
- See `sonicake-flash.md` for the protocol details and current caveats.
