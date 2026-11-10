#!/usr/bin/env bash
# Flash firmware to Sonicake Pocket Master (0x84ef:0x0285).
#
# The pedal must first be put into update mode manually: hold the 1st and 2nd
# footswitch and the VOL/VALUE knob while powering on, until the screen lights.
#
# Uses rawmidi: rtmidi input does not receive the device's ACK frames.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <firmware.bin> [rawmidi_node]" >&2
    echo "  rawmidi_node: optional, e.g. /dev/snd/midiC2D0 (default: auto-detect)" >&2
    exit 1
fi

FIRMWARE="$1"
RAW="${2:-}"

if [ ! -f "$FIRMWARE" ]; then
    echo "Error: firmware file not found: $FIRMWARE" >&2
    exit 1
fi

ARGS=(--transport rawmidi --i-understand-the-risk)
if [ -n "$RAW" ]; then
    ARGS+=(--rawmidi "$RAW")
fi

exec uv run --with python-rtmidi python ~/sonicake-pocket-master-linux-flash/upload.py \
    "$FIRMWARE" "${ARGS[@]}"
