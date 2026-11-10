#!/usr/bin/env bash
# Flash firmware to Sonicake Pocket Master (0x84ef:0x0285)
# Uses ALSA transport (MIDI class 01/03) as determined by probe.py
# Runs via 'uv run --with python-rtmidi python'

set -euo pipefail

# Check arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <firmware.bin> [alsa_port]" >&2
    echo "  firmware.bin: path to HTFW or raw firmware file" >&2
    echo "  alsa_port:   optional ALSA MIDI port name (default: auto-detect)" >&2
    exit 1
fi

FIRMWARE="$1"
ALSA_PORT="${2:-}"

# Verify firmware file exists
if [ ! -f "$FIRMWARE" ]; then
    echo "Error: firmware file not found: $FIRMWARE" >&2
    exit 1
fi

# If no ALSA port specified, try to auto-detect
if [ -z "$ALSA_PORT" ]; then
    # Parse aconnect -l output for Pocket Master
    # Format:
    #   client 24: 'Pocket Master' [type=kernel,card=2]
    #   0 'Pocket Master MIDI 1'
    # rtmidi expects: 'Pocket Master:Pocket Master MIDI 1 24:0'
    
    # Extract client line: "client 24: 'Pocket Master' [type=kernel,card=2]"
    CLIENT_LINE=$(aconnect -l 2>/dev/null | sed -n '/Pocket Master/p' | head -1)
    # Extract client name (first quoted field, non-greedy)
    CLIENT_NAME=$(echo "$CLIENT_LINE" | sed "s/^[^']*'\([^']*\)'.*/\1/")
    # Extract client number (e.g., 24 from "client 24:")
    CLIENT_NUM=$(echo "$CLIENT_LINE" | grep -o 'client [0-9]*' | grep -o '[0-9]*')
    # Extract port line: "    0 'Pocket Master MIDI 1'"
    PORT_LINE=$(aconnect -l 2>/dev/null | sed -n '/Pocket Master/,/^$/{n;p}' | head -1)
    # Extract port name (first quoted field, non-greedy)
    PORT_NAME=$(echo "$PORT_LINE" | sed "s/^[^']*'\([^']*\)'.*/\1/")
    
    if [ -n "$CLIENT_NAME" ] && [ -n "$CLIENT_NUM" ] && [ -n "$PORT_NAME" ]; then
        # Construct rtmidi port name: "ClientName:PortName ClientNum:PortNum"
        ALSA_PORT="${CLIENT_NAME}:${PORT_NAME} ${CLIENT_NUM}:0"
        echo "Auto-detected ALSA port: $ALSA_PORT"
    else
        echo "Warning: Could not auto-detect ALSA port." >&2
        aconnect -l 2>/dev/null | grep "Pocket Master" || true
        exit 1
    fi
fi

# Run the upload using uv run python with rtmidi dependency
exec uv run --with python-rtmidi python /home/miguel/sonicake-flash/upload.py "$FIRMWARE" \
    --transport alsa \
    --port "$ALSA_PORT" \
    --i-understand-the-risk