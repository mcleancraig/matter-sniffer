#!/usr/bin/env bash
set -euo pipefail

ESPRESSIF_DIR="$HOME/.espressif"
IDF_PATH="$ESPRESSIF_DIR/v6.0/esp-idf"
PYTHON="$ESPRESSIF_DIR/tools/python/v6.0/venv/bin/python"
FIRMWARE_DIR="$(cd "$(dirname "$0")/firmware" && pwd)"

if [ ! -f "$PYTHON" ]; then
    echo "Error: Python venv not found at $PYTHON"
    exit 1
fi
if [ ! -d "$IDF_PATH" ]; then
    echo "Error: ESP-IDF not found at $IDF_PATH"
    exit 1
fi

export IDF_PATH
export IDF_TOOLS_PATH="$ESPRESSIF_DIR/tools"
export IDF_PYTHON_ENV_PATH="$ESPRESSIF_DIR/tools/python/v6.0/venv"
export ESP_IDF_VERSION="6.0.0"
export IDF_COMPONENT_LOCAL_STORAGE_URL="file://$ESPRESSIF_DIR/tools"

_find_tool_ver() { ls "$ESPRESSIF_DIR/tools/$1" 2>/dev/null | sort -V | tail -1; }
XTENSA_VER=$(_find_tool_ver "xtensa-esp-elf")
NINJA_VER=$(_find_tool_ver "ninja")

export PATH="$ESPRESSIF_DIR/tools/xtensa-esp-elf/$XTENSA_VER/xtensa-esp-elf/bin:$ESPRESSIF_DIR/tools/ninja/$NINJA_VER:$IDF_PATH/tools:$PATH"

idf() { "$PYTHON" "$IDF_PATH/tools/idf.py" -C "$FIRMWARE_DIR" "$@"; }

TARGET="${IDF_TARGET:-esp32s3}"
CMD="${1:-build}"

case "$CMD" in
    build)
        echo "Building for $TARGET..."
        idf set-target "$TARGET"
        idf build
        echo ""
        echo "Build complete: firmware/build/matter_sniffer.bin"
        ;;
    flash)
        PORT="${2:-$(ls /dev/tty.usbmodem* /dev/ttyUSB* 2>/dev/null | head -1)}"
        echo "Flashing to $PORT"
        idf -p "$PORT" flash
        ;;
    monitor)
        PORT="${2:-$(ls /dev/tty.usbmodem* /dev/ttyUSB* 2>/dev/null | head -1)}"
        echo "Monitoring $PORT — Ctrl-C to exit"
        "$PYTHON" -m serial.tools.miniterm --exit-char 3 --eol LF "$PORT" 115200
        ;;
    flash-monitor)
        PORT="${2:-$(ls /dev/tty.usbmodem* /dev/ttyUSB* 2>/dev/null | head -1)}"
        echo "Flashing and monitoring on $PORT — Ctrl-C to exit monitor"
        idf -p "$PORT" flash
        "$PYTHON" -m serial.tools.miniterm --exit-char 3 --eol LF "$PORT" 115200
        ;;
    menuconfig)
        idf menuconfig
        ;;
    clean)
        rm -rf "$FIRMWARE_DIR/build"
        echo "Build directory cleaned"
        ;;
    *)
        echo "Usage: $0 [build|flash [port]|monitor [port]|flash-monitor [port]|menuconfig|clean]"
        exit 1
        ;;
esac
