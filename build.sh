#!/usr/bin/env bash
set -e

ESPRESSIF_DIR="$HOME/.espressif"
IDF_PATH="$ESPRESSIF_DIR/v6.0/esp-idf"
PYTHON="$ESPRESSIF_DIR/tools/python/v6.0/venv/bin/python"
FIRMWARE_DIR="$(cd "$(dirname "$0")/firmware" && pwd)"

if [ ! -d "$IDF_PATH" ]; then
    echo "ESP-IDF not found at $IDF_PATH"
    exit 1
fi

# Activate environment
source "$ESPRESSIF_DIR/tools/activate_idf_v6.0.sh" > /dev/null 2>&1 || true

export IDF_PATH
export IDF_TOOLS_PATH="$ESPRESSIF_DIR/tools"
export IDF_PYTHON_ENV_PATH="$ESPRESSIF_DIR/tools/python/v6.0/venv"
export ESP_IDF_VERSION="6.0.0"
export IDF_COMPONENT_LOCAL_STORAGE_URL="file://$ESPRESSIF_DIR/tools"

# Prepend tool paths
TOOL_BIN="$ESPRESSIF_DIR/tools/xtensa-esp-elf/$(ls $ESPRESSIF_DIR/tools/xtensa-esp-elf 2>/dev/null | head -1)/xtensa-esp-elf/bin"
export PATH="$TOOL_BIN:$ESPRESSIF_DIR/tools/ninja/$(ls $ESPRESSIF_DIR/tools/ninja 2>/dev/null | head -1):$IDF_PATH/tools:$PATH"

IDF="$PYTHON $IDF_PATH/tools/idf.py"
TARGET="${IDF_TARGET:-esp32s3}"

CMD="${1:-build}"

case "$CMD" in
    build)
        echo "Building for $TARGET..."
        $IDF -C "$FIRMWARE_DIR" set-target "$TARGET"
        $IDF -C "$FIRMWARE_DIR" build
        echo ""
        echo "Build complete: firmware/build/matter_sniffer.bin"
        ;;
    flash)
        PORT="${2:-}"
        if [ -z "$PORT" ]; then
            PORT=$(ls /dev/tty.usbmodem* /dev/ttyUSB* 2>/dev/null | head -1)
            echo "Auto-detected port: $PORT"
        fi
        $IDF -C "$FIRMWARE_DIR" -p "$PORT" flash
        ;;
    monitor)
        PORT="${2:-}"
        if [ -z "$PORT" ]; then
            PORT=$(ls /dev/tty.usbmodem* /dev/ttyUSB* 2>/dev/null | head -1)
        fi
        $IDF -C "$FIRMWARE_DIR" -p "$PORT" monitor
        ;;
    flash-monitor)
        PORT="${2:-}"
        if [ -z "$PORT" ]; then
            PORT=$(ls /dev/tty.usbmodem* /dev/ttyUSB* 2>/dev/null | head -1)
            echo "Auto-detected port: $PORT"
        fi
        $IDF -C "$FIRMWARE_DIR" -p "$PORT" flash monitor
        ;;
    menuconfig)
        $IDF -C "$FIRMWARE_DIR" menuconfig
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
