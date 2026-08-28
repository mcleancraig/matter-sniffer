#!/usr/bin/env python3
"""
matter-sniffer pcap capture tool

Reads framed pcap data from the ESP32 USB serial port and either:
  - writes to a .pcap file  (--out capture.pcap)
  - pipes to Wireshark live  (--wireshark)
  - prints summary stats     (--stats, default)

Frame envelope: 0xFE 0xFE <len_hi> <len_lo> <pcap_bytes...>
Log text from the device (anything outside envelope) is printed to stderr.

Usage:
    python pcap_capture.py --port /dev/tty.usbmodem* --out capture.pcap
    python pcap_capture.py --port /dev/tty.usbmodem* --wireshark
    python pcap_capture.py --port /dev/ttyUSB0 --stats
"""

import argparse
import os
import struct
import subprocess
import sys
import time
from datetime import datetime


def find_port():
    import glob
    candidates = (
        glob.glob("/dev/tty.usbmodem*") +
        glob.glob("/dev/tty.usbserial*") +
        glob.glob("/dev/ttyUSB*") +
        glob.glob("/dev/ttyACM*")
    )
    if not candidates:
        sys.exit("No serial port found. Pass --port explicitly.")
    if len(candidates) > 1:
        print(f"Multiple ports found: {candidates}", file=sys.stderr)
        print(f"Using {candidates[0]}", file=sys.stderr)
    return candidates[0]


class FramedReader:
    """Reads byte stream, separates envelope-framed pcap records from log text."""

    MAGIC = bytes([0xFE, 0xFE])

    def __init__(self, stream):
        self._s = stream
        self._buf = bytearray()

    def _read_byte(self):
        while True:
            b = self._s.read(1)
            if b:
                return b[0]

    def read_record(self):
        """Block until a framed pcap record is available.
        Returns (record_bytes, log_text_emitted_so_far)."""
        log_chars = bytearray()

        while True:
            b = self._read_byte()
            if b != 0xFE:
                log_chars.append(b)
                if b == ord('\n') and log_chars:
                    line = log_chars.decode('utf-8', errors='replace')
                    print(line, end='', file=sys.stderr)
                    log_chars.clear()
                continue

            # Potential start of envelope
            b2 = self._read_byte()
            if b2 != 0xFE:
                log_chars.append(0xFE)
                log_chars.append(b2)
                continue

            # Read 2-byte length
            len_hi = self._read_byte()
            len_lo = self._read_byte()
            data_len = (len_hi << 8) | len_lo

            if data_len == 0 or data_len > 65535:
                continue  # spurious match

            # Read the pcap record
            data = bytearray()
            while len(data) < data_len:
                chunk = self._s.read(data_len - len(data))
                if chunk:
                    data.extend(chunk)

            return bytes(data)


def run(args):
    import serial

    port = args.port or find_port()
    baud = args.baud

    print(f"Opening {port} @ {baud}...", file=sys.stderr)
    ser = serial.Serial(port, baud, timeout=1)

    reader = FramedReader(ser)

    out_file = None
    wireshark_proc = None

    if args.out:
        out_file = open(args.out, 'wb')
        print(f"Writing to {args.out}", file=sys.stderr)
    elif args.wireshark:
        # Open named pipe to Wireshark
        pipe_path = "/tmp/matter_sniffer.pcap"
        try:
            os.mkfifo(pipe_path)
        except FileExistsError:
            pass
        wireshark_proc = subprocess.Popen(
            ["wireshark", "-k", "-i", pipe_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        out_file = open(pipe_path, 'wb')
        print(f"Wireshark launched (pipe: {pipe_path})", file=sys.stderr)

    frame_count = 0
    byte_count = 0
    header_written = False
    start = time.time()

    try:
        while True:
            record = reader.read_record()

            if not record:
                continue

            # First record from device includes the pcap global header (20 bytes)
            # followed by optional packet records. We pass it through as-is.
            if not header_written:
                # Validate: should start with pcap magic 0xa1b2c3d4
                if len(record) >= 4 and record[:4] == b'\xd4\xc3\xb2\xa1':
                    header_written = True
                else:
                    # This is a pcap record without a global header yet
                    # (shouldn't happen, but be defensive)
                    pass

            if out_file:
                out_file.write(record)
                out_file.flush()

            frame_count += 1
            byte_count += len(record)

            if args.stats or (not out_file):
                elapsed = time.time() - start
                print(
                    f"\r[{elapsed:.0f}s] frames={frame_count} bytes={byte_count}  ",
                    end='', file=sys.stderr
                )

    except KeyboardInterrupt:
        print(f"\nCaptured {frame_count} records ({byte_count} bytes)", file=sys.stderr)
    finally:
        if out_file:
            out_file.close()
        if wireshark_proc:
            wireshark_proc.terminate()
        ser.close()


def main():
    parser = argparse.ArgumentParser(description="Matter Sniffer pcap capture tool")
    parser.add_argument("--port", help="Serial port (auto-detected if omitted)")
    parser.add_argument("--baud", type=int, default=921600, help="Baud rate")
    parser.add_argument("--out", help="Output .pcap file path")
    parser.add_argument("--wireshark", action="store_true", help="Pipe to Wireshark")
    parser.add_argument("--stats", action="store_true", help="Print stats only")
    args = parser.parse_args()

    try:
        import serial  # noqa: F401
    except ImportError:
        sys.exit("Install pyserial first: pip install pyserial")

    run(args)


if __name__ == "__main__":
    main()
