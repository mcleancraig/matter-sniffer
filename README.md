# matter-sniffer

An ESP32-S3 firmware tool for debugging Matter-over-WiFi networks. Connects to your WiFi as a station, passively captures 802.11 frames, actively scans for Matter devices via mDNS, tracks device availability, and publishes everything to Home Assistant via MQTT.

## What it captures

| Data | How | Notes |
|------|-----|-------|
| Matter device names, IPs, ports | mDNS (`_matter._tcp`, `_matterc._udp`) | Includes Thread devices via Border Router |
| Vendor ID, Product ID, Device Type | mDNS TXT records | |
| Fabric ID, Node ID | mDNS service instance names | |
| Device availability (online/offline) | mDNS heartbeat timeout | Offline after 5 min silence |
| Per-device RSSI | WiFi promiscuous mode | |
| Raw 802.11 frames | WiFi promiscuous mode → pcap | Management frames + data frame headers |
| Matter TCP connection patterns | Port 5540 frame counts | Payloads are encrypted |

Matter application traffic is CASE-encrypted — payloads are not readable. What's valuable is device discovery, availability monitoring, and connection patterns.

## Hardware

- ESP32-S3 DevKit (any variant with native USB)
- USB cable to your Mac

## Prerequisites

- ESP-IDF v6.0 installed at `~/.espressif/v6.0/esp-idf`
- Home Assistant with MQTT integration enabled (optional)
- Python 3 + `pyserial` for the pcap host tool (optional)

## Build

```bash
git clone <repo> matter-sniffer
cd matter-sniffer
./build.sh build
```

The first build takes a few minutes. Output: `firmware/build/matter_sniffer.bin`.

## Flash

Hold **BOOT**, press **RESET**, release **BOOT** to enter download mode, then:

```bash
./build.sh flash-monitor /dev/tty.usbmodem*
```

Auto-detects the port if you omit it.

## First-run configuration

On first boot the device has no WiFi credentials. Type this in the serial monitor:

```
CONFIG your-ssid:your-password:mqtt-broker-ip
```

The device saves the config to NVS and restarts. After connecting you'll see:

```
I (1234) main: WiFi connected, starting services
I (1234) main: Web UI: http://192.168.x.x/
I (1234) main: Serial commands: pcap on/off | devices | CONFIG s:p:h
```

MQTT broker IP can be left empty if you're not using Home Assistant (`CONFIG ssid:pass:`).

## Web UI

Open `http://<device-ip>/` in a browser. Shows a live table of all discovered Matter devices with online/offline status, RSSI, vendor/product IDs, and fabric/node IDs. Updates in real time via WebSocket.

## Serial commands

| Command | Effect |
|---------|--------|
| `devices` | Print full device registry to console |
| `pcap on` | Start streaming pcap frames over USB serial |
| `pcap off` | Stop pcap stream |
| `pcap mdns` | pcap filter: mDNS frames only |
| `pcap all` | pcap filter: all 802.11 frames |
| `CONFIG ssid:pass:mqtt_host` | Update credentials and restart |
| `restart` | Reboot device |

## Packet capture (Wireshark)

```bash
pip install pyserial
python tools/pcap_capture.py --port /dev/tty.usbmodem* --out capture.pcap
```

Open `capture.pcap` in Wireshark. Filter suggestions:

```
mdns                        # all mDNS traffic
dns.qry.name contains "matter"  # Matter service discovery
wlan.fc.type_subtype == 0x08    # beacon frames
```

Live pipe to Wireshark (requires Wireshark in PATH):

```bash
python tools/pcap_capture.py --port /dev/tty.usbmodem* --wireshark
```

pcap frames are framed over USB serial with a `0xFE 0xFE <len>` envelope so the host tool can separate them from log text on the same port.

## Home Assistant integration

The device publishes MQTT auto-discovery messages so HA automatically creates entities for each Matter device found. Each device gets:

- A sensor entity with IP, MAC, RSSI, vendor/product ID, device type as attributes
- An availability topic (`online`/`offline`)

After the first scan, import the Lovelace dashboard:

1. In HA go to **Settings → Dashboards → Add Dashboard**
2. Edit the dashboard YAML and paste the contents of `homeassistant/lovelace/matter-network.yaml`

The auto-entity card requires the [auto-entities](https://github.com/thomasloven/lovelace-auto-entities) HACS frontend integration.

## Architecture

```
ESP32-S3
│
├── wifi_manager        connects to AP in STA mode; enables promiscuous mode
│
├── packet_sniffer      promiscuous callback → 802.11 frame stats + RSSI per MAC
│   └── pcap_streamer   queues frames → USB serial (0xFE 0xFE framed pcap)
│
├── mdns_scanner        lwIP UDP socket on 224.0.0.251:5353
│   ├── passive         parses all received mDNS packets for Matter records
│   └── active          sends PTR queries every 60s for _matter._tcp etc.
│
├── device_registry     central state: up to 256 devices, offline after 5 min
│   └── callbacks ──────────────────────────────────────┐
│                                                        │
├── mqtt_ha             HA auto-discovery + availability  ◄─┘
└── http_server         REST API + WebSocket + web UI    ◄─┘
```

## Build commands

```bash
./build.sh build              # compile
./build.sh flash [port]       # flash only
./build.sh monitor [port]     # serial monitor only
./build.sh flash-monitor [port]  # flash then monitor
./build.sh menuconfig         # interactive config (flash size, PSRAM, etc.)
./build.sh clean              # delete build directory
```

## Troubleshooting

**"No serial data received" when flashing** — board isn't in download mode. Hold BOOT, tap RESET, release BOOT, then flash.

**Board shows as `/dev/tty.usbserial-*` not `/dev/tty.usbmodem*`** — you're on the UART port, not the native USB port. Both work for flashing, but the native USB port (`usbmodem`) gives faster throughput for pcap streaming.

**No devices discovered** — check that your Matter devices are on the same 2.4 GHz network. ESP32-S3 is 2.4 GHz only; 5 GHz Matter devices are invisible. Run `pcap on` and open the capture in Wireshark to confirm mDNS traffic is present.

**PSRAM errors on boot** — if your DevKit doesn't have PSRAM, run `./build.sh menuconfig` and disable PSRAM under *Component config → ESP PSRAM*.

**Flash size mismatch** — if flashing fails with a size error, run `./build.sh menuconfig` and set the correct flash size under *Serial flasher config → Flash size* (most DevKits are 4 MB or 8 MB).
