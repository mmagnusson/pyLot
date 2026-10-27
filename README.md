# pyLot

A passive network mapper for industrial control systems (ICS), rewriting NSA's GRASSMARLIN as a
Python web application.

## Features

- Upload PCAP or PCAPNG captures; each upload becomes a saved session you can revisit or delete
- Optional live capture from a network interface, saved as its own session
- Classifies hosts with GRASSMARLIN's fingerprint engine and its 118 stock fingerprints (Modbus,
  DNP3, BACnet, EtherNet/IP, S7, IEC 60870-5-104, PROFINET, vendor-specific protocols and more)
- Loads fingerprints in GRASSMARLIN's own XML format as well as the YAML conversions in `fingerprints/`
- Hosts, flows, MAC addresses and ARP bindings, with MAC vendor lookup that doesn't credit a
  router's MAC to the remote hosts behind it
- Network topology graph, colored by device category

## Installation

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   Uploaded captures are decoded in Python, so nothing else is needed for them.

2. **For live capture, install dumpcap** (part of Wireshark):
   ```bash
   # Ubuntu/Debian
   sudo apt-get install wireshark-common

   # CentOS/RHEL
   sudo yum install wireshark-cli

   # macOS
   brew install wireshark
   ```

3. **Set up permissions for live capture (optional):**
   ```bash
   # Allow non-root capture through dumpcap (answer "Yes"), then join the wireshark group
   sudo dpkg-reconfigure wireshark-common
   sudo usermod -a -G wireshark $USER   # log out and back in afterwards
   ```
   Don't run pyLot itself with `sudo`. dumpcap is the only part that needs capture privileges.

## Usage

1. **Start the application:**
   ```bash
   python app.py                              # serves http://127.0.0.1:5000
   python app.py --capture-interface enp3s0   # also capture live traffic (off by default)
   python app.py --capture-interface enp3s0 --capture-filter "not port 22"
   python app.py --debug                      # Flask debugger and auto-reload, local use only
   ```
   Run `python app.py --help` for all options.

2. **Access the web interface:**
   - Open http://127.0.0.1:5000 in your browser
   - Upload a PCAP or PCAPNG file; you're taken to its session when it has been analyzed
   - Hover over hosts and connections for details, including every fingerprint result and its
     confidence (1 is high, 5 is low, as in GRASSMARLIN)

Live capture saves to its session every couple of seconds; use the Refresh button on its page to see
new hosts. A capture still marked "capturing" when pyLot restarts is marked "stopped".

## Configuration

| Environment variable | Default | Purpose |
|---|---|---|
| `PYLOT_MAX_UPLOAD_MB` | `500` | Largest capture file accepted |
| `PYLOT_TRUSTED_HOSTS` | `localhost,127.0.0.1` | Host names the app answers to; other `Host` headers get a 400 |
| `PYLOT_DB_PATH` | `pylot.sqlite3` in the app directory | Session database |
| `PYLOT_UPLOAD_FOLDER` | `uploads/` in the app directory | Where uploaded captures are kept |

## Security

pyLot has no authentication, so by default it only listens on 127.0.0.1. If you pass `--host` to
listen elsewhere, anyone who can reach that address can use it; set `PYLOT_TRUSTED_HOSTS` to the
names you'll browse to it by. Uploaded files are stored under random names, non-capture files are
rejected, and POSTs from other sites are refused.

## Fingerprints

Every `.yaml`, `.yml` and `.xml` file in `fingerprints/` is loaded at startup. XML files use
GRASSMARLIN 3's format (`fingerprint3.xsd`), so fingerprints written for GRASSMARLIN work unchanged.

The engine follows GRASSMARLIN 3.2's behavior, apart from a few of its bugs that pyLot fixes; they're
listed at the top of `parser/fingerprint_matcher.py`. A host's properties use GRASSMARLIN's rule: for
each property, the values reported at the best confidence.

Extracts that look up a vendor or device name (`ENIPVENDOR`, `ENIPDEVICE`, `BACNET`) read
`parser/reference/<LOOKUP>.csv` files of `id,name` rows. Without them, the numeric ID is shown.

## Database

The application uses SQLite (`pylot.sqlite3`) to store:
- **sessions**: one per upload or live capture
- **hosts**: each IP address, with its MAC and vendor when it's on the captured segment, or the
  router MAC it was reached through when it isn't
- **flows**: traffic between two hosts per protocol and port pair, with packet and byte counts
- **evidence**: every fingerprint result for a host, with its confidence
- **mac_addresses** and **arp_bindings**: layer-2 observations

The database is automatically created on first run.

## Troubleshooting

- **Live capture fails**: The session shows dumpcap's error. Usually you need to be in the
  wireshark group (log out and back in after adding yourself) or the interface name is wrong
  (`ip link` lists them)
- **Upload fails**: The error is shown on the upload page; details are in the server log
- **400 Bad Request when browsing by hostname or IP**: Add that name to `PYLOT_TRUSTED_HOSTS`
- **Very large captures**: Analysis runs at roughly 5,000 to 15,000 packets a second and the upload
  waits for it. A graph with thousands of hosts is drawn as a grid and is slow to display

## Development

The application structure:
- `app.py`: Main Flask application
- `storage.py`: SQLite schema and queries
- `parser/packets.py`: pcap/pcapng decoding (dpkt)
- `parser/fingerprint_loader.py`, `parser/fingerprint_matcher.py`: the fingerprint engine
- `parser/analysis.py`: hosts, flows and evidence for one capture
- `capture/live_capture.py`: Real-time capture with dumpcap
- `templates/`: HTML templates
- `tests/`: pytest suite

Run the tests with:
```bash
pip install -r requirements-dev.txt
python -m pytest
```
To also check the YAML fingerprints against GRASSMARLIN's originals, set `PYLOT_GM_FINGERPRINTS`
to a GRASSMARLIN checkout's `GM3/data/fingerprint` directory.

## License

pyLot's code is under the MIT License (see `LICENSE`). The fingerprints in `fingerprints/` are
derived from NSA's GRASSMARLIN and are under the LGPL-3.0; see `fingerprints/README.md`.
