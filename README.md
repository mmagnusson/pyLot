# pyLot

A passive network mapper for industrial control systems (ICS), rewriting NSA's GRASSMARLIN as a
Python web application.

## Features

- Upload PCAP or PCAPNG captures, or Zeek `conn.log` files; each upload becomes a saved session you can
  revisit or delete
- Live capture from a network interface, started and stopped from the web page, saved as its own session
- Classifies hosts with GRASSMARLIN's fingerprint engine and its 118 stock fingerprints (Modbus,
  DNP3, BACnet, EtherNet/IP, S7, IEC 60870-5-104, PROFINET, vendor-specific protocols and more)
- Loads fingerprints in GRASSMARLIN's own XML format as well as the YAML conversions in `fingerprints/`
- Hosts, flows, MAC addresses and ARP bindings, with MAC vendor lookup that doesn't credit a
  router's MAC to the remote hosts behind it
- Logical view: a network graph grouped by network, colored by device category and shaped by role;
  hosts behind a router are merged into one node when there are many of them
- Named networks: give address ranges names on the Networks page, or by clicking a network in the
  graph, and every session groups its hosts by them
- Layer-2 devices: LLDP, CDP and STP from network gear, and the industrial protocols that run without IP
  (PROFINET DCP and RT, IEC 61850 GOOSE and Sampled Values, EtherCAT, POWERLINK, MRP) identify and
  classify devices, including ones that never send IP traffic
- Physical view: import Cisco switch output (running config, MAC address table, CDP/LLDP neighbors) to
  see which device is plugged into which port, how switches connect, and where the capture was taken
- Baseline comparison: new and missing hosts, MAC addresses and conversations, and hosts whose MAC or
  classification changed since a known-good capture, listed on a comparison page and marked on the graph
- Sortable, searchable host, device and flow tables, a details panel for everything, and PNG, JSON
  and CSV exports

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
   python app.py --capture-interface enp3s0   # also start capturing live traffic right away
   python app.py --capture-interface enp3s0 --capture-filter "not port 22"
   python app.py --debug                      # Flask debugger and auto-reload, local use only
   ```
   Run `python app.py --help` for all options.

2. **Access the web interface:**
   - Open http://127.0.0.1:5000 in your browser
   - Upload a PCAP or PCAPNG file or a Zeek `conn.log`, or pick an interface and start a live capture
   - Each opens a session page. Uploads are analyzed in the background and appear when ready
   - Click a host or connection for details, including every fingerprint result and its
     confidence (1 is high, 5 is low, as in GRASSMARLIN). The Hosts and Flows tabs list everything

3. **Name your networks (optional):** open Networks from any page and add ranges such as
   `10.20.0.0/24  Packaging line`. Hosts outside named networks are grouped by /24 (IPv4) and /64
   (IPv6); you can change or turn off that automatic grouping on the same page.

4. **Add switch data for the physical view (optional):** on a session's Physical tab, upload or paste
   the output of these commands from each Cisco IOS, IOS-XE or NX-OS switch, in one file or several:
   ```
   show running-config
   show mac address-table
   show cdp neighbors detail      (or: show lldp neighbors detail)
   ```
   pyLot places each device on the access port where it was learned, rather than the uplinks it was
   also learned on. Without switch data the Physical tab still shows each device's VLAN, and the
   switch and port the capture is plugged into when LLDP or CDP was captured.

5. **Compare with a baseline:** use "Compare with a baseline" on a session, or Compare on the sessions
   list, and pick an earlier capture of the network in a known-good state. To see the changes on the
   graph instead, pick the baseline under "Changes since" on the Logical tab: new hosts and
   conversations are drawn in green, changed hosts in orange.

### Zeek logs

pyLot reads Zeek's `conn.log`, in the default tab-separated format or as JSON lines, and either one
gzipped. Zeek records connections rather than packets, so fingerprints, which need packet payloads,
don't run on them. Instead, hosts are classified from the service Zeek identified, for the industrial
protocols its analyzers and CISA's ICSNPP plugins recognize (Modbus, DNP3, EtherNet/IP, BACnet, S7,
IEC 104 and others). MAC addresses are used when Zeek logged them, which it does when the
`policy/protocols/conn/mac-logging` script is loaded.

Live capture saves to its session every couple of seconds; use the Refresh button on its page to see
new hosts, and Stop capture to end it. A capture or analysis still running when pyLot stops is marked
"stopped" or "failed" on the next start.

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
`parser/reference/<LOOKUP>.csv` files of `id,name` rows, taken from GRASSMARLIN's tables. IDs that
aren't listed are shown as numbers.

## Database

The application uses SQLite (`pylot.sqlite3`) to store:
- **sessions**: one per upload or live capture
- **hosts**: each IP address, with its MAC and vendor when it's on the captured segment, or the
  router MAC it was reached through when it isn't
- **flows**: traffic between two hosts per protocol and port pair, with packet and byte counts
- **evidence**: every fingerprint result for a host, with its confidence
- **mac_addresses**, **arp_bindings**, **mac_vlans**: layer-2 observations
- **l2_flows** and **mac_evidence**: traffic without IP, and what layer-2 protocols say about each MAC
- **switches**, **switch_ports**, **switch_macs**, **switch_neighbors**: imported switch data, per session
- **networks** and **settings**: named networks and automatic grouping, shared by all sessions

The database is automatically created on first run.

## Troubleshooting

- **A device is on the wrong switch port**: pyLot prefers access ports, recognizing uplinks by trunk
  mode, port channels and CDP/LLDP neighbors. Include `show running-config` and the neighbors output
  so it can tell them apart
- **Live capture fails**: The session shows dumpcap's error. Usually you need to be in the
  wireshark group (log out and back in after adding yourself) or the interface name is wrong
  (`ip link` lists them)
- **Upload fails**: The error is shown on the upload page; details are in the server log
- **400 Bad Request when browsing by hostname or IP**: Add that name to `PYLOT_TRUSTED_HOSTS`
- **Very large captures**: Analysis runs at roughly 5,000 to 15,000 packets a second in the
  background, one upload at a time. When more than 200 hosts were reached through routers, the graph
  merges them into one node per router; above 1,500 hosts it is drawn as a plain grid without labels

## Development

The application structure:
- `app.py`: Main Flask application
- `storage.py`: SQLite schema and queries
- `parser/packets.py`: pcap/pcapng decoding (dpkt)
- `parser/fingerprint_loader.py`, `parser/fingerprint_matcher.py`: the fingerprint engine
- `parser/analysis.py`: hosts, flows and evidence for one capture
- `parser/layer2.py`: LLDP, CDP, STP and industrial Ethernet decoding
- `parser/switch_config.py`: Cisco switch output parsing for the physical view
- `capture/live_capture.py`: Real-time capture with dumpcap
- `templates/`: HTML templates
- `static/`: page scripts (`session.js`, `networks.js`, `compare.js`, shared `common.js`) and `style.css`
- `tests/`: pytest suite

Run the tests with:
```bash
pip install -r requirements-dev.txt
python -m pytest
```
To also check the YAML fingerprints against GRASSMARLIN's originals, set `PYLOT_GM_FINGERPRINTS`
to a GRASSMARLIN checkout's `GM3/data/fingerprint` directory.

## License

pyLot's code is under the MIT License (see `LICENSE`). The fingerprints in `fingerprints/` and the
lookup tables in `parser/reference/` are derived from NSA's GRASSMARLIN and are under the LGPL-3.0;
see `fingerprints/README.md` and `parser/reference/README.md`.
