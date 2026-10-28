# pyLot

A passive network mapper for industrial control systems (ICS), rewriting NSA's GRASSMARLIN as a
Python web application.

## Features

- Upload PCAP or PCAPNG captures, or Zeek `conn.log` files; each upload becomes a saved session you can
  revisit or delete
- Live capture from a network interface, started and stopped from the web page, saved as its own session
- Classifies hosts with GRASSMARLIN's fingerprint engine and its 118 stock fingerprints (Modbus,
  DNP3, BACnet, EtherNet/IP, S7, IEC 60870-5-104, PROFINET, vendor-specific protocols and more)
- Decodes industrial protocols to list what each client asks each device to do: Modbus/TCP (with
  Schneider UMAS), DNP3, S7comm, EtherNet/IP and CIP (including Logix tag services), IEC 60870-5-104,
  BACnet/IP and SNMP. Program downloads, PLC stop and start, control commands and writes are listed
  first and drawn in red or orange on the graph
- Asset identity: vendor, model, order number, firmware and serial number from the identification
  replies devices send (Modbus Read Device Identification, EtherNet/IP List Identity and Identity
  object, S7 module and component identification, BACnet device properties), plus SNMP system
  descriptions and HTTP, FTP and SSH server banners
- Loads fingerprints in GRASSMARLIN's own XML format as well as the YAML conversions in `fingerprints/`
- Hosts, flows, MAC addresses and ARP bindings, with MAC vendor lookup that doesn't credit a
  router's MAC to the remote hosts behind it
- Logical view: a network graph grouped by network, colored by device category and shaped by role;
  hosts behind a router are merged into one node when there are many of them
- Named networks: give address ranges names on the Networks page, or by clicking a network in the
  graph, and every session groups its hosts by them
- Layer-2 devices: LLDP, CDP, STP and Cisco PVST+ from network gear, and the industrial protocols that run without IP
  (PROFINET DCP and RT, IEC 61850 GOOSE and Sampled Values, EtherCAT, POWERLINK, MRP) identify and
  classify devices, including ones that never send IP traffic
- Physical view: import Cisco switch output (running config, MAC address table, CDP/LLDP neighbors) to
  see which device is plugged into which port, how switches connect, and where the capture was taken
- Baseline comparison: new and missing hosts, MAC addresses and conversations, new industrial
  operations, and hosts whose MAC, classification, model or firmware changed since a known-good capture, listed on a comparison page and marked on the graph
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
     confidence (1 is high, 5 is low, as in GRASSMARLIN)
   - The Logical tab is the IP network graph and the Physical tab the switch-level view. Hosts lists
     every IP address, Devices every MAC address (including devices that never sent IP traffic) and
     Flows every conversation. Operations lists the industrial operations decoded from the traffic,
     most consequential first, with a filter by kind (program, control, write, read and so on)
   - A host's panel starts with its identity, as the device reported it, when the capture includes
     an identification reply

   Uploaded files are kept, so a session can be analyzed again with Re-analyze on its page, or every
   upload at once with "Re-analyze all uploads" on the sessions list. Do this after updating pyLot or
   its fingerprints; imported switch data is kept.

   Live capture saves to its session every couple of seconds; use the Refresh button on its page to
   see new hosts, and Stop capture to end it. A capture or analysis still running when pyLot stops is
   marked "stopped" or "failed" on the next start.

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

### Industrial operations and identity

Each operation is listed under the conversation's client and server, with how many times it was
seen and when, and a kind that says what it does to the server: **program** (downloads, uploads,
block changes), **control** (PLC stop and start, DNP3 operate and restarts, IEC 104 commands, CIP
reset), **write**, **read**, **diagnostic** (identification, status and discovery), **data**
(values the server reports on its own), **session**, **error** (exceptions and failed requests) and
**other**. Errors and reported data are listed under the conversation they belong to.

Decoders check a message parses as its protocol before reporting anything, so other traffic on the
same ports is ignored. TCP streams are reassembled, so messages split across segments are decoded and
retransmissions aren't counted twice. Roles from decoded traffic (Modbus master, S7 server and so on)
have confidence 2, ahead of the fingerprints' guesses, and what a device says about itself has
confidence 1. A CIP identity reply that came through a chassis backplane (Unconnected Send to a slot)
describes that module, so it is listed under Modules rather than as the address's own identity.

Identity only appears when the capture includes a device answering an identification request, for
example an engineering tool going online, an asset inventory scan, or EtherNet/IP and BACnet
discovery broadcasts. A baseline comparison only reports a model or firmware change when both
captures heard that device's identity.

### Zeek logs

pyLot reads Zeek's `conn.log`, in the default tab-separated format or as JSON lines, and either one
gzipped. Zeek records connections rather than packets, so fingerprints and the protocol decoders, which need
packet payloads, don't run on them, and Zeek sessions have no operations or identity. Instead, hosts are classified from the service Zeek identified, for the industrial
protocols its analyzers and CISA's ICSNPP plugins recognize (Modbus, DNP3, EtherNet/IP, BACnet, S7,
IEC 104 and others). MAC addresses are used when Zeek logged them, which it does when the
`policy/protocols/conn/mac-logging` script is loaded. Other Zeek logs (`dns.log`, `http.log` and so on)
are rejected.

## Configuration

| Environment variable | Default | Purpose |
|---|---|---|
| `PYLOT_MAX_UPLOAD_MB` | `500` | Largest capture or Zeek log accepted |
| `PYLOT_TRUSTED_HOSTS` | `localhost,127.0.0.1` | Host names the app answers to; other `Host` headers get a 400 |
| `PYLOT_DB_PATH` | `pylot.sqlite3` in the app directory | Session database |
| `PYLOT_UPLOAD_FOLDER` | `uploads/` in the app directory | Where uploaded captures and logs are kept |

## Security

pyLot has no authentication, so by default it only listens on 127.0.0.1. If you pass `--host` to
listen elsewhere, anyone who can reach that address can use it; set `PYLOT_TRUSTED_HOSTS` to the
names you'll browse to it by. Uploaded files are stored under random names, files that aren't captures
or Zeek conn.logs are rejected, and requests that change data are refused when they come from other sites.

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
- **evidence**: every fingerprint result and decoded property (role, identity) for a host, with its confidence
- **operations**: decoded industrial operations per client, server and protocol, with their kind and counts
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
- **A session shows out-of-date results** (after updating pyLot or its fingerprints): use Re-analyze.
  Live captures aren't saved to a file, so they can't be re-analyzed
- **No identity shown for a PLC**: devices only report their model and firmware when asked. Capture
  while an engineering tool connects to them, or while EtherNet/IP or BACnet discovery runs
- **Upload fails**: The error is shown on the upload page; details are in the server log. For Zeek,
  upload `conn.log` itself, not another log or a directory archive
- **400 Bad Request when browsing by hostname or IP**: Add that name to `PYLOT_TRUSTED_HOSTS`
- **Very large captures**: Analysis runs at roughly 5,000 to 15,000 packets a second in the
  background, one upload at a time; a 2.3-million-packet capture takes about three minutes. Captures
  full of scans can hold millions of flows, which makes the graph and baseline comparisons take
  several seconds. When more than 200 hosts were reached through routers, the graph
  merges them into one node per router; above 1,500 hosts it is drawn as a plain grid without labels

## Development

The application structure:
- `app.py`: Main Flask application
- `storage.py`: SQLite schema and queries
- `parser/pcap_parser.py`: entry point that analyzes a capture or Zeek log
- `parser/packets.py`: pcap/pcapng decoding (dpkt)
- `parser/zeek.py`: Zeek conn.log reading
- `parser/fingerprint_loader.py`, `parser/fingerprint_matcher.py`: the fingerprint engine
- `parser/reference/`: vendor and device name tables for fingerprint lookups
- `parser/analysis.py`: hosts, flows and evidence for one capture
- `parser/layer2.py`: LLDP, CDP, STP and industrial Ethernet decoding
- `parser/ics/`: industrial protocol decoders (one module per protocol) and TCP reassembly for them
- `parser/switch_config.py`: Cisco switch output parsing for the physical view
- `parser/mac_lookup.py`, `parser/oui.csv`: MAC vendor lookup (see `README_vendor_enrichment.md`)
- `parser/protocols.py`: flow labels by well-known port
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
