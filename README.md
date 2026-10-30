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
- Alerts for risky activity: controller programs changed or read out, controllers stopped or
  restarted, control commands, writes, devices changed from several hosts, protocol fuzzing, device
  enumeration and scans of industrial ports, each rated high, medium or low
- Asset identity: vendor, model, order number, firmware and serial number from the identification
  replies devices send (Modbus Read Device Identification, EtherNet/IP List Identity and Identity
  object, S7 module and component identification, BACnet device properties), plus SNMP system
  descriptions and HTTP, FTP and SSH server banners
- Known vulnerabilities: imports security advisories in CSAF format (CISA's ICS advisories with one
  click, or vendors' own) and matches them against each device's vendor, model, order number and
  firmware, module by module in a ControlLogix chassis
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
- Asset inventory: every device across all sessions, recognized again by serial number, MAC or IP
  address, with when it was first and last seen, each sighting, changes to its address, model,
  firmware or serial number, and its known vulnerabilities; devices can be named, annotated and merged
- Baseline comparison: new and missing hosts, MAC addresses and conversations, new industrial
  operations, new alerts and vulnerabilities, and hosts whose MAC, classification, model or firmware changed since a known-good capture, listed on a comparison page and marked on the graph
- Sortable, searchable host, device and flow tables, a details panel for everything, and PNG, JSON
  and CSV exports
- Accounts with viewer, analyst and admin roles, and HTTPS (your certificate, a self-signed one, or a
  reverse proxy), required before pyLot listens on anything but the machine it runs on

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
   python app.py --host 0.0.0.0 --self-signed # serve other machines over HTTPS (needs an account first)
   ```
   Run `python app.py --help` for all options. To use pyLot from other machines, see
   [Accounts and HTTPS](#accounts-and-https).

2. **Access the web interface:**
   - Open http://127.0.0.1:5000 in your browser
   - Upload a PCAP or PCAPNG file or a Zeek `conn.log`, or pick an interface and start a live capture
   - Each opens a session page. Uploads are analyzed in the background and appear when ready
   - Click a host or connection for details, including every fingerprint result and its
     confidence (1 is high, 5 is low, as in GRASSMARLIN)
   - The Logical tab is the IP network graph and the Physical tab the switch-level view. Hosts lists
     every IP address, Devices every MAC address (including devices that never sent IP traffic) and
     Flows every conversation. Operations lists the industrial operations decoded from the traffic,
     most consequential first, with a filter by kind (program, control, write, read and so on), and
     Alerts the risky activity found in them; the alert count is shown at the top of the page.
     Vulnerabilities lists the advisories that match the session's devices
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

5. **Check devices for known vulnerabilities (optional):** open Advisories from any page and use
   "Download from CISA", or import CSAF files there. See [Known vulnerabilities](#known-vulnerabilities).

6. **Keep track of devices over time:** every finished session adds the devices it saw to the asset
   inventory (Asset inventory on the sessions page). See [Asset inventory](#asset-inventory).

7. **Compare with a baseline:** use "Compare with a baseline" on a session, or Compare on the sessions
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

### Alerts

| Severity | Alert | Raised when |
|---|---|---|
| High | Controller program changed | program blocks or files downloaded, deleted or activated |
| High | Controller stopped, started or restarted | PLC stop or start, restarts, CIP reset, Modbus listen-only mode |
| High | Protocol fuzzing or scanning | a client sends 5 or more function codes no standard defines |
| Medium | Program read from a controller | a program or configuration upload |
| Medium | Control commands | DNP3 operate, IEC 104 commands and other commands that move equipment |
| Medium | Changed from several hosts | more than one host writes to, commands or programs the same device |
| Medium | Devices asked to identify themselves | one host asks 5 or more devices for their model and firmware |
| Medium | Many failed requests | 20 or more errors and exceptions between one client and one device |
| Medium | Scan of industrial services | one host touches 10 or more industrial services with 3 packets or fewer each |
| Medium | SNMP Set | a device's settings changed over SNMP |
| Low | Writes to a device | values written to registers, tags, objects or memory |
| Low | Clock set | a device's clock set |
| Low | Password or authentication sent | a client authenticates to a device |

Each alert covers one client and one device (or one client and many devices), however many times
it happened, with the operations involved, a count and the first frame to look at in Wireshark.
Some of these are routine for a SCADA master or an engineering workstation: compare with a baseline
to see only the alerts that are new.

### Known vulnerabilities

pyLot checks devices against security advisories in CSAF 2.0, the format CISA publishes its ICS
advisories in. On the Advisories page, "Download from CISA" fetches CISA's CSAF repository (about
12 MB from GitHub) and imports its ICS and medical advisories; run it again to pick up new and updated
ones. Vendors such as Siemens, Schneider Electric and Hitachi Energy publish CSAF advisories of their
own, which can be imported as JSON files or as a .zip or .tar.gz of them. Advisories are shared by
every session, and an advisory imported again replaces its older revision. Without Internet access,
download `https://codeload.github.com/cisagov/CSAF/tar.gz/refs/heads/develop` elsewhere and import it,
or from the command line:
```bash
python advisories.py fetch                    # download and import CISA's ICS advisories
python advisories.py import advisories.tar.gz # or CSAF .json files, or a .zip of them
python advisories.py status
```

A device is matched in one of three ways, and the match says which:
- **model number**: the advisory lists the device's order or model number (Siemens order numbers
  such as `6ES7 315-2EH14-0AB0`, Rockwell catalog numbers, Schneider references with wildcards)
- **product name**: the device's model, such as `1756-ENBT`, appears in the advisory's product name
- **product family**: the family the device's order or catalog number belongs to, such as S7-1200 or
  MicroLogix 1400, appears in the advisory's product name, and the advisory lists no model numbers

When an advisory lists the order numbers it covers, a device with a different order number doesn't
match it. The device is **affected** when the firmware it reported is in the advisory's affected
versions (`vers:intdot/<4.5.0`, `<= 5.008`, `>=7.80|<8.90` and the like), and **possibly affected**
when its firmware wasn't seen or pyLot can't read the versions (about 8% of CISA's are free text).
Only devices that reported their model can be checked, so capture while an engineering tool or a
discovery scan talks to them. Treat every match as a lead and confirm it against the advisory: a
family-level match in particular may concern only some models of that family.

### Asset inventory

The inventory lists every device pyLot has seen, across all sessions, and keeps it when the session is
deleted. Each finished session (an analyzed upload, or a stopped live capture) adds a sighting of each
device it saw: one per MAC address, with the addresses it used and the identity it reported, plus one
per private IP address reached through a router. Internet addresses aren't assets.

A sighting joins the asset with the same serial number (from the same vendor), else the same MAC
address, else the same IP address when either was only seen through a router. So a device keeps its
entry when its address changes, while a replacement at the same address, with a new MAC, gets a new
one. Asset pages list every sighting and every change to the device's addresses, MAC, vendor, model,
firmware and serial number, which is how a firmware update, a swapped module or a device that moved
shows up. Each asset is checked against the imported advisories with the identity it last reported.

Analysts can name assets and add notes, merge two entries that are really the same device (for example
one seen only through a router), and remove entries. The inventory filters to assets whose identity
changed, vulnerable ones, and ones missing from the newest session, and downloads as CSV. A host's or
device's panel in a session links to its asset.

### Zeek logs

pyLot reads Zeek's `conn.log`, in the default tab-separated format or as JSON lines, and either one
gzipped. Zeek records connections rather than packets, so fingerprints and the protocol decoders, which need
packet payloads, don't run on them, and Zeek sessions have no operations or identity. Instead, hosts are classified from the service Zeek identified, for the industrial
protocols its analyzers and CISA's ICSNPP plugins recognize (Modbus, DNP3, EtherNet/IP, BACnet, S7,
IEC 104 and others). MAC addresses are used when Zeek logged them, which it does when the
`policy/protocols/conn/mac-logging` script is loaded. Other Zeek logs (`dns.log`, `http.log` and so on)
are rejected.

### Accounts and HTTPS

Until you add an account, pyLot asks no one to sign in, which suits one analyst on their own machine:
it only listens on 127.0.0.1 unless told otherwise. Once there is an account, everyone signs in. Add
the first one on the Accounts page (the link at the top right) or on the server:

```bash
python auth.py add alice                  # the first account is an admin; asks for a password
python auth.py add bob --role viewer
python auth.py list                       # also: passwd NAME, role NAME ROLE, remove NAME
```

| Role | Can |
|---|---|
| viewer | look at sessions, advisories and networks, and download exports |
| analyst | also upload captures, run live captures, re-analyze and delete sessions, import switch data and name networks |
| admin | also manage accounts (the Users page) and download or import security advisories |

Admins manage accounts on the Users page; everyone changes their own password on the Account page.
Changing a password or removing an account signs out the browsers using it. Passwords need at least
12 characters, and an address that fails to sign in 10 times in 15 minutes has to wait.

To listen on a network address, pyLot needs an account and HTTPS, and won't start without them:

```bash
python app.py --host 0.0.0.0 --self-signed            # makes tls/cert.pem and tls/key.pem on first use
python app.py --host 10.1.2.3 --cert cert.pem --key key.pem
python app.py --behind-proxy                          # nginx, Caddy etc. serve HTTPS and forward to 127.0.0.1:5000
```

With `--self-signed`, browsers warn that they don't know the certificate. The server log prints its
SHA-256 fingerprint; check that the browser shows the same one before accepting it. Delete `tls/` to
make a new certificate (for instance after the machine's name changes). Set `PYLOT_TRUSTED_HOSTS` to
the names and addresses you'll browse to pyLot by. Behind a proxy, pyLot trusts its `X-Forwarded-For`,
`-Proto` and `-Host` headers, so only use `--behind-proxy` when the proxy is the only way in.

`app.py` serves with Flask's built-in server, which is fine for a handful of users; a production
deployment (Docker, systemd) is on the roadmap.

## Configuration

| Environment variable | Default | Purpose |
|---|---|---|
| `PYLOT_MAX_UPLOAD_MB` | `500` | Largest capture or Zeek log accepted |
| `PYLOT_TRUSTED_HOSTS` | `localhost,127.0.0.1` | Host names the app answers to; other `Host` headers get a 400 |
| `PYLOT_DB_PATH` | `pylot.sqlite3` in the app directory | Session database |
| `PYLOT_UPLOAD_FOLDER` | `uploads/` in the app directory | Where uploaded captures and logs are kept |
| `PYLOT_SESSION_HOURS` | `12` | How long a sign-in lasts without using pyLot |
| `PYLOT_SECRET_KEY` | made on first run, kept in the database | Key that signs sign-in cookies; changing it signs everyone out |

## Security

By default pyLot only listens on 127.0.0.1 and, until you add an account, asks no one to sign in. It
won't listen on a network address without an account and HTTPS, or with `--debug`. Passwords are
stored as salted scrypt hashes. Sign-ins use a signed cookie that page scripts can't read, that
browsers don't send with other sites' form posts, and that is only sent over HTTPS when pyLot serves HTTPS. Pages refuse to be
framed by other sites. Requests whose `Host` isn't in `PYLOT_TRUSTED_HOSTS` are refused, which blocks
DNS rebinding. Failed sign-ins are logged with the user name and address. Uploaded files are stored under random names, files that aren't captures
or Zeek conn.logs are rejected, and requests that change data are refused when they come from other sites.
pyLot only reaches the Internet when you click "Download from CISA" (or run `advisories.py fetch`).

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
  (settings also holds the key that signs sign-in cookies)
- **assets**, **asset_observations** and **inventory_sessions**: the asset inventory, each asset's
  sightings (kept when their session is deleted) and which sessions have been added to it
- **users**: accounts, with salted password hashes, roles and when each last signed in
- **advisories** and **advisory_products**: imported security advisories and the products they say
  are affected, shared by all sessions

The database is automatically created on first run.

## Troubleshooting

- **A device is on the wrong switch port**: pyLot prefers access ports, recognizing uplinks by trunk
  mode, port channels and CDP/LLDP neighbors. Include `show running-config` and the neighbors output
  so it can tell them apart
- **Live capture fails**: The session shows dumpcap's error. Usually you need to be in the
  wireshark group (log out and back in after adding yourself, then restart pyLot, or start it with
  `sg wireshark -c "venv/bin/python app.py"`) or the interface name is wrong (`ip link` lists them).
  The sessions page shows these steps under "How to enable live capture" when dumpcap can't run
- **A session shows out-of-date results** (after updating pyLot or its fingerprints): use Re-analyze.
  Live captures aren't saved to a file, so they can't be re-analyzed
- **"Download from CISA" fails**: pyLot needs HTTPS access to codeload.github.com. Download the
  archive on another machine and import it on the Advisories page instead
- **No identity shown for a PLC**: devices only report their model and firmware when asked. Capture
  while an engineering tool connects to them, or while EtherNet/IP or BACnet discovery runs
- **Upload fails**: The error is shown on the upload page; details are in the server log. For Zeek,
  upload `conn.log` itself, not another log or a directory archive
- **400 Bad Request when browsing by hostname or IP**: Add that name to `PYLOT_TRUSTED_HOSTS`
- **Forgotten password, or locked out**: on the server, `python auth.py passwd NAME` sets a new
  password, and `python auth.py role NAME admin` restores admin rights. A refused sign-in after many
  failures clears itself within 15 minutes, or when pyLot restarts
- **The browser warns about the certificate**: expected with `--self-signed`; compare the fingerprint
  in the server log with the one the browser shows. Use `--cert` and `--key` with a certificate from
  your organization's CA to avoid the warning
- **Very large captures**: Analysis runs at roughly 5,000 to 15,000 packets a second in the
  background, one upload at a time; a 2.3-million-packet capture takes about three minutes. Captures
  full of scans can hold millions of flows, which makes the graph and baseline comparisons take
  several seconds. When more than 200 hosts were reached through routers, the graph
  merges them into one node per router; above 1,500 hosts it is drawn as a plain grid without labels

## Development

Where the project stands and what's planned next is in `PROGRESS.md`.

The application structure:
- `app.py`: Main Flask application
- `storage.py`: SQLite schema and queries
- `inventory.py`: the asset inventory: sightings from each session, matching them to assets, and
  identity changes
- `auth.py`: accounts, roles, sign-in limits and self-signed certificates; also the command-line
  account manager
- `alerts.py`: alert rules, worked out from a session's operations and flows when asked for
- `advisories.py`: CSAF advisory import, version ranges and matching devices to advisories; also a
  command-line importer
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
