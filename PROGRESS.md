# pyLot progress notes

Where the project stands and what comes next, so work can pick up on any machine. Last updated
2026-10-30.

## Goal

pyLot is a rewrite of NSA's GRASSMARLIN (passive ICS/SCADA network mapping) as a Python/Flask web
application. Judge features against GRASSMARLIN's (logical and physical views, its fingerprint
grammar and confidence rules, sessions), then go beyond it for ICS/OT work.

## Done

| Commit | What |
|---|---|
| `265c044` | Phase 0: safe uploads (random names, type checks), correct results, history purged of captures and databases |
| `8b00a88` | Phase 1: dpkt packet pipeline (replaced pyshark, ~75x faster), GRASSMARLIN fingerprint engine with its semantics, sessions in SQLite, dumpcap live capture, pytest suite |
| `b78dd1c` | Phase 2: session page, background analysis, live capture from the UI, network grouping, merging hosts behind routers, tables, details panel, exports |
| `4428e80` | Phase 3: named networks, layer-2 decoding (LLDP, CDP, STP, PROFINET, GOOSE, SV, EtherCAT, POWERLINK, MRP), Cisco switch import and physical view, devices tab, baseline compare |
| `28fb16a` | Zeek conn.log import, baseline changes on the graph, GRASSMARLIN's ENIP/BACnet vendor tables |
| `1190940` | Roadmap 1 and 2: validated against 474 real ICS captures (fixes for crashes, PROFINET DCP, PVST+, vendor names, speed); Re-analyze buttons |
| `c171e2a` | Roadmap 3 and 5: industrial protocol decoders (Modbus/UMAS, DNP3, S7comm, EtherNet/IP and CIP, IEC 104, BACnet, SNMP, banners) giving operations and asset identity (vendor, model, firmware, serial) |
| `6350a64` | Roadmap 4: risky-activity alerts (13 rules, high/medium/low), Alerts tab, new alerts on the compare page |
| `d952794` | Roadmap 6: vulnerability matching against CSAF advisories (CISA download or file import), Vulnerabilities tab, host panel section, new vulnerabilities on the compare page |

Tests: 215 pass, 1 skipped (it needs a GRASSMARLIN checkout; see the README).

## Roadmap: what's left

The roadmap agreed after Phase 3, in its original numbering. 1 to 6 are done.

7. **Persistent asset inventory**: assets that outlive sessions, merged across captures by MAC,
   serial or IP, with first and last seen and a history of identity changes.
8. **Authentication and HTTPS**: logins and TLS. Needed before pyLot listens on anything but localhost.
9. **Capture rotation and performance**: long-running live capture with ring files, and faster
   analysis of multi-million-packet captures (fingerprint matching and dpkt dominate the time).
10. **Switch formats beyond Cisco**: Hirschmann, Siemens SCALANCE, Moxa, Juniper and others for the
    physical view.
11. **Deployment**: Docker image and a systemd unit.
12. **Reports**: a printable or PDF summary of a session: assets, identity, alerts, changes since a baseline.

Suggested next: 8 (before opening pyLot to a network) or 7 (an asset inventory would let vulnerabilities
and identity carry across sessions).

## Known gaps in what's built

- **Decoders**:
  - MMS / IEC 61850 is not decoded. Its identity replies would cover substation IEDs, and 21 of the test captures contain it.
  - Rockwell PCCC commands and S7comm-plus functions are recognised but not broken down.
- **Alerts**: no way to dismiss an alert or allow-list expected activity (baseline comparison is the workaround), and no alert markers on the graph.
- **Vulnerabilities**:
  - Matching works from what devices report, so devices that never sent an identity reply aren't checked,
    and layer-2-only devices (PROFINET DCP without IP) aren't matched yet.
  - About 8% of CISA's version ranges are free text pyLot can't read; those matches are "possibly affected".
  - Product-family matches use a small table in `advisories.py` (`FAMILIES`: Siemens S7 order numbers,
    Rockwell catalog numbers); other vendors only match by model number or product name.
  - CSAF relationships (a component installed on a product) are ignored, and NVD/CPE data isn't used.
  - Checked against the real captures: ENBT, ControlLogix L61, MicroLogix 1400, S7-300, S7-1200 and
    ET 200S all match the expected CISA advisories.
- **Zeek imports**: no operations, identity or alerts, since conn.log has no payloads.
- **Modbus identity**: Read Device Identification replies are covered only by unit tests; none of the test captures has a successful one.

## Picking up on another machine

```bash
git clone https://github.com/mmagnusson/pyLot.git && cd pyLot
python3 -m venv venv && venv/bin/python -m pip install -r requirements-dev.txt
venv/bin/python -m pytest
venv/bin/python app.py            # http://127.0.0.1:5000
```

- tshark/capinfos are only needed for cross-checking decoders. Live capture needs dumpcap and
  membership of the `wireshark` group.
- Keep pyLot bound to 127.0.0.1 (the default) until roadmap item 8 is done; reach it remotely with
  an SSH tunnel: `ssh -L 5000:127.0.0.1:5000 <user>@<host>`.

### Test data

Real-world validation uses a local folder of third-party ICS captures, `ICS-DATA_DO-NOT-COMMIT/`
(public sets such as ICS-pcap and ICS-Security-Tools, 474 captures and 91 Zeek logs). It is
gitignored and must never be committed (check with `git status --ignored`); copy it across separately.

The batch, tshark-comparison and browser-check scripts used for validation were not kept in the
repository. To recreate the checks:
- Run every capture through `parser.pcap_parser.parse_file` and compare packet counts with `capinfos`.
- Compare decoded request counts per protocol with tshark fields (`modbus.func_code`, `dnp3.al.func`,
  `s7comm.param.func`, `cip.service`).
- Drive the session page with headless Chromium (Playwright) and check for console errors.

## Conventions

- Work on a branch, then fast-forward `main` and push. Commit and push only when asked.
- Fingerprints in `fingerprints/` and the tables in `parser/reference/` are LGPL-3.0 (from GRASSMARLIN);
  the rest is MIT.
- Text that comes from captured traffic only reaches the page as textContent, and CSV cells that
  would start a spreadsheet formula are prefixed with an apostrophe.
- Decoders report nothing until a message parses as its protocol; validate new ones against tshark
  on the test captures.
