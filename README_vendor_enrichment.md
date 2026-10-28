# Device Vendor Enrichment in pyLot

This document explains how to enable and use device vendor enrichment in the pyLot web application. With this feature, devices detected from PCAP files or live capture will be enriched with vendor information based on their MAC addresses.

## How It Works
- When a PCAP file is uploaded or live capture is running, pyLot records the MAC addresses each IP address is seen with, plus ARP replies.
- The first 3 bytes (OUI) of a host's MAC address are used to look up its vendor in a local OUI database file.
- Hosts on another network arrive with their router's MAC address, so pyLot doesn't credit that MAC to them. A MAC is treated as a router when ARP binds it to a different IPv4 address, or when it carries traffic for more than 3 IP addresses of the same family. Those hosts show "Reached via router" with the router's MAC instead of a vendor.
- Each host's IP, MAC, and vendor are stored in the database and shown when you hover over the host in the graph, in its details panel, and in the Hosts and Devices tabs.

## The OUI Database

pyLot ships with an OUI database at `parser/oui.csv`, so vendor lookup works out of the box. To use a newer or larger list instead, replace that file and restart pyLot.

### 1. Prepare the OUI Database File
- The file must be named `oui.csv` and contain MAC address prefixes (OUIs) and their vendor names.
- Each line should have the prefix and vendor, separated by a comma. Example:

```
001A2B,Acme Corporation
AABBCC,Example Vendor Inc.
```
- Prefixes can be in any case, with or without colons/hyphens (they will be normalized automatically).

### 2. Place the File
- Copy your OUI file over `parser/oui.csv`

### 3. Restart the Application
- Restart pyLot to ensure the OUI database is loaded at startup.
- If the file is missing or invalid, a warning is logged and every device shows 'Unknown Vendor'.

### 4. Using the Feature
- Upload a capture or Zeek conn.log, or start live capture as usual.
- Hosts on the captured network segment are enriched with vendor info, shown in the graph's host details.

## Troubleshooting
- If you see 'Unknown Vendor', the MAC prefix was not found in your OUI file.
- Ensure the OUI file is present and formatted correctly.
- Check the application logs for any warnings about loading the OUI database.

## Customization
- You can use a more complete OUI database (e.g., from IEEE or Wireshark) for better coverage.
- The lookup logic is in `parser/mac_lookup.py` if you wish to customize it.

---

Device type and role come from fingerprints; see the main README. 