# Device Vendor Enrichment in pyLot

This document explains how to enable and use device vendor enrichment in the pyLot web application. With this feature, devices detected from PCAP files or live capture will be enriched with vendor information based on their MAC addresses.

## How It Works
- When a PCAP file is uploaded or live capture is running, pyLot extracts MAC addresses from packets (when available).
- The first 3 bytes (OUI) of each MAC address are used to look up the device vendor using a local OUI database file.
- The device's IP, MAC, and vendor are stored in the database and shown in the UI (if configured).

## Setup Instructions

### 1. Prepare the OUI Database File
- You need a file containing MAC address prefixes (OUIs) and their corresponding vendor names.
- The file should be named `oui.csv` and placed in the `pylot/parser/` directory.
- Each line should have the prefix and vendor, separated by a comma or tab. Example:

```
001A2B,Acme Corporation
AABBCC,Example Vendor Inc.
```
- Prefixes can be in any case, with or without colons/hyphens (they will be normalized automatically).

### 2. Place the File
- Copy your OUI file to: `pylot/parser/oui.csv`

### 3. Restart the Application
- Restart pyLot to ensure the OUI database is loaded at startup.
- If the file is missing or invalid, a warning will be printed and vendor enrichment will be skipped.

### 4. Using the Feature
- Upload a PCAP file or start live capture as usual.
- Devices with detected MAC addresses will be enriched with vendor info in the database.
- (Optional) Update the UI to display vendor info for each device.

## Troubleshooting
- If you see 'Unknown Vendor', the MAC prefix was not found in your OUI file.
- Ensure the OUI file is present and formatted correctly.
- Check the application logs for any warnings about loading the OUI database.

## Customization
- You can use a more complete OUI database (e.g., from IEEE or Wireshark) for better coverage.
- The lookup logic is in `pylot/parser/mac_lookup.py` if you wish to customize it.

---

For further enhancements (device type, fingerprinting, etc.), see the main README or contact the project maintainer. 