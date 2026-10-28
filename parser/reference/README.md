# Lookup tables

Fingerprint Extracts with a `Lookup` turn a numeric ID into a name using these tables, one `id,name`
row per entry:

- `ENIPVENDOR.csv`: EtherNet/IP (CIP) vendor IDs
- `ENIPDEVICE.csv`: EtherNet/IP (CIP) device types
- `BACNET.csv`: BACnet vendor IDs

They are derived from GRASSMARLIN 3.2 by the National Security Agency
(https://github.com/nsacyber/GRASSMARLIN, `GM3/data/reference`: `enipVendors.csv`, `enipDevice.csv`
and `BACnetVendors.htm`). Like GRASSMARLIN, they are licensed under the GNU Lesser General Public
License, version 3 (LGPL-3.0): see `fingerprints/COPYING.LESSER` and `fingerprints/COPYING`.

## Changes from GRASSMARLIN

In October 2026 the tables were converted to CSV files named after the lookup they serve. Names that
contain commas are quoted, and the BACnet table keeps only the vendor ID and organization columns,
without contacts and addresses. IDs and names are otherwise unchanged.

The lists stop where GRASSMARLIN's did; vendors registered since then show their numeric ID. To
update one, replace its rows with the current list from ODVA (EtherNet/IP) or ASHRAE (BACnet).
