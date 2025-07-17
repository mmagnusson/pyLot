import csv
import os
from typing import Dict

_OUI_MAP: Dict[str, str] = {}

def load_oui_database(filename: str):
    print(f"[OUI-DEBUG] load_oui_database called with filename: {repr(filename)}")
    try:
        """
        Loads an OUI (MAC prefix) to manufacturer mapping from a comma-delimited file.
        The file should have the prefix in the first column and the manufacturer in the second column.
        """
        global _OUI_MAP
        _OUI_MAP.clear()
        abs_path = os.path.abspath(filename)
        print(f"[OUI] Attempting to load OUI database from: {abs_path}")
        if not os.path.exists(abs_path):
            print(f"[OUI] ERROR: OUI database file not found: {abs_path}")
            raise FileNotFoundError(f"OUI database file not found: {abs_path}")
        with open(abs_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile, delimiter=',')
            count = 0
            for row in reader:
                if len(row) >= 2:
                    prefix = row[0].strip().upper().replace(':', '').replace('-', '')
                    vendor = row[1].strip()
                    if len(prefix) >= 6:
                        _OUI_MAP[prefix[:6]] = vendor
                        count += 1
        print(f"[OUI] Loaded {count} OUI entries from {abs_path}")
    except Exception as e:
        print(f"[OUI-DEBUG] Unexpected error in load_oui_database: {e}")
        raise

def lookup_manufacturer(mac: str) -> str:
    """
    Looks up the manufacturer for a given MAC address string (format: XX:XX:XX:XX:XX:XX or similar).
    Returns the manufacturer name or 'Unknown Vendor' if not found.
    """
    if not _OUI_MAP:
        raise RuntimeError("OUI database not loaded. Call load_oui_database() first.")
    cleaned = mac.upper().replace(':', '').replace('-', '')
    prefix = cleaned[:6]
    return _OUI_MAP.get(prefix, "Unknown Vendor") 