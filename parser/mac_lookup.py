import csv
import logging
import os
from typing import Dict

logger = logging.getLogger(__name__)

DEFAULT_OUI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'oui.csv')
UNKNOWN_VENDOR = 'Unknown Vendor'

_OUI_MAP: Dict[str, str] = {}

def load_oui_database(filename: str = DEFAULT_OUI_PATH) -> int:
    """
    Loads an OUI (MAC prefix) to manufacturer mapping from a comma-delimited file.
    The file should have the prefix in the first column and the manufacturer in the second column.
    Returns the number of entries loaded. A missing or unreadable file logs a warning and
    leaves vendor lookup returning UNKNOWN_VENDOR instead of raising.
    """
    global _OUI_MAP
    oui_map: Dict[str, str] = {}
    try:
        with open(filename, newline='', encoding='utf-8') as csvfile:
            for row in csv.reader(csvfile, delimiter=','):
                if len(row) >= 2:
                    prefix = row[0].strip().upper().replace(':', '').replace('-', '')
                    if len(prefix) >= 6:
                        # Vendor names can contain unquoted commas, and a few end with a stray one
                        oui_map[prefix[:6]] = ','.join(row[1:]).strip().rstrip(',').strip()
    except OSError as e:
        logger.warning("OUI database not loaded, vendor lookup disabled: %s", e)
        return 0
    # Swap in the finished map in one step so lookups on other threads never see a half-built table
    _OUI_MAP = oui_map
    logger.info("Loaded %d OUI entries from %s", len(oui_map), filename)
    return len(oui_map)

def lookup_manufacturer(mac: str) -> str:
    """
    Looks up the manufacturer for a given MAC address string (format: XX:XX:XX:XX:XX:XX or similar).
    Returns the manufacturer name, or UNKNOWN_VENDOR if it isn't found or no database is loaded.
    """
    cleaned = mac.upper().replace(':', '').replace('-', '')
    return _OUI_MAP.get(cleaned[:6], UNKNOWN_VENDOR)

load_oui_database()
