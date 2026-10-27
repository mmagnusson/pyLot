import logging
import pyshark
from parser.pcap_parser import detect_protocol, get_mac, fingerprint_summary
from parser.mac_lookup import lookup_manufacturer
import sqlite3

logger = logging.getLogger(__name__)

def start_live_capture(interface, db_path):
    """Capture on interface until stopped, adding new devices and connections to db_path."""
    try:
        capture = pyshark.LiveCapture(interface=interface)
        logger.info("Started live capture on interface %s", interface)
        conn = sqlite3.connect(db_path)
        # Only distinct connections are stored, matching what parse_pcap produces for uploads
        seen_connections = set()
        for pkt in capture.sniff_continuously():
            if not hasattr(pkt, 'ip'):
                continue
            try:
                ip_src = pkt.ip.src
                ip_dst = pkt.ip.dst
                new_rows = 0
                for ip, direction in ((ip_src, 'src'), (ip_dst, 'dst')):
                    mac = get_mac(pkt, direction)
                    cur = conn.execute("INSERT INTO devices(ip, mac, vendor) VALUES (?, ?, ?) ON CONFLICT(ip) DO NOTHING",
                                       (ip, mac, lookup_manufacturer(mac) if mac else ''))
                    new_rows += cur.rowcount
                key = (ip_src, ip_dst, detect_protocol(pkt), fingerprint_summary(pkt))
                if key not in seen_connections:
                    seen_connections.add(key)
                    conn.execute("INSERT INTO connections(src, dst, protocol, fingerprint) VALUES (?, ?, ?, ?)", key)
                    new_rows += 1
                # Commit only when something was added; steady-state traffic writes nothing
                if new_rows:
                    conn.commit()
            except Exception:
                logger.warning("Error processing packet", exc_info=True)
                conn.rollback()
    except Exception as e:
        logger.error("Live capture on %s failed: %s", interface, e)
        logger.error("Make sure TShark is installed and you have permission to capture on the interface")
        return False
    return True
