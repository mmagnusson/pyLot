import pyshark
from parser.pcap_parser import detect_protocol, get_mac
from parser.mac_lookup import lookup_manufacturer, load_oui_database
from parser.fingerprint_loader import load_fingerprints
from parser.fingerprint_matcher import match_packet_to_fingerprint
import sqlite3
import sys
import os

fingerprints = load_fingerprints()

def start_live_capture(interface='eth0'):
    # Ensure OUI database is loaded in this process/thread
    oui_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../parser/oui.csv'))
    print(f"[DEBUG] Loading OUI database in start_live_capture from: {oui_path}")
    try:
        load_oui_database(oui_path)
    except Exception as e:
        print(f"[DEBUG] Failed to load OUI database: {e}")
    try:
        capture = pyshark.LiveCapture(interface=interface)
        print(f"Started live capture on interface {interface}")
        
        for pkt in capture.sniff_continuously():
            try:
                ip_src = pkt.ip.src
                ip_dst = pkt.ip.dst
                proto = detect_protocol(pkt)
                mac_src = get_mac(pkt, 'src')
                mac_dst = get_mac(pkt, 'dst')
                vendor_src = lookup_manufacturer(mac_src) if mac_src else ''
                vendor_dst = lookup_manufacturer(mac_dst) if mac_dst else ''
                # Fingerprint matching
                fp_matches = match_packet_to_fingerprint(pkt, fingerprints)
                fp_summary = '; '.join([f"{m['fingerprint']}|{m.get('category','')}|{m.get('role','')}|{m.get('ics_protocol','')}" for m in fp_matches]) if fp_matches else ''
                conn = sqlite3.connect('db.sqlite3')
                cur = conn.cursor()
                cur.execute("INSERT INTO devices(ip, mac, vendor) VALUES (?, ?, ?) ON CONFLICT(ip) DO NOTHING", (ip_src, mac_src, vendor_src))
                cur.execute("INSERT INTO devices(ip, mac, vendor) VALUES (?, ?, ?) ON CONFLICT(ip) DO NOTHING", (ip_dst, mac_dst, vendor_dst))
                cur.execute("INSERT INTO connections(src, dst, protocol, fingerprint) VALUES (?, ?, ?, ?)", (ip_src, ip_dst, proto, fp_summary))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue
    except Exception as e:
        print(f"Live capture failed: {e}")
        print("Make sure TShark is installed and you have permission to capture on the interface")
        return False
    return True
