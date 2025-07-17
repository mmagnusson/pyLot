import pyshark
from parser.pcap_parser import detect_protocol
import sqlite3
import sys

def start_live_capture(interface='eth0'):
    try:
        capture = pyshark.LiveCapture(interface=interface)
        print(f"Started live capture on interface {interface}")
        
        for pkt in capture.sniff_continuously():
            try:
                ip_src = pkt.ip.src
                ip_dst = pkt.ip.dst
                proto = detect_protocol(pkt)
                conn = sqlite3.connect('db.sqlite3')
                cur = conn.cursor()
                cur.execute("INSERT INTO devices(ip, mac, vendor) VALUES (?, ?, ?) ON CONFLICT(ip) DO NOTHING", (ip_src, '', ''))
                cur.execute("INSERT INTO devices(ip, mac, vendor) VALUES (?, ?, ?) ON CONFLICT(ip) DO NOTHING", (ip_dst, '', ''))
                cur.execute("INSERT INTO connections(src, dst, protocol) VALUES (?, ?, ?)", (ip_src, ip_dst, proto))
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
