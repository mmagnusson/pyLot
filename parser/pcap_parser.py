import pyshark
from parser.mac_lookup import lookup_manufacturer, load_oui_database
from parser.fingerprint_loader import load_fingerprints
from parser.fingerprint_matcher import match_packet_to_fingerprint
import os

fingerprints = load_fingerprints()

def detect_protocol(pkt):
    try:
        # Check for specific protocols in the packet layers
        if hasattr(pkt, 'modbus'):
            return 'Modbus'
        elif hasattr(pkt, 'dnp3'):
            return 'DNP3'
        elif hasattr(pkt, 'bacnet'):
            return 'BACnet'
        elif hasattr(pkt, 'tcp'):
            if pkt.tcp.dstport == '502':
                return 'Modbus'
            elif pkt.tcp.dstport == '20000':
                return 'DNP3'
        elif hasattr(pkt, 'udp'):
            if pkt.udp.dstport == '47808':
                return 'BACnet'
        # Return the highest layer if no specific protocol is detected
        return pkt.highest_layer if hasattr(pkt, 'highest_layer') else 'Unknown'
    except Exception as e:
        return 'Unknown'

def get_mac(pkt, direction='src'):
    # Try to extract MAC address from Ethernet layer
    try:
        if hasattr(pkt, 'eth'):
            if direction == 'src' and hasattr(pkt.eth, 'src'):
                return pkt.eth.src
            elif direction == 'dst' and hasattr(pkt.eth, 'dst'):
                return pkt.eth.dst
    except Exception:
        pass
    return ''

def parse_pcap(file_path):
    # Ensure OUI database is loaded in this process/thread
    oui_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'oui.csv'))
    print(f"[DEBUG] Loading OUI database in parse_pcap from: {oui_path}")
    try:
        load_oui_database(oui_path)
    except Exception as e:
        print(f"[DEBUG] Failed to load OUI database: {e}")
    try:
        cap = pyshark.FileCapture(file_path)
        devices = set()
        connections = set()

        for pkt in cap:
            try:
                # Check if packet has IP layer
                if not hasattr(pkt, 'ip'):
                    continue
                ip_src = pkt.ip.src
                ip_dst = pkt.ip.dst
                # Skip if source or destination IP is missing
                if not ip_src or not ip_dst:
                    continue
                proto = detect_protocol(pkt)
                mac_src = get_mac(pkt, 'src')
                mac_dst = get_mac(pkt, 'dst')
                vendor_src = lookup_manufacturer(mac_src) if mac_src else ''
                vendor_dst = lookup_manufacturer(mac_dst) if mac_dst else ''
                # Fingerprint matching
                fp_matches = match_packet_to_fingerprint(pkt, fingerprints)
                # Store all matches as a string summary (could be improved to structured storage)
                fp_summary = '; '.join([f"{m['fingerprint']}|{m.get('category','')}|{m.get('role','')}|{m.get('ics_protocol','')}" for m in fp_matches]) if fp_matches else ''
                devices.add((ip_src, mac_src, vendor_src))
                devices.add((ip_dst, mac_dst, vendor_dst))
                connections.add((ip_src, ip_dst, proto, fp_summary))
            except AttributeError as e:
                # Skip packets without required attributes
                continue
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue
        cap.close()
        return list(devices), list(connections)
    except Exception as e:
        print(f"Error parsing PCAP file: {e}")
        return [], []
