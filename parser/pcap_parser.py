import logging
import pyshark
from parser.mac_lookup import lookup_manufacturer
from parser.fingerprint_loader import load_fingerprints
from parser.fingerprint_matcher import match_packet_to_fingerprint

logger = logging.getLogger(__name__)

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

def fingerprint_summary(pkt):
    """Match pkt against all fingerprints and flatten the results to 'name|category|role|ics_protocol; ...'."""
    # Store all matches as a string summary (could be improved to structured storage)
    fp_matches = match_packet_to_fingerprint(pkt, fingerprints)
    return '; '.join([f"{m['fingerprint']}|{m.get('category','')}|{m.get('role','')}|{m.get('ics_protocol','')}" for m in fp_matches])

def parse_pcap(file_path):
    """
    Returns (devices, connections) seen in a capture file. Raises if the file can't be read,
    so callers can report the failure instead of storing an empty result.
    """
    cap = pyshark.FileCapture(file_path)
    devices = {}  # ip -> (ip, mac, vendor); an IP can appear with several MACs, keep the first seen
    connections = set()
    skipped = 0
    try:
        for pkt in cap:
            # Check if packet has IP layer
            if not hasattr(pkt, 'ip'):
                continue
            try:
                ip_src = pkt.ip.src
                ip_dst = pkt.ip.dst
                # Skip if source or destination IP is missing
                if not ip_src or not ip_dst:
                    continue
                # Everything that can fail runs first, so a skipped packet adds nothing
                connection = (ip_src, ip_dst, detect_protocol(pkt), fingerprint_summary(pkt))
                for ip, direction in ((ip_src, 'src'), (ip_dst, 'dst')):
                    if ip not in devices:
                        mac = get_mac(pkt, direction)
                        devices[ip] = (ip, mac, lookup_manufacturer(mac) if mac else '')
                connections.add(connection)
            except Exception:
                skipped += 1
                logger.debug("Error processing packet", exc_info=True)
    finally:
        cap.close()
    if skipped:
        logger.warning("Skipped %d packets in %s that could not be processed", skipped, file_path)
    return list(devices.values()), list(connections)
