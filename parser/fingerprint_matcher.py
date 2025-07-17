from parser.fingerprint_loader import load_fingerprints
import binascii

def extract_int(val, default=None):
    if isinstance(val, dict):
        val = val.get('_text', default)
    if val is None:
        return default
    try:
        return int(val)
    except Exception:
        return default

def get_packet_ports(pkt):
    proto = None
    src_port = None
    dst_port = None
    # Try TCP/UDP
    if hasattr(pkt, 'tcp'):
        proto = 6
        src_port = int(pkt.tcp.srcport)
        dst_port = int(pkt.tcp.dstport)
    elif hasattr(pkt, 'udp'):
        proto = 17
        src_port = int(pkt.udp.srcport)
        dst_port = int(pkt.udp.dstport)
    return proto, src_port, dst_port

def get_packet_payload(pkt):
    # Try to get raw payload as hex string
    try:
        if hasattr(pkt, 'data') and hasattr(pkt.data, 'data'):
            return pkt.data.data.replace(':', '').lower()
        elif hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload'):
            return pkt.tcp.payload.replace(':', '').lower()
        elif hasattr(pkt, 'udp') and hasattr(pkt.udp, 'payload'):
            return pkt.udp.payload.replace(':', '').lower()
    except Exception:
        pass
    return None

def match_content(payload, content):
    # Only support HEX content for now
    if not payload or not content:
        return False
    if isinstance(content, dict):
        content = content.get('_text', '')
    content = content.lower().replace(' ', '')
    return content in payload

def match_packet_to_fingerprint(pkt, fingerprints):
    matches = []
    proto, src_port, dst_port = get_packet_ports(pkt)
    payload = get_packet_payload(pkt)
    if proto is None:
        return matches
    for fp in fingerprints:
        fp_data = fp.get('fingerprint', fp)
        filters = fp_data.get('filter', [])
        if not isinstance(filters, list):
            filters = [filters]
        filter_match = False
        for f in filters:
            f = f.get('filter', f)
            f_proto = extract_int(f.get('transportprotocol', f.get('transport_protocol', proto)), None) if 'transportprotocol' in f or 'transport_protocol' in f else None
            f_src = extract_int(f.get('srcport', f.get('src_port', -1)), -1) if 'srcport' in f or 'src_port' in f else None
            f_dst = extract_int(f.get('dstport', f.get('dst_port', -1)), -1) if 'dstport' in f or 'dst_port' in f else None
            if f_proto is not None and proto != f_proto:
                continue
            if f_src is not None and f_src != -1 and src_port != f_src:
                continue
            if f_dst is not None and f_dst != -1 and dst_port != f_dst:
                continue
            filter_match = True
            break
        if not filter_match:
            continue
        header = fp_data.get('header', {})
        name = header.get('name') if isinstance(header, dict) else None
        payloads = fp_data.get('payload', [])
        if not isinstance(payloads, list):
            payloads = [payloads]
        for p in payloads:
            p = p.get('payload', p)
            # Content/Match block support
            match_found = False
            if 'match' in p:
                match_blocks = p['match']
                if not isinstance(match_blocks, list):
                    match_blocks = [match_blocks]
                for m in match_blocks:
                    m = m.get('match', m)
                    content = m.get('content')
                    if match_content(payload, content):
                        match_found = True
                        break
            else:
                match_found = True  # No match block, so filter match is enough
            if not match_found:
                continue
            details = None
            if 'always' in p and 'return' in p['always']:
                ret = p['always']['return']
                details = ret.get('details', {})
            match_info = {
                'fingerprint': name,
                'category': details.get('category') if details else None,
                'role': details.get('role') if details else None,
                'ics_protocol': details.get('ics_protocol') or details.get('detail', {}).get('icsprotocol') if details else None,
            }
            matches.append(match_info)
    return matches 