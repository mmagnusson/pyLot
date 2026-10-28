"""
Decode the layer-2 protocols that announce or reveal devices without IP: LLDP, CDP and STP from network
gear, and the industrial protocols that run straight on Ethernet (PROFINET, IEC 61850 GOOSE and Sampled
Values, EtherCAT, POWERLINK, MRP).

decode() returns the protocol name and what the frame says about its sender, as (name, value, confidence)
properties in GRASSMARLIN's vocabulary: Category, Role and ICSProtocol, plus protocol-specific fields such
as SystemName or NameOfStation. Confidence is 1 when the device describes itself, higher when it is inferred.
"""
import socket
import struct

ETHERTYPE_NAMES = {
    0x0842: 'Wake-on-LAN', 0x22F0: 'AVTP', 0x22EA: 'SRP', 0x6002: 'DEC MOP', 0x8035: 'RARP', 0x809B: 'AppleTalk',
    0x8137: 'IPX', 0x8808: 'Ethernet flow control', 0x8809: 'LACP', 0x8847: 'MPLS', 0x8848: 'MPLS',
    0x8863: 'PPPoE discovery', 0x8864: 'PPPoE', 0x886D: 'Intel ANS', 0x888E: 'EAPOL', 0x8892: 'PROFINET',
    0x889A: 'HyperSCSI', 0x88A2: 'ATA over Ethernet', 0x88A4: 'EtherCAT', 0x88A8: 'Q-in-Q', 0x88AB: 'POWERLINK',
    0x88B8: 'IEC 61850 GOOSE', 0x88B9: 'GSE Management', 0x88BA: 'IEC 61850 Sampled Values', 0x88CC: 'LLDP',
    0x88CD: 'SERCOS III', 0x88E1: 'HomePlug AV', 0x88E3: 'MRP', 0x88E5: 'MACsec', 0x88E7: 'PBB', 0x88F7: 'PTP',
    0x88FB: 'PRP supervision', 0x8902: 'CFM', 0x8906: 'FCoE', 0x8914: 'FCoE init', 0x892F: 'HSR', 0x893A: 'IEEE 1905',
    0x8899: 'Realtek RRCP', 0x9000: 'Loopback (CTP)', 0x0806: 'ARP',
}
LLDP_CAPABILITIES = ['Other', 'Repeater', 'Bridge', 'WLAN AP', 'Router', 'Telephone', 'DOCSIS', 'Station',
                     'C-VLAN', 'S-VLAN', 'TPMR']
CDP_CAPABILITIES = ['Router', 'Transparent bridge', 'Source-route bridge', 'Switch', 'Host', 'IGMP', 'Repeater',
                    'VoIP phone', 'Remotely managed', 'CVTA', 'Two-port MAC relay']
INFRASTRUCTURE = {'Bridge', 'Router', 'WLAN AP', 'Repeater', 'Switch', 'Transparent bridge', 'Source-route bridge',
                  'C-VLAN', 'S-VLAN', 'TPMR'}
DCP_HELLO = 0x06  # service IDs: 3 Get, 4 Set, 5 Identify, 6 Hello
PROFINET_ROLES = {0x01: 'IO-Device', 0x02: 'IO-Controller', 0x04: 'IO-Multidevice', 0x08: 'PN-Supervisor'}

def ethertype_name(ethertype):
    return ETHERTYPE_NAMES.get(ethertype, f'EtherType 0x{ethertype:04x}')

def decode(ethertype, payload, dst_mac):
    """
    (protocol, [(name, value, confidence)]) for a non-IP frame. ethertype is None for 802.3 frames, whose
    payload starts at the LLC header. Malformed frames still get a protocol name, with what was decoded.
    """
    if ethertype is None:
        return _decode_llc(payload, dst_mac)
    decoder = DECODERS.get(ethertype)
    properties = []
    if decoder:
        try:
            decoder(payload, properties)
        except (IndexError, struct.error, ValueError, UnicodeDecodeError):
            pass
    if ethertype == 0x8892:
        return _profinet_name(payload), properties
    return ethertype_name(ethertype), properties

def _text(data):
    return data.decode('utf-8', 'replace').replace('\x00', '').strip()

def _mac(data):
    return data.hex(':')

def _capabilities(bits, names):
    return [name for i, name in enumerate(names) if bits & (1 << i)]

def _infrastructure(capabilities, properties, confidence):
    if INFRASTRUCTURE.intersection(capabilities):
        properties.append(('Category', 'NETWORK_DEVICE', confidence))

# --- LLDP

def _lldp(payload, properties):
    offset = 0
    capabilities = []
    while offset + 2 <= len(payload):
        header, = struct.unpack_from('>H', payload, offset)
        kind, length = header >> 9, header & 0x1FF
        value = payload[offset + 2:offset + 2 + length]
        offset += 2 + length
        if kind == 0:
            break
        if kind == 1 and value:
            properties.append(('ChassisID', _mac(value[1:]) if value[0] == 4 and len(value) == 7 else _text(value[1:]), 1))
        elif kind == 2 and value:
            properties.append(('PortID', _mac(value[1:]) if value[0] == 3 and len(value) == 7 else _text(value[1:]), 1))
        elif kind == 4:
            properties.append(('PortDescription', _text(value), 1))
        elif kind == 5:
            properties.append(('SystemName', _text(value), 1))
        elif kind == 6:
            properties.append(('SystemDescription', _text(value), 1))
        elif kind == 7 and len(value) >= 4:
            capabilities = _capabilities(struct.unpack_from('>H', value, 2)[0], LLDP_CAPABILITIES)  # enabled ones
            if capabilities:
                properties.append(('Capabilities', ', '.join(capabilities), 1))
        elif kind == 8 and len(value) >= 2:
            address = _address(value[1], value[2:1 + value[0]])
            if address:
                properties.append(('ManagementAddress', address, 1))
    _infrastructure(capabilities, properties, 1)
    properties[:] = [p for p in properties if p[1]]

def _address(family, data):
    """IANA address family 1 is IPv4, 2 is IPv6."""
    if family == 1 and len(data) == 4:
        return socket.inet_ntop(socket.AF_INET, data)
    if family == 2 and len(data) == 16:
        return socket.inet_ntop(socket.AF_INET6, data)
    return None

# --- 802.3/LLC: CDP and STP

def _decode_llc(payload, dst_mac):
    if payload[:3] == b'\xaa\xaa\x03' and payload[3:8] == b'\x00\x00\x0c\x20\x00':
        properties = []
        try:
            _cdp(payload[8:], properties)
        except (IndexError, struct.error, ValueError):
            pass
        return 'CDP', properties
    if payload[:2] == b'\x42\x42':
        properties = []
        try:
            _stp(payload[3:], properties)
        except (IndexError, struct.error):
            pass
        return 'STP', properties
    if payload[:3] == b'\xaa\xaa\x03' and payload[3:8] == b'\x00\x00\x0c\x01\x0b':
        # Cisco's per-VLAN spanning tree: an ordinary BPDU after a SNAP header
        properties = []
        try:
            _stp(payload[8:], properties)
        except (IndexError, struct.error):
            pass
        return 'PVST+', properties
    if payload[:3] == b'\xaa\xaa\x03' and payload[3:6] == b'\x00\x00\x0c':
        return 'Cisco SNAP', []
    return 'LLC', []

def _cdp(payload, properties):
    offset = 4  # version, TTL, checksum
    capabilities = []
    while offset + 4 <= len(payload):
        kind, length = struct.unpack_from('>HH', payload, offset)
        if length < 4:
            break
        value = payload[offset + 4:offset + length]
        offset += length
        if kind == 0x0001:
            properties.append(('SystemName', _text(value), 1))
        elif kind == 0x0002:
            address = _cdp_address(value)
            if address:
                properties.append(('ManagementAddress', address, 1))
        elif kind == 0x0003:
            properties.append(('PortID', _text(value), 1))
        elif kind == 0x0004 and len(value) == 4:
            capabilities = _capabilities(struct.unpack('>I', value)[0], CDP_CAPABILITIES)
            if capabilities:
                properties.append(('Capabilities', ', '.join(capabilities), 1))
        elif kind == 0x0005:
            properties.append(('SystemDescription', _text(value), 1))
        elif kind == 0x0006:
            properties.append(('Platform', _text(value), 1))
        elif kind == 0x000A and len(value) == 2:
            properties.append(('NativeVLAN', str(struct.unpack('>H', value)[0]), 1))
    _infrastructure(capabilities, properties, 1)
    properties[:] = [p for p in properties if p[1]]

def _cdp_address(value):
    """The first IPv4 address in a CDP Addresses TLV."""
    count, = struct.unpack_from('>I', value, 0)
    offset = 4
    for _ in range(count):
        protocol_type, protocol_length = value[offset], value[offset + 1]
        protocol = value[offset + 2:offset + 2 + protocol_length]
        offset += 2 + protocol_length
        address_length, = struct.unpack_from('>H', value, offset)
        address = value[offset + 2:offset + 2 + address_length]
        offset += 2 + address_length
        if protocol_type == 1 and protocol == b'\xcc' and address_length == 4:
            return socket.inet_ntop(socket.AF_INET, address)
    return None

def _bridge_id(data):
    priority, = struct.unpack('>H', data[:2])
    return f'{priority >> 12 << 12}.{data[2:8].hex(":")}'  # priority without the extended system ID (VLAN)

def _stp(payload, properties):
    # protocol ID (2), version (1), BPDU type (1), flags (1), root ID (8), root path cost (4), bridge ID (8), port ID (2)
    if len(payload) < 4 or payload[3] not in (0x00, 0x02):
        return  # topology change notification: says nothing about the bridge
    properties.append(('Category', 'NETWORK_DEVICE', 1))
    properties.append(('RootBridgeID', _bridge_id(payload[5:13]), 1))
    properties.append(('BridgeID', _bridge_id(payload[17:25]), 1))
    properties.append(('STPPort', f'0x{struct.unpack_from(">H", payload, 25)[0]:04x}', 1))

# --- PROFINET

def _profinet_name(payload):
    frame_id = struct.unpack_from('>H', payload, 0)[0] if len(payload) >= 2 else None
    if frame_id is None:
        return 'PROFINET'
    if 0xFEFC <= frame_id <= 0xFEFF:
        return 'PROFINET DCP'
    if frame_id in (0xFC01, 0xFE01):
        return 'PROFINET alarm'
    if 0x0100 <= frame_id <= 0x7FFF:
        return 'PROFINET IRT'
    if 0x8000 <= frame_id <= 0xFBFF:
        return 'PROFINET RT'
    if 0xFF00 <= frame_id <= 0xFF43:
        return 'PROFINET PTCP'
    return 'PROFINET'

def _profinet(payload, properties):
    frame_id, = struct.unpack_from('>H', payload, 0)
    properties.append(('ICSProtocol', 'PROFINET', 1 if frame_id >= 0xFEFC else 3))
    if frame_id == 0xFEFE:
        # An Identify request for all devices comes from a controller or engineering tool scanning the network.
        # One filtered on a name says nothing about the sender: devices look for their own name at startup
        # to catch duplicates, and controllers look up their devices by name.
        if payload[12:14] == b'\xff\xff':
            properties.append(('Role', 'MASTER', 3))
        return
    if not 0xFEFC <= frame_id <= 0xFEFF:
        return
    service_id, service_type = payload[2], payload[3]
    response = service_type & 0x01 == 1
    # Responses and Hello announcements describe the sender. Other requests don't: the name in an Identify
    # request is the device being looked for, and a Set request's address is for the device being set.
    if not response and service_id != DCP_HELLO:
        return
    data_length, = struct.unpack_from('>H', payload, 10)
    offset, end = 12, min(12 + data_length, len(payload))
    while offset + 4 <= end:
        option, suboption = payload[offset], payload[offset + 1]
        length, = struct.unpack_from('>H', payload, offset + 2)
        block = payload[offset + 6:offset + 4 + length]  # after the 2-byte BlockInfo responses and Hellos carry
        offset += 4 + length + (length & 1)
        if (option, suboption) == (2, 1):
            properties.append(('TypeOfStation', _text(block), 1))
        elif (option, suboption) == (2, 2):
            properties.append(('NameOfStation', _text(block), 1))
        elif (option, suboption) == (2, 3) and len(block) >= 4:
            vendor, device = struct.unpack_from('>HH', block)
            properties.append(('VendorID', f'0x{vendor:04x}', 1))
            properties.append(('DeviceID', f'0x{device:04x}', 1))
        elif (option, suboption) == (2, 4) and block:
            roles = [name for bit, name in PROFINET_ROLES.items() if block[0] & bit]
            for role in roles:
                properties.append(('DeviceRole', role, 1))
            if 'IO-Controller' in roles:
                properties += [('Category', 'PLC', 1), ('Role', 'MASTER', 1)]
            elif 'IO-Device' in roles:
                properties += [('Category', 'ICS_HOST', 2), ('Role', 'SLAVE', 1)]
            elif 'PN-Supervisor' in roles:
                properties += [('Category', 'WORKSTATION', 2), ('Role', 'ENGINEER', 1)]
        elif (option, suboption) == (1, 2) and len(block) >= 12:
            ip, mask, gateway = (socket.inet_ntop(socket.AF_INET, block[i:i + 4]) for i in (0, 4, 8))
            if ip != '0.0.0.0':
                properties += [('IPAddress', ip, 1), ('Netmask', mask, 1)]
            if gateway != '0.0.0.0':
                properties.append(('Gateway', gateway, 1))
    properties[:] = [p for p in properties if p[1]]

# --- IEC 61850

def _ber(data, offset):
    """(tag, value, next offset) for one BER element."""
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset:offset + count], 'big')
        offset += count
    return tag, data[offset:offset + length], offset + length

def _goose(payload, properties):
    properties += [('ICSProtocol', 'IEC 61850 GOOSE', 1), ('Category', 'IED', 2)]
    appid, = struct.unpack_from('>H', payload, 0)
    properties.append(('APPID', f'0x{appid:04x}', 1))
    tag, pdu, _ = _ber(payload, 8)
    if tag != 0x61:
        return
    names = {0x80: 'GoCBRef', 0x82: 'DataSet', 0x83: 'GoID'}
    offset = 0
    while offset < len(pdu):
        tag, value, offset = _ber(pdu, offset)
        if tag in names:
            properties.append((names[tag], _text(value), 1))

def _sampled_values(payload, properties):
    properties += [('ICSProtocol', 'IEC 61850 Sampled Values', 1), ('Category', 'IED', 2)]
    appid, = struct.unpack_from('>H', payload, 0)
    properties.append(('APPID', f'0x{appid:04x}', 1))
    tag, pdu, _ = _ber(payload, 8)
    if tag != 0x60:
        return
    offset = 0
    while offset < len(pdu):
        tag, value, offset = _ber(pdu, offset)
        if tag == 0xA2:  # sequence of ASDUs; the first one's svID names the stream
            _, asdu, _ = _ber(value, 0)
            tag, sv_id, _ = _ber(asdu, 0)
            if tag == 0x80:
                properties.append(('SvID', _text(sv_id), 1))
            return

# --- other industrial Ethernet

def _ethercat(payload, properties):
    properties.append(('ICSProtocol', 'EtherCAT', 2))

POWERLINK_TYPES = {0x01: 'SoC', 0x03: 'PReq', 0x04: 'PRes', 0x05: 'SoA', 0x06: 'ASnd'}

def _powerlink(payload, properties):
    properties.append(('ICSProtocol', 'POWERLINK', 1))
    message_type, src_node = payload[0] & 0x7F, payload[2]
    properties.append(('NodeID', str(src_node), 1))
    # Node 240 is the managing node, which polls the controlled nodes
    if src_node == 240:
        properties.append(('Role', 'MASTER', 1))
    elif POWERLINK_TYPES.get(message_type) == 'PRes':
        properties.append(('Role', 'SLAVE', 1))

def _mrp(payload, properties):
    properties += [('Category', 'NETWORK_DEVICE', 2), ('ICSProtocol', 'MRP', 2)]

DECODERS = {0x88CC: _lldp, 0x8892: _profinet, 0x88B8: _goose, 0x88BA: _sampled_values, 0x88A4: _ethercat,
            0x88AB: _powerlink, 0x88E3: _mrp}
