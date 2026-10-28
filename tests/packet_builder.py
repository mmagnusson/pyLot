"""Build real Ethernet frames and pcap/pcapng files for tests, so no third-party captures are needed."""
import io
import socket

import dpkt

from parser.packets import Packet

MAC_A = '00:50:04:93:70:67'  # 3COM
MAC_B = '00:02:b3:ce:70:51'  # Intel
ROUTER_MAC = '00:80:f4:09:51:3b'

def mac_bytes(mac):
    return bytes.fromhex(mac.replace(':', ''))

def ipv4_frame(src, dst, transport, src_mac=MAC_A, dst_mac=MAC_B, ttl=64, offset=0):
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=_proto(transport), ttl=ttl, data=transport)
    ip.offset = offset
    return bytes(dpkt.ethernet.Ethernet(src=mac_bytes(src_mac), dst=mac_bytes(dst_mac), type=dpkt.ethernet.ETH_TYPE_IP, data=ip))

def _proto(transport):
    if isinstance(transport, dpkt.tcp.TCP):
        return dpkt.ip.IP_PROTO_TCP
    if isinstance(transport, dpkt.udp.UDP):
        return dpkt.ip.IP_PROTO_UDP
    return dpkt.ip.IP_PROTO_ICMP

def tcp_frame(src, dst, sport, dport, payload=b'', flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, opts=b'', seq=0xdeadbeef, **kwargs):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, opts=opts, seq=seq, data=payload)
    tcp.off = 5 + len(opts) // 4  # dpkt doesn't size the header for options itself
    return ipv4_frame(src, dst, tcp, **kwargs)

def udp_frame(src, dst, sport, dport, payload=b'', **kwargs):
    return ipv4_frame(src, dst, dpkt.udp.UDP(sport=sport, dport=dport, data=payload), **kwargs)

def icmp_frame(src, dst, **kwargs):
    return ipv4_frame(src, dst, dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b'ping')), **kwargs)

def arp_frame(sender_ip, sender_mac, target_ip, op=dpkt.arp.ARP_OP_REPLY):
    arp = dpkt.arp.ARP(op=op, sha=mac_bytes(sender_mac), spa=socket.inet_aton(sender_ip),
                       tha=b'\x00' * 6, tpa=socket.inet_aton(target_ip))
    return bytes(dpkt.ethernet.Ethernet(src=mac_bytes(sender_mac), dst=b'\xff' * 6, type=dpkt.ethernet.ETH_TYPE_ARP, data=arp))

def ipv6_udp_frame(src, dst, sport, dport, payload=b'', src_mac=MAC_A, dst_mac=MAC_B):
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = len(udp)
    ip6 = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, src), dst=socket.inet_pton(socket.AF_INET6, dst),
                       nxt=dpkt.ip.IP_PROTO_UDP, hlim=255, plen=len(udp), data=udp)
    return bytes(dpkt.ethernet.Ethernet(src=mac_bytes(src_mac), dst=mac_bytes(dst_mac), type=dpkt.ethernet.ETH_TYPE_IP6, data=ip6))

def pcap_bytes(frames, start=1_700_000_000.0, linktype=dpkt.pcap.DLT_EN10MB):
    out = io.BytesIO()
    writer = dpkt.pcap.Writer(out, linktype=linktype)
    for i, frame in enumerate(frames):
        writer.writepkt(frame, ts=start + i)
    return out.getvalue()

def pcapng_bytes(frames, start=1_700_000_000.0):
    out = io.BytesIO()
    writer = dpkt.pcapng.Writer(out)
    for i, frame in enumerate(frames):
        writer.writepkt(frame, ts=start + i)
    return out.getvalue()

def reader(data):
    return io.BufferedReader(io.BytesIO(data))

def packet(src='10.0.0.1', dst='10.0.0.2', transport=6, src_port=1234, dst_port=80, payload=b'', ttl=64,
           src_mac=MAC_A, dst_mac=MAC_B, frame=1, time=1_700_000_000.0, **kwargs):
    """A decoded Packet built directly, for tests that don't need real frames."""
    return Packet(frame=frame, time=time, length=60 + len(payload), src_mac=src_mac, dst_mac=dst_mac,
                  ethertype=0x0800, src_ip=src, dst_ip=dst, ttl=ttl, transport=transport,
                  src_port=src_port, dst_port=dst_port, payload=payload, **kwargs)

def arp_packet(sender_ip, sender_mac, target_ip='10.0.0.254'):
    return Packet(frame=1, time=1_700_000_000.0, length=42, src_mac=sender_mac, dst_mac='ff:ff:ff:ff:ff:ff',
                  ethertype=0x0806, arp=(2, sender_mac, sender_ip, '00:00:00:00:00:00', target_ip))

# --- layer-2 frames

import struct

def ethernet(dst_mac, src_mac, ethertype, payload, vlan=None):
    tag = struct.pack('>HH', 0x8100, vlan) if vlan is not None else b''
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + tag + struct.pack('>H', ethertype) + payload

def llc_frame(dst_mac, src_mac, llc_payload):
    """An 802.3 frame: a length where the EtherType would be, then LLC."""
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack('>H', len(llc_payload)) + llc_payload

def _tlv(kind, value):
    return struct.pack('>H', kind << 9 | len(value)) + value

def lldp_frame(src_mac, system_name, port_id, capabilities=0x0014, management_ip='10.0.0.250', vlan=None):
    payload = (_tlv(1, b'\x04' + mac_bytes(src_mac)) + _tlv(2, b'\x05' + port_id.encode()) + _tlv(3, b'\x00\x78')
               + _tlv(4, b'Uplink to sensor') + _tlv(5, system_name.encode()) + _tlv(6, b'Cisco IOS Software')
               + _tlv(7, struct.pack('>HH', capabilities, capabilities))
               + _tlv(8, b'\x05\x01' + socket.inet_aton(management_ip) + b'\x02\x00\x00\x00\x01\x00') + _tlv(0, b''))
    return ethernet('01:80:c2:00:00:0e', src_mac, 0x88CC, payload, vlan)

def cdp_frame(src_mac, device_id, port_id, address='10.0.0.251', capabilities=0x28, platform='cisco WS-C2960-24TT-L'):
    def tlv(kind, value):
        return struct.pack('>HH', kind, 4 + len(value)) + value
    addresses = struct.pack('>I', 1) + b'\x01\x01\xcc' + struct.pack('>H', 4) + socket.inet_aton(address)
    body = (b'\x02\xb4\x00\x00' + tlv(1, device_id.encode()) + tlv(2, addresses) + tlv(3, port_id.encode())
            + tlv(4, struct.pack('>I', capabilities)) + tlv(6, platform.encode()) + tlv(10, struct.pack('>H', 10)))
    return llc_frame('01:00:0c:cc:cc:cc', src_mac, b'\xaa\xaa\x03\x00\x00\x0c\x20\x00' + body)

def stp_frame(src_mac, root_mac, bridge_mac, priority=0x8000):
    bpdu = (b'\x00\x00\x02\x02\x3c' + struct.pack('>H', priority) + mac_bytes(root_mac) + struct.pack('>I', 4)
            + struct.pack('>H', priority + 1) + mac_bytes(bridge_mac) + b'\x80\x01' + b'\x00' * 8 + b'\x00')
    return llc_frame('01:80:c2:00:00:00', src_mac, b'\x42\x42\x03' + bpdu)

def _dcp_block(option, suboption, value, response=True):
    data = (b'\x00\x00' if response else b'') + value
    return bytes([option, suboption]) + struct.pack('>H', len(data)) + data + (b'\x00' if len(data) % 2 else b'')

def _dcp_blocks(name_of_station, role, vendor, device, ip, response=True):
    return (_dcp_block(2, 1, b'S7-1500', response) + _dcp_block(2, 2, name_of_station.encode(), response)
            + _dcp_block(2, 3, struct.pack('>HH', vendor, device), response) + _dcp_block(2, 4, bytes([role, 0]), response)
            + _dcp_block(1, 2, socket.inet_aton(ip) + socket.inet_aton('255.255.255.0') + socket.inet_aton('0.0.0.0'), response))

def dcp_identify_response(src_mac, name_of_station, role=0x01, vendor=0x002a, device=0x0313, ip='10.0.0.20'):
    blocks = _dcp_blocks(name_of_station, role, vendor, device, ip)
    payload = struct.pack('>HBBIHH', 0xFEFF, 0x05, 0x01, 0x1234, 0, len(blocks)) + blocks
    return ethernet('00:0e:8c:00:00:01', src_mac, 0x8892, payload)

def dcp_hello(src_mac, name_of_station, role=0x01, vendor=0x002a, device=0x0313, ip='10.0.0.21'):
    blocks = _dcp_blocks(name_of_station, role, vendor, device, ip)  # Hello blocks carry BlockInfo like responses
    payload = struct.pack('>HBBIHH', 0xFEFC, 0x06, 0x00, 0x1234, 0, len(blocks)) + blocks
    return ethernet('01:0e:cf:00:00:01', src_mac, 0x8892, payload)

def dcp_identify_request_for(src_mac, name_of_station):
    """An Identify request filtered on a name: the name is the device looked for, not the sender."""
    block = _dcp_block(2, 2, name_of_station.encode(), response=False)
    payload = struct.pack('>HBBIHH', 0xFEFE, 0x05, 0x00, 0x1234, 1, len(block)) + block
    return ethernet('01:0e:cf:00:00:00', src_mac, 0x8892, payload)

def dcp_set_ip_request(src_mac, ip='192.168.0.10'):
    """A tool setting another device's address: the address is not the sender's."""
    block = bytes([1, 2]) + struct.pack('>H', 14) + b'\x00\x01' + socket.inet_aton(ip) + socket.inet_aton('255.255.255.0') + b'\x00' * 4
    payload = struct.pack('>HBBIHH', 0xFEFD, 0x04, 0x00, 0x1234, 0, len(block)) + block
    return ethernet('08:00:06:93:cf:32', src_mac, 0x8892, payload)

def pvst_frame(src_mac, root_mac, bridge_mac, priority=0x8000):
    bpdu = (b'\x00\x00\x02\x02\x3c' + struct.pack('>H', priority) + mac_bytes(root_mac) + struct.pack('>I', 4)
            + struct.pack('>H', priority + 10) + mac_bytes(bridge_mac) + b'\x80\x01' + b'\x00' * 8 + b'\x00')
    return llc_frame('01:00:0c:cc:cc:cd', src_mac, b'\xaa\xaa\x03\x00\x00\x0c\x01\x0b' + bpdu)

def dcp_identify_request(src_mac):
    payload = struct.pack('>HBBIHH', 0xFEFE, 0x05, 0x00, 0x1234, 1, 4) + b'\xff\xff\x00\x00'
    return ethernet('01:0e:cf:00:00:00', src_mac, 0x8892, payload)

def profinet_rt_frame(src_mac, dst_mac, frame_id=0x8001):
    return ethernet(dst_mac, src_mac, 0x8892, struct.pack('>H', frame_id) + b'\x00' * 40, vlan=0)

def _ber(tag, value):
    return bytes([tag, len(value)]) + value

def goose_frame(src_mac, gocb_ref='IED1LD0/LLN0$GO$gcb01', dataset='IED1LD0/LLN0$DS1', go_id='IED1_GOOSE1', appid=0x0001):
    pdu = _ber(0x80, gocb_ref.encode()) + _ber(0x81, b'\x07\xd0') + _ber(0x82, dataset.encode()) + _ber(0x83, go_id.encode())
    apdu = _ber(0x61, pdu)
    payload = struct.pack('>HHHH', appid, 8 + len(apdu), 0, 0) + apdu
    return ethernet('01:0c:cd:01:00:01', src_mac, 0x88B8, payload, vlan=5)

# --- industrial protocol messages (application payloads)

def modbus_adu(function, data=b'', unit=1, transaction=1):
    pdu = bytes([function]) + data
    return struct.pack('>HHHB', transaction, 0, len(pdu) + 1, unit) + pdu

def modbus_device_identification(objects, unit=1):
    """A Read Device Identification reply carrying {object id: text}."""
    body = b''.join(bytes([oid, len(value)]) + value.encode() for oid, value in objects.items())
    return modbus_adu(43, bytes([0x0e, 0x01, 0x01, 0x00, 0x00, len(objects)]) + body, unit)

def dnp3_frame(function, source=1, destination=10, control=0xC4, transport=0xC0, app_control=0xC0, objects=b''):
    """A DNP3 link frame with one application fragment, CRCs and all."""
    from parser.ics.dnp3 import crc
    user = bytes([transport, app_control, function]) + objects
    header = b'\x05\x64' + bytes([5 + len(user), control]) + struct.pack('<HH', destination, source)
    frame = header + struct.pack('<H', crc(header))
    for i in range(0, len(user), 16):
        block = user[i:i + 16]
        frame += block + struct.pack('<H', crc(block))
    return frame

def tpkt(payload):
    cotp = b'\x02\xf0\x80'
    return struct.pack('>BBH', 3, 0, 4 + len(cotp) + len(payload)) + cotp + payload

def s7_job(parameters, data=b''):
    return tpkt(struct.pack('>BBHHHH', 0x32, 1, 0, 1, len(parameters), len(data)) + parameters + data)

def s7_read_var(area=0x84, db=1):
    item = b'\x12\x0a\x10\x02' + struct.pack('>HHB', 4, db, area) + b'\x00\x00\x00'
    return s7_job(b'\x04\x01' + item)

def s7_userdata(group, subfunction, data=b'', response=False, error=0):
    kind = 0x8 if response else 0x4
    parameters = b'\x00\x01\x12' + bytes([8 if response else 4, 0x12 if response else 0x11, kind << 4 | group, subfunction, 0])
    if response:
        parameters += b'\x00\x00' + struct.pack('>H', error)
    return tpkt(struct.pack('>BBHHHH', 0x32, 7, 0, 1, len(parameters), len(data)) + parameters + data)

def s7_szl_reply(szl_id, entries, entry_length):
    body = struct.pack('>HHHH', szl_id, 0, entry_length, len(entries)) + b''.join(entries)
    return s7_userdata(4, 1, b'\xff\x09' + struct.pack('>H', len(body)) + body, response=True)

def szl_module_entry(index, order='', version=b'\x00\x00\x00\x00'):
    return struct.pack('>H', index) + order.encode().ljust(20) + b'\x00\xc0' + version

def szl_component_entry(index, value):
    return struct.pack('>H', index) + value.encode().ljust(32, b'\x00')

def enip(command, body=b'', context=b'\x00' * 8, session=1):
    return struct.pack('<HHII', command, len(body), session, 0) + context + b'\x00' * 4 + body

def cip_identity(vendor=1, device_type=14, product_code=90, revision=(20, 11), serial=0x00ABCDEF, name='1756-L71/B LOGIX5571'):
    return (struct.pack('<HHHBBHI', vendor, device_type, product_code, revision[0], revision[1], 0x0030, serial)
            + bytes([len(name)]) + name.encode())

def enip_list_identity_reply(**identity):
    item = struct.pack('<H', 1) + b'\x00\x02\xaf\x12' + b'\x0a\x00\x00\x03' + b'\x00' * 8 + cip_identity(**identity) + b'\x03'
    return enip(0x63, struct.pack('<HHH', 1, 0x0c, len(item)) + item)

def cip_path(cls, instance=1, attribute=None):
    path = bytes([0x20, cls, 0x24, instance]) + (bytes([0x30, attribute]) if attribute is not None else b'')
    return bytes([len(path) // 2]) + path

def enip_send_rr(cip, context=b'ctx00001'):
    body = b'\x00' * 6 + struct.pack('<HHHHH', 2, 0, 0, 0xb2, len(cip)) + cip
    return enip(0x6f, body, context)

def iec104_apdu(type_id, cause=6, address=1, information=b'\x00\x00\x00\x01'):
    asdu = bytes([type_id, 1, cause, 0]) + struct.pack('<H', address) + information
    return bytes([0x68, 4 + len(asdu)]) + b'\x00\x00\x00\x00' + asdu

def bacnet(apdu, broadcast=False):
    npdu = b'\x01\x00' + apdu
    return struct.pack('>BBH', 0x81, 0x0b if broadcast else 0x0a, 4 + len(npdu)) + npdu

def bacnet_i_am(instance, vendor):
    return bacnet(b'\x10\x00' + b'\xc4' + struct.pack('>I', 8 << 22 | instance) + b'\x22\x05\xc4\x91\x03\x21' + bytes([vendor]),
                  broadcast=True)

def bacnet_read_property_ack(instance, prop, value):
    string = b'\x00' + value.encode()
    return bacnet(b'\x30\x01\x0c' + b'\x0c' + struct.pack('>I', 8 << 22 | instance) + b'\x19' + bytes([prop])
                  + b'\x3e\x75' + bytes([len(string)]) + string + b'\x3f')

def snmp_get_response(oid, value, pdu_tag=0xa2):
    def element(tag, data):
        return bytes([tag, len(data)]) + data
    parts = [int(p) for p in oid.split('.')]
    encoded = bytes([parts[0] * 40 + parts[1]]) + bytes(parts[2:])
    binding = element(0x30, element(0x06, encoded) + element(0x04, value.encode()))
    pdu = element(pdu_tag, element(0x02, b'\x01') + element(0x02, b'\x00') + element(0x02, b'\x00') + element(0x30, binding))
    return element(0x30, element(0x02, b'\x01') + element(0x04, b'public') + pdu)
