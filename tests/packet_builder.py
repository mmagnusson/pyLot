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

def tcp_frame(src, dst, sport, dport, payload=b'', flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, opts=b'', **kwargs):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, opts=opts, data=payload)
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
