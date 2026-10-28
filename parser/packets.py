"""Decode pcap and pcapng captures into the packet fields pyLot uses, with dpkt instead of tshark."""
import logging
import socket
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional

import dpkt

logger = logging.getLogger(__name__)

PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
DLT_LINUX_SLL2 = 276
RAW_IP_LINKTYPES = (12, 14, 101, 228, 229)
LOOPBACK_LINKTYPES = (0, 108)

# TCP flag names as GRASSMARLIN fingerprints spell them
TCP_FLAGS = {'FIN': 0x01, 'SYN': 0x02, 'RST': 0x04, 'PSH': 0x08, 'ACK': 0x10, 'URG': 0x20, 'ECE': 0x40, 'CWR': 0x80, 'NS': 0x100}

@dataclass(slots=True)
class Packet:
    frame: int                       # 1-based position in the capture
    time: float                      # seconds since the epoch
    length: int                      # bytes captured for this frame
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    ethertype: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None        # IPv4 TTL or IPv6 hop limit
    transport: Optional[int] = None  # IP protocol number: 6 = TCP, 17 = UDP
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[int] = None
    seq: Optional[int] = None
    ack: Optional[int] = None
    window: Optional[int] = None
    mss: Optional[int] = None
    payload: bytes = b''             # TCP or UDP payload
    arp: Optional[tuple] = None      # (operation, sender MAC, sender IP, target MAC, target IP)

def read_capture(stream: BinaryIO) -> Iterator[Packet]:
    """
    Yield a Packet for every frame in a pcap or pcapng stream. Works on pipes as well as files,
    so stream must support peek() (any file opened with open(path, 'rb') or a subprocess stdout).
    Raises ValueError for unsupported link types; frames that fail to decode are logged and skipped.
    """
    reader, linktype = _open(stream)
    skipped = 0
    for frame, (ts, buf) in enumerate(reader, start=1):
        try:
            yield decode_frame(frame, ts, buf, linktype)
        except (dpkt.Error, struct.error, ValueError, IndexError):
            skipped += 1
            logger.debug("Could not decode frame %d", frame, exc_info=True)
    if skipped:
        logger.warning("Skipped %d frames that could not be decoded", skipped)

def _open(stream):
    try:
        reader = dpkt.pcapng.Reader(stream) if stream.peek(4)[:4] == PCAPNG_MAGIC else dpkt.pcap.Reader(stream)
    except dpkt.Error as e:  # e.g. a truncated header
        raise ValueError(f'Not a readable capture: {e}') from e
    linktype = reader.datalink()
    if linktype not in (dpkt.pcap.DLT_EN10MB, dpkt.pcap.DLT_LINUX_SLL, DLT_LINUX_SLL2) + RAW_IP_LINKTYPES + LOOPBACK_LINKTYPES:
        raise ValueError(f'Unsupported capture link type {linktype}')
    return reader, linktype

def check_capture(path):
    """Raise ValueError unless path starts like a pcap/pcapng capture pyLot can decode."""
    with open(path, 'rb') as f:
        _open(f)

def decode_frame(frame: int, ts: float, buf: bytes, linktype: int) -> Packet:
    pkt = Packet(frame=frame, time=float(ts), length=len(buf))
    if linktype == dpkt.pcap.DLT_EN10MB:
        eth = dpkt.ethernet.Ethernet(buf)
        pkt.src_mac, pkt.dst_mac = eth.src.hex(':'), eth.dst.hex(':')
        # Values below 0x600 are 802.3 lengths, not EtherTypes
        pkt.ethertype = eth.type if eth.type >= 0x600 else None
        l3 = eth.data
    elif linktype in (dpkt.pcap.DLT_LINUX_SLL, DLT_LINUX_SLL2):
        sll = dpkt.sll.SLL(buf) if linktype == dpkt.pcap.DLT_LINUX_SLL else dpkt.sll2.SLL2(buf)
        if sll.hlen == 6:
            pkt.src_mac = sll.hdr[:6].hex(':')
        pkt.ethertype = sll.ethtype
        l3 = sll.data
    elif linktype in LOOPBACK_LINKTYPES:
        l3 = dpkt.loopback.Loopback(buf).data
    else:
        l3 = dpkt.ip6.IP6(buf) if buf and buf[0] >> 4 == 6 else dpkt.ip.IP(buf)

    if isinstance(l3, dpkt.ip.IP):
        # Set from the decoded layer: for 802.1Q frames dpkt leaves the outer tag type in eth.type
        pkt.ethertype = ETHERTYPE_IPV4
        pkt.src_ip, pkt.dst_ip = socket.inet_ntop(socket.AF_INET, l3.src), socket.inet_ntop(socket.AF_INET, l3.dst)
        pkt.ttl, pkt.transport = l3.ttl, l3.p
        # Later fragments carry no transport header; dpkt would misread their data as one
        l4 = l3.data if l3.offset == 0 else None
    elif isinstance(l3, dpkt.ip6.IP6):
        pkt.ethertype = ETHERTYPE_IPV6
        pkt.src_ip, pkt.dst_ip = socket.inet_ntop(socket.AF_INET6, l3.src), socket.inet_ntop(socket.AF_INET6, l3.dst)
        pkt.ttl = l3.hlim
        l4 = l3.data
        pkt.transport = _ip6_transport(l3, l4)
    elif isinstance(l3, dpkt.arp.ARP):
        if l3.hln == 6 and l3.pln == 4:
            pkt.arp = (l3.op, l3.sha.hex(':'), socket.inet_ntop(socket.AF_INET, l3.spa),
                       l3.tha.hex(':'), socket.inet_ntop(socket.AF_INET, l3.tpa))
        return pkt
    else:
        return pkt

    if isinstance(l4, dpkt.tcp.TCP):
        pkt.src_port, pkt.dst_port = l4.sport, l4.dport
        pkt.tcp_flags, pkt.seq, pkt.ack, pkt.window = l4.flags, l4.seq, l4.ack, l4.win  # flags include NS
        for option, value in dpkt.tcp.parse_opts(l4.opts):
            if option == dpkt.tcp.TCP_OPT_MSS and len(value) == 2:
                pkt.mss = struct.unpack('>H', value)[0]
        pkt.payload = bytes(l4.data)
    elif isinstance(l4, dpkt.udp.UDP):
        pkt.src_port, pkt.dst_port = l4.sport, l4.dport
        pkt.payload = bytes(l4.data)
    return pkt

def _ip6_transport(ip6, l4) -> int:
    """Protocol number of the layer after any IPv6 extension headers."""
    if isinstance(l4, dpkt.tcp.TCP):
        return 6
    if isinstance(l4, dpkt.udp.UDP):
        return 17
    if isinstance(l4, dpkt.icmp6.ICMP6):
        return 58
    return getattr(ip6, 'p', ip6.nxt)
