import io
import struct

import dpkt
import pytest

from packet_builder import (MAC_A, MAC_B, arp_frame, icmp_frame, ipv6_udp_frame, pcap_bytes, pcapng_bytes, reader,
                            tcp_frame, udp_frame)
from parser.packets import TCP_FLAGS, decode_frame, read_capture

def decode(frames, writer=pcap_bytes):
    return list(read_capture(reader(writer(frames))))

def test_tcp_fields_and_mss_option():
    mss = struct.pack('>BBH', dpkt.tcp.TCP_OPT_MSS, 4, 1460)
    [pkt] = decode([tcp_frame('10.0.0.1', '10.0.0.2', 40000, 502, b'\x00\x01', flags=dpkt.tcp.TH_SYN, opts=mss, ttl=128)])
    assert (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.transport) == ('10.0.0.1', '10.0.0.2', 40000, 502, 6)
    assert (pkt.src_mac, pkt.dst_mac, pkt.ethertype, pkt.ttl) == (MAC_A, MAC_B, 0x0800, 128)
    assert pkt.tcp_flags == TCP_FLAGS['SYN'] and pkt.mss == 1460 and pkt.payload == b'\x00\x01'
    assert pkt.frame == 1 and pkt.time == 1_700_000_000.0

def test_udp_and_icmp():
    udp, icmp = decode([udp_frame('10.0.0.1', '10.0.0.255', 47808, 47808, b'\x81\x0b'), icmp_frame('10.0.0.1', '10.0.0.2')])
    assert (udp.transport, udp.src_port, udp.payload) == (17, 47808, b'\x81\x0b')
    assert (icmp.transport, icmp.src_port, icmp.dst_port, icmp.payload) == (1, None, None, b'')

def test_arp():
    [pkt] = decode([arp_frame('10.0.0.5', MAC_A, '10.0.0.1')])
    assert pkt.src_ip is None and pkt.arp == (dpkt.arp.ARP_OP_REPLY, MAC_A, '10.0.0.5', '00:00:00:00:00:00', '10.0.0.1')

def test_ipv6():
    [pkt] = decode([ipv6_udp_frame('fe80::1', 'ff02::fb', 5353, 5353, b'mdns')])
    assert (pkt.src_ip, pkt.dst_ip, pkt.transport, pkt.ttl, pkt.ethertype) == ('fe80::1', 'ff02::fb', 17, 255, 0x86DD)

def test_vlan_tag_is_skipped():
    frame = tcp_frame('10.0.0.1', '10.0.0.2', 1234, 502)
    tagged = frame[:12] + b'\x81\x00\x00\x64' + frame[12:]  # 802.1Q, VLAN 100
    [pkt] = decode([tagged])
    assert (pkt.ethertype, pkt.dst_port) == (0x0800, 502)

def test_later_fragments_have_no_ports():
    [pkt] = decode([tcp_frame('10.0.0.1', '10.0.0.2', 1234, 502, b'data', offset=10)])
    assert pkt.src_ip == '10.0.0.1' and pkt.src_port is None and pkt.payload == b''

def test_pcapng():
    [pkt] = decode([udp_frame('10.0.0.1', '10.0.0.2', 1, 2, b'x')], writer=pcapng_bytes)
    assert pkt.payload == b'x'

def test_raw_ip_link_type():
    ip_only = tcp_frame('10.0.0.1', '10.0.0.2', 1234, 80)[14:]
    [pkt] = list(read_capture(reader(pcap_bytes([ip_only], linktype=101))))
    assert pkt.src_mac is None and pkt.ethertype == 0x0800 and pkt.dst_port == 80

def test_undecodable_frames_are_skipped():
    truncated = tcp_frame('10.0.0.1', '10.0.0.2', 1234, 80)[:20]
    pkts = decode([truncated, udp_frame('10.0.0.1', '10.0.0.2', 1, 2)])
    assert len(pkts) == 2 and pkts[0].src_ip is None and pkts[1].src_ip == '10.0.0.1'

def test_unsupported_link_type_raises():
    with pytest.raises(ValueError, match='link type'):
        list(read_capture(reader(pcap_bytes([b'\x00' * 20], linktype=105))))  # 802.11

def test_not_a_capture_raises():
    with pytest.raises(ValueError):
        list(read_capture(io.BufferedReader(io.BytesIO(b'this is not a pcap file at all'))))

def test_truncated_header_raises_value_error():
    with pytest.raises(ValueError, match='Not a readable capture'):
        list(read_capture(reader(pcap_bytes([])[:10])))

def test_truncated_tcp_option_is_ignored():
    # An option kind with no room for its length byte: dpkt returns None for it
    pkt = decode_frame(1, 0.0, tcp_frame('10.0.0.1', '10.0.0.2', 1234, 80, opts=b'\x02\x04\x05\xb4\x01\x01\x01\x08'), 1)
    assert pkt.mss == 1460 and pkt.dst_port == 80

def test_unexpected_decoding_errors_skip_only_that_frame(monkeypatch, caplog):
    import parser.packets as packets
    real = packets.decode_frame
    def flaky(frame, ts, buf, linktype):
        if frame == 2:
            raise TypeError('decoder bug')
        return real(frame, ts, buf, linktype)
    monkeypatch.setattr(packets, 'decode_frame', flaky)
    frames = [tcp_frame('10.0.0.1', '10.0.0.2', 1234, 80)] * 3
    assert [p.frame for p in packets.read_capture(reader(pcap_bytes(frames)))] == [1, 3]
    assert 'Unexpected error decoding frame 2' in caplog.text
