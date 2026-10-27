from packet_builder import MAC_A, MAC_B, ROUTER_MAC, arp_packet, packet
from parser.analysis import CaptureAnalyzer
from parser.fingerprint_matcher import Annotation

class NoFingerprints:
    def evaluate(self, pkt):
        return []

def analyze(packets, engine=NoFingerprints()):
    analyzer = CaptureAnalyzer(engine)
    for pkt in packets:
        analyzer.add(pkt)
    return analyzer

def hosts(analyzer):
    """ip -> (mac, vendor, via_mac, kind)"""
    return {row[0]: row[1:5] for row in analyzer.host_rows()}

def test_routed_hosts_are_not_credited_with_the_router_mac():
    remote = [f'198.51.100.{i}' for i in range(1, 6)]
    packets = [packet(src=ip, dst='10.0.0.5', src_mac=ROUTER_MAC, dst_mac=MAC_A) for ip in remote]
    packets += [packet(src='10.0.0.5', dst=ip, src_mac=MAC_A, dst_mac=ROUTER_MAC) for ip in remote]
    result = hosts(analyze(packets))
    assert result['10.0.0.5'] == (MAC_A, '3COM', None, 'unicast')
    assert all(result[ip] == (None, None, ROUTER_MAC, 'unicast') for ip in remote)

def test_arp_identifies_the_router_even_for_a_single_remote_host():
    packets = [arp_packet('10.0.0.1', ROUTER_MAC),
               packet(src='203.0.113.9', dst='10.0.0.5', src_mac=ROUTER_MAC, dst_mac=MAC_A)]
    result = hosts(analyze(packets))
    assert result['203.0.113.9'][:3] == (None, None, ROUTER_MAC)

def test_dual_stack_host_keeps_its_mac_for_ipv6():
    packets = [arp_packet('10.0.0.5', MAC_A),
               packet(src='10.0.0.5', dst='10.0.0.6', src_mac=MAC_A, dst_mac=MAC_B),
               packet(src='fe80::250:4ff:fe93:7067', dst='fe80::1', src_mac=MAC_A, dst_mac=MAC_B, transport=17)]
    assert hosts(analyze(packets))['fe80::250:4ff:fe93:7067'][:3] == (MAC_A, '3COM', None)

def test_address_kinds():
    packets = [packet(src='0.0.0.0', dst='255.255.255.255', dst_mac='ff:ff:ff:ff:ff:ff', transport=17),
               packet(src='10.0.0.5', dst='224.0.0.251', dst_mac='01:00:5e:00:00:fb', transport=17),
               packet(src='10.0.0.5', dst='10.0.0.255', dst_mac='ff:ff:ff:ff:ff:ff', transport=17)]
    result = hosts(analyze(packets))
    assert {ip: row[3] for ip, row in result.items()} == {
        '0.0.0.0': 'unspecified', '255.255.255.255': 'broadcast', '10.0.0.5': 'unicast',
        '224.0.0.251': 'multicast', '10.0.0.255': 'broadcast'}
    assert result['224.0.0.251'][0] is None  # group MACs never become a host's MAC

def test_flows_aggregate_by_five_tuple():
    packets = [packet(dst_port=502, time=100.0 + i, payload=b'x' * 10) for i in range(3)]
    packets.append(packet(transport=1, src_port=None, dst_port=None))
    analyzer = analyze(packets)
    flows = {row[:5]: row[5:] for row in analyzer.flow_rows()}
    assert flows[('10.0.0.1', '10.0.0.2', 6, 1234, 502)] == ('Modbus', 3, 210, 100.0, 102.0)
    assert flows[('10.0.0.1', '10.0.0.2', 1, 0, 0)][0] == 'ICMP'
    stats = {row[0]: row[5:9] for row in analyzer.host_rows()}
    assert stats['10.0.0.1'] == (4, 0, 270, 0) and stats['10.0.0.2'] == (0, 4, 0, 270)

class FakeEngine:
    def __init__(self, confidences):
        self.confidences = iter(confidences)

    def evaluate(self, pkt):
        return [Annotation('MODBUS', 'TCP Master', pkt.src_ip, next(self.confidences), {'Role': 'MASTER'})]

def test_evidence_keeps_best_confidence_and_first_frame():
    analyzer = analyze([packet(frame=7), packet(frame=8), packet(frame=9)], FakeEngine([4, 2, 3]))
    assert analyzer.evidence_rows() == [('10.0.0.1', 'MODBUS', 'Role', 'MASTER', 2, 3, 7)]

def test_only_dirty_rows_are_returned_after_a_save():
    analyzer = analyze([packet(dst_port=502)])
    assert len(analyzer.flow_rows(only_dirty=True)) == 1
    analyzer.clear_dirty()
    assert analyzer.flow_rows(only_dirty=True) == []
    analyzer.add(packet(dst_port=20000))
    assert [row[4] for row in analyzer.flow_rows(only_dirty=True)] == [20000]
    assert len(analyzer.flow_rows()) == 2
