import os

import pytest

import storage
from packet_builder import (MAC_A, MAC_B, ROUTER_MAC, cdp_frame, dcp_identify_response, goose_frame, lldp_frame, packet,
                            profinet_rt_frame)
from parser.analysis import CaptureAnalyzer
from parser.packets import decode_frame
from parser.pcap_parser import engine
from parser.switch_config import parse

DATA = os.path.join(os.path.dirname(__file__), 'data')
PLC_MAC = '00:0e:8c:11:22:33'
SWITCH_MAC = '00:1b:54:cc:dd:01'

@pytest.fixture
def conn(tmp_path):
    path = str(tmp_path / 'test.sqlite3')
    storage.init_db(path)
    connection = storage.connect(path)
    yield connection
    connection.close()

def session_with(conn, packets, frames=()):
    analyzer = CaptureAnalyzer(engine)
    for pkt in packets:
        analyzer.add(pkt)
    for i, frame in enumerate(frames, start=1):
        analyzer.add(decode_frame(i, 1_700_000_000.0 + i, frame, 1))
    session_id = storage.create_session(conn, 'x', 'upload', 'ready')
    storage.save_analysis(conn, session_id, analyzer)
    return session_id

def import_switch(conn, session_id, name):
    with open(os.path.join(DATA, name)) as f:
        return storage.save_switch(conn, session_id, parse(f.read()), filename=name)

# --- named networks

def test_network_crud(conn):
    network = storage.add_network(conn, '10.0.0.7/24', 'Process control')
    assert network['cidr'] == '10.0.0.0/24' and network['name'] == 'Process control'
    with pytest.raises(ValueError, match='already defined'):
        storage.add_network(conn, '10.0.0.0/24')
    with pytest.raises(ValueError, match='not a network'):
        storage.add_network(conn, '10.0.0.300/24')
    assert storage.add_network(conn, 'fd00::/64')['name'] == 'fd00::/64'  # the CIDR when there's no name
    storage.add_network(conn, '10.0.0.0/16', 'Plant')
    assert [n['cidr'] for n in storage.list_networks(conn)] == ['10.0.0.0/16', '10.0.0.0/24', 'fd00::/64']
    assert storage.update_network(conn, network['id'], name='Cell 1')['name'] == 'Cell 1'
    assert storage.delete_network(conn, network['id']) and not storage.delete_network(conn, network['id'])
    assert storage.update_network(conn, 999, name='x') is None

def test_hosts_use_the_most_specific_named_network(conn):
    session_id = session_with(conn, [packet(src='10.0.0.5', dst='10.0.1.9'), packet(src='10.0.0.5', dst='10.9.0.1')])
    storage.add_network(conn, '10.0.0.0/16', 'Plant')
    storage.add_network(conn, '10.0.1.0/24', 'Cell 1')
    graph = storage.session_graph(conn, session_id)
    groups = {n['ip']: n['group'] for n in graph['nodes']}
    assert groups == {'10.0.0.5': 'net:10.0.0.0/16', '10.0.1.9': 'net:10.0.1.0/24', '10.9.0.1': '10.9.0.0/24'}
    labels = {g['id']: g for g in graph['groups']}
    assert labels['net:10.0.1.0/24']['label'] == 'Cell 1 (10.0.1.0/24)' and labels['net:10.0.1.0/24']['hosts'] == 1
    assert labels['10.9.0.0/24']['network_id'] is None and labels['10.9.0.0/24']['cidr'] == '10.9.0.0/24'

def test_automatic_grouping_prefix_can_change_or_turn_off(conn):
    session_id = session_with(conn, [packet(src='10.0.0.5', dst='10.0.1.9')])
    storage.update_settings(conn, auto_prefix_v4=16)
    assert {n['group'] for n in storage.session_graph(conn, session_id)['nodes']} == {'10.0.0.0/16'}
    storage.update_settings(conn, auto_prefix_v4=0)
    assert {n['group'] for n in storage.session_graph(conn, session_id)['nodes']} == {'unassigned'}
    with pytest.raises(ValueError):
        storage.update_settings(conn, auto_prefix_v4=33)
    with pytest.raises(ValueError):
        storage.update_settings(conn, colour=1)

def test_hosts_in_named_networks_are_never_merged(conn):
    packets = []
    for i in range(5):
        packets.append(packet(src='10.0.0.5', dst=f'198.51.100.{i + 1}', dst_mac=ROUTER_MAC, dst_port=443))
    session_id = session_with(conn, packets)
    storage.add_network(conn, '198.51.100.0/30', 'Remote site')
    graph = storage.session_graph(conn, session_id, collapse_external=True)
    assert graph['external_hosts'] == 2  # .4 and .5; the named network holds .1 to .3
    ips = {n['ip'] for n in graph['nodes']}
    assert {'198.51.100.1', '198.51.100.2', '198.51.100.3'} <= ips and '198.51.100.4' not in ips

# --- layer 2

def test_layer2_evidence_classifies_the_host_with_that_mac(conn):
    session_id = session_with(conn, [packet(src='10.0.0.20', dst='10.0.0.30', src_mac=PLC_MAC, dst_mac=MAC_B, dst_port=34964, transport=17)],
                              [dcp_identify_response(PLC_MAC, 'plc-line-1', role=0x02)])
    host = storage.host_detail(conn, session_id, '10.0.0.20')
    assert host['category'] == 'PLC' and host['role'] == 'MASTER' and host['layer2'] == ['PROFINET DCP']
    assert host['properties']['NameOfStation']['values'] == ['plc-line-1']
    assert any(e['name'] == 'NameOfStation' for e in host['layer2_evidence'])
    assert storage.list_hosts(conn, session_id, query='profinet dcp')[1] == 1

def test_devices_include_layer2_only_equipment(conn):
    session_id = session_with(conn, [packet(src='10.0.0.5', dst='10.0.0.6')],
                              [goose_frame(PLC_MAC), goose_frame(PLC_MAC), profinet_rt_frame('00:0e:8c:44:55:66', PLC_MAC)])
    devices = {d['mac']: d for d in storage.all_devices(conn, session_id)}
    ied = devices[PLC_MAC]
    assert ied['category'] == 'IED' and ied['ips'] == [] and ied['vlans'] == [5] and ied['layer2'] == ['IEC 61850 GOOSE']
    assert devices[MAC_A]['ips'] == ['10.0.0.5']
    flows = storage.list_l2_flows(conn, session_id)
    assert flows[0] == {**flows[0], 'src_mac': PLC_MAC, 'dst_mac': '01:0c:cd:01:00:01', 'protocol': 'IEC 61850 GOOSE', 'packets': 2}
    detail = storage.device_detail(conn, session_id, PLC_MAC)
    assert len(detail['l2_flows']) == 2 and detail['properties']['GoID']['values'] == ['IED1_GOOSE1']
    assert storage.list_devices(conn, session_id, query='vlan 5')[1] == 1
    assert storage.device_detail(conn, session_id, 'aa:aa:aa:aa:aa:aa') is None

def test_router_macs_are_network_devices(conn):
    session_id = session_with(conn, [packet(src='10.0.0.5', dst=f'198.51.100.{i}', dst_mac=ROUTER_MAC) for i in range(1, 6)]
                              + [packet(src='198.51.100.1', dst='10.0.0.5', src_mac=ROUTER_MAC, dst_mac=MAC_A)])
    router = next(d for d in storage.all_devices(conn, session_id) if d['mac'] == ROUTER_MAC)
    assert router['routes_for'] == 5 and router['category'] == 'NETWORK_DEVICE'

# --- switches and the physical view

def test_physical_view_places_devices_on_access_ports(conn):
    session_id = session_with(conn, [packet(src='10.0.0.20', dst='10.0.0.30', src_mac=PLC_MAC, dst_mac=MAC_A),
                                     packet(src='10.0.0.30', dst='10.0.0.20', src_mac=MAC_A, dst_mac=PLC_MAC)],
                              [lldp_frame(SWITCH_MAC, 'sw-access-1', 'Gi1/0/5')])
    access = import_switch(conn, session_id, 'sw-access-1.txt')
    core = import_switch(conn, session_id, 'sw-core-1.txt')
    assert [s['name'] for s in storage.list_switches(conn, session_id)] == ['sw-access-1', 'sw-core-1']

    devices = {d['mac']: d for d in storage.all_devices(conn, session_id)}
    # Learned on both switches; the access switch's edge port wins over the core's uplink port
    assert (devices[PLC_MAC]['switch'], devices[PLC_MAC]['port']) == ('sw-access-1', 'Gi1/0/1')
    assert (devices[MAC_A]['switch'], devices[MAC_A]['port']) == ('sw-access-1', 'Gi1/0/2')
    # Only in the core's table, and not seen in the capture
    assert (devices[MAC_B]['switch'], devices[MAC_B]['port'], devices[MAC_B]['seen']) == ('sw-core-1', 'Gi1/0/5', False)

    graph = storage.physical_graph(conn, session_id)
    nodes = {n['id']: n for n in graph['nodes']}
    edges = {(e['source'], e['target']): e for e in graph['edges']}
    assert nodes[f'port:{access}:Gi1/0/1']['description'] == 'PLC line 1'
    assert (f'mac:{PLC_MAC}', f'port:{access}:Gi1/0/1') in edges
    # The CDP and LLDP neighbor entries describe one link, drawn once
    links = [e for e in graph['edges'] if e['type'] == 'link']
    assert len(links) == 1 and {links[0]['source'], links[0]['target']} == {f'port:{access}:Gi1/0/24', f'port:{core}:Gi1/0/1'}
    # The LLDP frame came from the imported access switch, so the capture hangs off its announced port
    assert ('capture', f'port:{access}:Gi1/0/5') in edges
    assert f'mac:{SWITCH_MAC}' not in nodes

    assert storage.delete_switch(conn, session_id, core) and not storage.delete_switch(conn, session_id + 1, access)
    assert [s['name'] for s in storage.list_switches(conn, session_id)] == ['sw-access-1']

def test_physical_view_without_imports(conn):
    session_id = session_with(conn, [packet(src='10.0.0.5', dst='10.0.0.6')],
                              [cdp_frame(SWITCH_MAC, 'sw-9', 'GigabitEthernet0/3'), goose_frame(PLC_MAC)])
    graph = storage.physical_graph(conn, session_id)
    nodes = {n['id']: n for n in graph['nodes']}
    assert nodes[f'mac:{PLC_MAC}']['parent'] == 'vlan:5' and nodes['vlan:5']['label'] == 'VLAN 5, port unknown'
    assert nodes[f'mac:{MAC_A}']['parent'] == 'vlan:unknown'
    assert nodes[f'mac:{SWITCH_MAC}']['label'].startswith('sw-9')
    capture = [e for e in graph['edges'] if e['source'] == 'capture']
    assert capture == [{'source': 'capture', 'target': f'mac:{SWITCH_MAC}', 'type': 'capture', 'label': 'GigabitEthernet0/3'}]

# --- comparing sessions

def test_compare_sessions(conn):
    baseline = session_with(conn, [packet(src='10.0.0.5', dst='10.0.0.6', dst_port=502),
                                   packet(src='10.0.0.6', dst='10.0.0.5', src_port=502, dst_port=1234, src_mac=MAC_B, dst_mac=MAC_A),
                                   packet(src='10.0.0.5', dst='10.0.0.7', dst_port=80, dst_mac='00:00:00:00:00:07')])
    current = session_with(conn, [packet(src='10.0.0.5', dst='10.0.0.6', src_port=40000, dst_port=502),
                                  packet(src='10.0.0.6', dst='10.0.0.5', src_port=502, dst_port=40000, src_mac='00:50:c2:00:00:01', dst_mac=MAC_A),
                                  packet(src='10.0.0.5', dst='10.0.0.8', dst_port=22, dst_mac='00:00:00:00:00:08')],
                           [goose_frame(PLC_MAC)])
    diff = storage.compare_sessions(conn, current, baseline)
    assert [h['ip'] for h in diff['new_hosts']['items']] == ['10.0.0.8']
    assert [h['ip'] for h in diff['missing_hosts']['items']] == ['10.0.0.7']
    changed = {c['ip']: c['changes'] for c in diff['changed_hosts']['items']}
    assert [c['what'] for c in changed['10.0.0.6']] == ['MAC']
    # A new client port on the same Modbus service is not a new conversation
    assert [(c['client'], c['server'], c['port'], c['protocol']) for c in diff['new_conversations']['items']] == [('10.0.0.5', '10.0.0.8', 22, 'SSH')]
    assert [(c['server'], c['port']) for c in diff['missing_conversations']['items']] == [('10.0.0.7', 80)]
    assert {m['mac'] for m in diff['new_macs']['items']} == {'00:50:c2:00:00:01', PLC_MAC}
    assert [m['mac'] for m in diff['missing_macs']['items']] == [MAC_B]
    assert [(r['src_mac'], r['protocol']) for r in diff['new_layer2']['items']] == [(PLC_MAC, 'IEC 61850 GOOSE')]
    assert storage.compare_sessions(conn, current, current)['new_hosts']['total'] == 0

def test_graph_marks_changes_since_a_baseline(conn, monkeypatch):
    reply = packet(src='10.0.0.6', dst='10.0.0.5', src_port=502, dst_port=1234, src_mac=MAC_B, dst_mac=MAC_A)
    baseline = session_with(conn, [packet(src='10.0.0.5', dst='10.0.0.6', dst_port=502), reply])
    packets = [packet(src='10.0.0.5', dst='10.0.0.6', dst_port=502), reply, packet(src='10.0.0.5', dst='10.0.0.6', dst_port=22),
               packet(src='10.0.0.9', dst='10.0.0.6', dst_port=502, src_mac='00:00:00:00:00:09')]
    packets += [packet(src='10.0.0.5', dst=f'198.51.100.{i}', dst_mac=ROUTER_MAC, dst_port=443) for i in range(1, 5)]
    current = session_with(conn, packets)
    graph = storage.session_graph(conn, current, baseline_id=baseline)
    nodes = {n['id']: n for n in graph['nodes']}
    assert nodes['10.0.0.9']['change'] == 'new' and nodes['10.0.0.5']['change'] is None
    edges = {(e['source'], e['target']): e['new'] for e in graph['edges']}
    assert edges[('10.0.0.9', '10.0.0.6')] and edges[('10.0.0.5', '10.0.0.6')]  # 10.0.0.5 -> :22 is a new conversation
    assert not edges[('10.0.0.6', '10.0.0.5')]  # only Modbus replies went this way
    assert graph['baseline'] == {'id': baseline, 'new_hosts': 5, 'changed_hosts': 0, 'new_conversations': 6, 'missing_hosts': 0}
    merged = storage.session_graph(conn, current, collapse_external=True, baseline_id=baseline)
    router = next(n for n in merged['nodes'] if n['id'] == f'via:{ROUTER_MAC}')
    assert router['change'] == 'new' and router['new_hosts'] == 4
    assert 'baseline' not in storage.session_graph(conn, current)
