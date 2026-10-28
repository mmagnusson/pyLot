from parser.packets import decode_frame
from packet_builder import (MAC_A, cdp_frame, dcp_identify_request, dcp_identify_response, goose_frame, lldp_frame,
                                  profinet_rt_frame, stp_frame)

SWITCH_MAC = '00:1b:54:aa:bb:01'
PLC_MAC = '00:0e:8c:11:22:33'

def decode(frame):
    return decode_frame(1, 0.0, frame, 1)

def props(pkt):
    return {name: value for name, value, _ in pkt.l2_properties}

def test_lldp():
    pkt = decode(lldp_frame(SWITCH_MAC, 'sw-core-1', 'Gi1/0/24', vlan=10))
    assert pkt.l2_protocol == 'LLDP' and pkt.vlan == 10 and pkt.src_ip is None
    assert props(pkt) == {'ChassisID': SWITCH_MAC, 'PortID': 'Gi1/0/24', 'PortDescription': 'Uplink to sensor',
                          'SystemName': 'sw-core-1', 'SystemDescription': 'Cisco IOS Software', 'Capabilities': 'Bridge, Router',
                          'ManagementAddress': '10.0.0.250', 'Category': 'NETWORK_DEVICE'}

def test_lldp_station_is_not_network_gear():
    assert 'Category' not in props(decode(lldp_frame(MAC_A, 'hmi-1', 'eth0', capabilities=0x0080)))

def test_cdp():
    pkt = decode(cdp_frame(SWITCH_MAC, 'sw-access-2.plant.local', 'GigabitEthernet0/3'))
    assert pkt.l2_protocol == 'CDP'
    assert props(pkt) == {'SystemName': 'sw-access-2.plant.local', 'ManagementAddress': '10.0.0.251', 'PortID': 'GigabitEthernet0/3',
                          'Capabilities': 'Switch, IGMP', 'Platform': 'cisco WS-C2960-24TT-L', 'NativeVLAN': '10',
                          'Category': 'NETWORK_DEVICE'}

def test_stp():
    pkt = decode(stp_frame(SWITCH_MAC, '00:1b:54:00:00:01', SWITCH_MAC))
    assert pkt.l2_protocol == 'STP'
    assert props(pkt) == {'Category': 'NETWORK_DEVICE', 'RootBridgeID': '32768.00:1b:54:00:00:01',
                          'BridgeID': f'32768.{SWITCH_MAC}', 'STPPort': '0x8001'}

def test_profinet_dcp_identify_response():
    pkt = decode(dcp_identify_response(PLC_MAC, 'plc-line-1', role=0x02))
    assert pkt.l2_protocol == 'PROFINET DCP'
    assert props(pkt) == {'ICSProtocol': 'PROFINET', 'TypeOfStation': 'S7-1500', 'NameOfStation': 'plc-line-1',
                          'VendorID': '0x002a', 'DeviceID': '0x0313', 'DeviceRole': 'IO-Controller', 'Category': 'PLC',
                          'Role': 'MASTER', 'IPAddress': '10.0.0.20', 'Netmask': '255.255.255.0'}

def test_profinet_identify_request_and_cyclic():
    assert ('Role', 'MASTER', 3) in decode(dcp_identify_request(PLC_MAC)).l2_properties
    pkt = decode(profinet_rt_frame(PLC_MAC, MAC_A))
    assert pkt.l2_protocol == 'PROFINET RT' and pkt.vlan is None  # priority-tagged, VLAN 0
    assert pkt.l2_properties == (('ICSProtocol', 'PROFINET', 3),)

def test_goose():
    pkt = decode(goose_frame(PLC_MAC))
    assert pkt.l2_protocol == 'IEC 61850 GOOSE' and pkt.vlan == 5
    assert props(pkt) == {'ICSProtocol': 'IEC 61850 GOOSE', 'Category': 'IED', 'APPID': '0x0001',
                          'GoCBRef': 'IED1LD0/LLN0$GO$gcb01', 'DataSet': 'IED1LD0/LLN0$DS1', 'GoID': 'IED1_GOOSE1'}

def test_truncated_frames_still_get_a_protocol():
    frame = lldp_frame(SWITCH_MAC, 'sw', 'Gi1')
    pkt = decode(frame[:20])
    assert pkt.l2_protocol == 'LLDP'
    pkt = decode(goose_frame(PLC_MAC)[:25])
    assert pkt.l2_protocol == 'IEC 61850 GOOSE'

def test_unknown_ethertype():
    from packet_builder import ethernet
    assert decode(ethernet('ff:ff:ff:ff:ff:ff', MAC_A, 0x9999, b'\x00' * 30)).l2_protocol == 'EtherType 0x9999'
