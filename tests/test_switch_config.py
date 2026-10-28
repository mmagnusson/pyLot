import os

from parser.switch_config import Neighbor, Port, interface_name, mac_address, parse

DATA = os.path.join(os.path.dirname(__file__), 'data')

def read(name):
    with open(os.path.join(DATA, name)) as f:
        return f.read()

def test_interface_names():
    assert interface_name('GigabitEthernet1/0/1') == 'Gi1/0/1'
    assert interface_name('Gig 1/0/1') == 'Gi1/0/1'
    assert interface_name('Gi1/0/1') == 'Gi1/0/1'
    assert interface_name('TenGigabitEthernet1/1/1') == 'Te1/1/1'
    assert interface_name('Ethernet1/12') == 'Eth1/12'
    assert interface_name('Port-channel1') == 'Po1'
    assert interface_name('CPU') is None

def test_mac_formats():
    assert mac_address('000e.8c11.2233') == '00:0e:8c:11:22:33'
    assert mac_address('00-0E-8C-11-22-33') == '00:0e:8c:11:22:33'
    assert mac_address('Gi1/0/1') is None

def test_ios_running_config_mac_table_and_cdp():
    data = parse(read('sw-access-1.txt'))
    assert data.hostname == 'sw-access-1'
    assert data.ports['Gi1/0/1'] == Port('Gi1/0/1', 'PLC line 1', 'access', 10, False)
    assert data.ports['Gi1/0/3'].shutdown
    assert data.ports['Gi1/0/24'] == Port('Gi1/0/24', 'Uplink to core', 'trunk', 99, False)
    assert 'Vl10' in data.ports
    assert data.macs == [('Gi1/0/1', 10, '00:0e:8c:11:22:33'), ('Gi1/0/2', 10, '00:50:04:93:70:67'),
                         ('Gi1/0/24', 10, '00:1b:54:cc:dd:01'), ('Gi1/0/24', 10, '00:02:b3:ce:70:51')]
    assert data.neighbors == [Neighbor('Gi1/0/24', 'sw-core-1', 'Gi1/0/1', 'cisco WS-C3850-24T', '10.0.0.1')]

def test_lldp_neighbors_and_hostname_from_prompt():
    data = parse(read('sw-core-1.txt'))
    assert data.hostname == 'sw-core-1'
    assert len(data.macs) == 3
    assert data.neighbors == [Neighbor('Gi1/0/1', 'sw-access-1', 'Gi1/0/24', None, '10.0.0.2')]

def test_nxos_and_old_ios_mac_tables():
    data = parse("""
   VLAN     MAC Address      Type      age     Secure NTFY Ports
---------+-----------------+--------+---------+------+----+------------------
*   20     0050.5683.1234   dynamic  0         F      F    Eth1/7
G    -     00de.fb12.3456   static   -         F      F    sup-eth1(R)
0011.2233.4455   Dynamic       30  FastEthernet0/4
""")
    assert data.macs == [('Eth1/7', 20, '00:50:56:83:12:34'), ('Fa0/4', 30, '00:11:22:33:44:55')]

def test_unrelated_text_is_empty():
    assert parse('hello world\nnothing to see').is_empty()
