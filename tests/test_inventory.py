import pytest

import advisories
import app as app_module
import inventory
import storage
from test_advisories import csaf
from test_app import client, controllogix_pcap, upload  # noqa: F401 (client is a fixture)

@pytest.fixture
def conn(tmp_path):
    db_path = str(tmp_path / 'inventory.sqlite3')
    storage.init_db(db_path)
    connection = storage.connect(db_path)
    yield connection
    connection.close()

def add_session(conn, name, devices, start=1000.0, status='ready'):
    """
    A finished session that saw these devices: dicts with ip and/or mac, optional via (router MAC),
    sent (packets sent, default 10) and identity properties (Vendor, Model, Firmware, Serial...).
    """
    session_id = storage.create_session(conn, name, 'upload', status)
    storage.update_session(conn, session_id, first_seen=start, last_seen=start + 60)
    with conn:
        for device in devices:
            device = dict(device)
            ip, mac, via, sent = device.pop('ip', None), device.pop('mac', None), device.pop('via', None), device.pop('sent', 10)
            if mac:
                conn.execute("INSERT OR IGNORE INTO mac_addresses (session_id, mac, vendor, packets, bytes, first_seen, last_seen) "
                             "VALUES (?, ?, NULL, 10, 1000, ?, ?)", (session_id, mac, start, start + 60))
            if ip:
                conn.execute("INSERT INTO hosts (session_id, ip, mac, vendor, via_mac, kind, packets_sent, packets_received, "
                             "bytes_sent, bytes_received, first_seen, last_seen) VALUES (?, ?, ?, NULL, ?, 'unicast', ?, 5, 100, 100, ?, ?)",
                             (session_id, ip, mac, via, sent, start, start + 60))
                for prop, value in device.items():
                    conn.execute("INSERT INTO evidence (session_id, ip, fingerprint, name, value, confidence, count, first_frame) "
                                 "VALUES (?, ?, 'decoder', ?, ?, 1, 1, 1)", (session_id, ip, prop, value))
            elif mac:
                for prop, value in device.items():
                    conn.execute("INSERT INTO mac_evidence (session_id, mac, protocol, name, value, confidence, count, first_frame) "
                                 "VALUES (?, ?, 'PROFINET DCP', ?, ?, 1, 1, 1)", (session_id, mac, prop, value))
    return session_id

def assets(conn):
    """The inventory, the PLC (10.0.0.3) first if it's there, then by id."""
    return sorted(inventory.list_assets(conn), key=lambda a: ('10.0.0.3' not in a['all_ips'], a['id']))

PLC = {'ip': '10.0.0.3', 'mac': '00:00:bc:00:00:03', 'Vendor': 'Rockwell Automation', 'Model': '1756-ENBT/A', 'Firmware': '6.1',
       'Serial': '0x00a1b2c3'}

def test_a_device_seen_in_several_sessions_is_one_asset(conn):
    add_session(conn, 'monday', [PLC, {'ip': '10.0.0.57', 'mac': '00:00:00:00:00:57'}], start=1000)
    add_session(conn, 'tuesday', [PLC], start=90000)
    found = assets(conn)
    assert len(found) == 2
    plc = found[0]
    assert plc['ips'] == ['10.0.0.3'] and plc['mac'] == PLC['mac'] and plc['model'] == '1756-ENBT/A'
    assert plc['sessions'] == 2 and plc['first_seen'] == 1000 and plc['last_seen'] == 90060
    assert plc['changes'] == 0 and plc['in_latest_session'] and not found[1]['in_latest_session']
    assert plc['label'] == '10.0.0.3'

def test_identity_changes_are_listed(conn):
    add_session(conn, 'before', [PLC], start=1000)
    add_session(conn, 'after', [{**PLC, 'ip': '10.0.1.3', 'Firmware': '6.6'}], start=5000)
    plc = assets(conn)[0]
    assert plc['firmware'] == '6.6' and plc['all_ips'] == ['10.0.0.3', '10.0.1.3'] and plc['changes'] == 2
    changes = inventory.get_asset(conn, plc['id'])['changes']
    assert {(c['label'], c['old'], c['new'], c['session_name']) for c in changes} == {
        ('IP address', '10.0.0.3', '10.0.1.3', 'after'), ('Firmware', '6.1', '6.6', 'after')}

def test_sessions_are_added_in_capture_order(conn):
    add_session(conn, 'newer', [{**PLC, 'Firmware': '6.6'}], start=5000)
    add_session(conn, 'older', [PLC], start=1000)
    plc = inventory.get_asset(conn, assets(conn)[0]['id'])
    assert plc['firmware'] == '6.6' and plc['first_seen'] == 1000
    assert [(c['old'], c['new']) for c in plc['changes']] == [('6.1', '6.6')]
    assert [s['session_name'] for s in plc['sightings']] == ['newer', 'older']

def test_a_new_mac_at_the_same_address_is_a_new_device(conn):
    add_session(conn, 'before', [{'ip': '10.0.0.9', 'mac': '00:00:00:00:00:01'}], start=1000)
    add_session(conn, 'after', [{'ip': '10.0.0.9', 'mac': '00:00:00:00:00:02'}], start=5000)
    found = assets(conn)
    assert len(found) == 2 and [a['sessions'] for a in found] == [1, 1]

def test_the_serial_number_follows_a_device_to_a_new_mac(conn):
    add_session(conn, 'before', [PLC], start=1000)
    add_session(conn, 'after', [{**PLC, 'mac': '00:00:bc:00:00:99'}], start=5000)
    found = assets(conn)
    assert len(found) == 1 and found[0]['mac'] == '00:00:bc:00:00:99'
    assert [c['label'] for c in inventory.get_asset(conn, found[0]['id'])['changes']] == ['MAC address']

def test_serial_numbers_belong_to_their_vendor(conn):
    add_session(conn, 'one', [{'ip': '10.0.0.1', 'mac': '00:00:00:00:00:01', 'Vendor': 'Siemens', 'Serial': '12345'}], start=1000)
    add_session(conn, 'two', [{'ip': '10.0.0.2', 'mac': '00:00:00:00:00:02', 'Vendor': 'Schneider Electric', 'Serial': '12345'}],
                start=5000)
    assert len(assets(conn)) == 2

def test_a_different_serial_behind_the_same_mac_is_a_different_device(conn):
    add_session(conn, 'one', [{**PLC, 'Serial': '1111'}], start=1000)
    add_session(conn, 'two', [{**PLC, 'Serial': '2222'}], start=5000)
    assert len(assets(conn)) == 2

def test_blank_serials_identify_nothing():
    assert inventory._normal_serial('0x00000000') is None and inventory._normal_serial(' ') is None
    assert inventory._normal_serial('0x00A1 B2C3') == '0x00a1b2c3'

def test_routed_hosts_are_tracked_by_private_address(conn):
    router = '00:00:0c:00:00:01'
    seen = [{'ip': '10.20.0.5', 'via': router}, {'ip': '8.8.8.8', 'via': router}, {'ip': '10.20.0.6', 'via': router, 'sent': 0},
            {'ip': '192.168.1.1', 'mac': router}]
    add_session(conn, 'one', seen, start=1000)
    add_session(conn, 'two', seen, start=5000)
    found = assets(conn)
    assert sorted(ip for a in found for ip in a['ips']) == ['10.20.0.5', '192.168.1.1']
    assert all(a['sessions'] == 2 for a in found)

def test_a_routed_host_seen_locally_later_keeps_its_asset(conn):
    add_session(conn, 'remote', [{'ip': '10.20.0.5', 'via': '00:00:0c:00:00:01'}], start=1000)
    add_session(conn, 'local', [{'ip': '10.20.0.5', 'mac': '00:00:00:00:20:05'}], start=5000)
    found = assets(conn)
    assert len(found) == 1 and found[0]['mac'] == '00:00:00:00:20:05' and found[0]['sessions'] == 2

def test_layer2_only_devices_are_assets(conn):
    add_session(conn, 'profinet', [{'mac': '00:0e:8c:00:00:01', 'NameOfStation': 'et200sp-1', 'Model': 'ET 200SP'}])
    asset = assets(conn)[0]
    assert asset['ips'] == [] and asset['name'] == 'et200sp-1' and asset['label'] == 'et200sp-1' and asset['model'] == 'ET 200SP'

def test_assets_outlive_their_sessions(conn):
    session_id = add_session(conn, 'gone', [PLC])
    plc = assets(conn)[0]
    storage.delete_session(conn, session_id)
    asset = inventory.get_asset(conn, plc['id'])
    assert asset['sightings'][0]['session_id'] is None and asset['sightings'][0]['session_name'] == 'gone'
    assert asset['model'] == '1756-ENBT/A'

def test_reanalysis_keeps_assets_and_their_names(conn):
    session_id = add_session(conn, 'capture', [PLC, {'ip': '10.0.0.57', 'mac': '00:00:00:00:00:57'}])
    before = assets(conn)
    inventory.update_asset(conn, before[1]['id'], name='Engineering laptop')
    storage.update_session(conn, session_id, capture_file='x.pcap')
    assert storage.reset_analysis(conn, session_id)
    with conn:  # analyzed again, and this time only the PLC is in it
        storage.update_session(conn, session_id, status='ready', first_seen=1000, last_seen=1060)
        conn.execute("INSERT INTO mac_addresses VALUES (?, ?, NULL, 10, 1000, 1000, 1060)", (session_id, PLC['mac']))
        conn.execute("INSERT INTO hosts VALUES (?, '10.0.0.3', ?, NULL, NULL, 'unicast', 10, 5, 100, 100, 1000, 1060)",
                     (session_id, PLC['mac']))
    after = assets(conn)
    assert [a['id'] for a in after] == [a['id'] for a in before]
    assert after[0]['sessions'] == 1 and after[1]['given_name'] == 'Engineering laptop' and after[1]['sessions'] == 0

def test_unfinished_sessions_wait(conn):
    session_id = add_session(conn, 'live', [PLC], status='capturing')
    assert assets(conn) == []
    storage.update_session(conn, session_id, status='stopped')
    assert len(assets(conn)) == 1

def test_naming_merging_and_removing(conn):
    add_session(conn, 'one', [PLC, {'ip': '10.0.0.57', 'mac': '00:00:00:00:00:57'}])
    plc, laptop = assets(conn)
    inventory.update_asset(conn, plc['id'], name='  Filler PLC ', notes='Line 2')
    assert assets(conn)[0]['label'] == 'Filler PLC' and assets(conn)[0]['notes'] == 'Line 2'
    with pytest.raises(ValueError):
        inventory.update_asset(conn, plc['id'], name='x' * 101)
    with pytest.raises(KeyError):
        inventory.update_asset(conn, 999, name='x')
    with pytest.raises(ValueError):
        inventory.merge_assets(conn, plc['id'], plc['id'])
    inventory.merge_assets(conn, plc['id'], laptop['id'])
    merged = assets(conn)
    assert len(merged) == 1 and merged[0]['given_name'] == 'Filler PLC' and set(merged[0]['all_ips']) == {'10.0.0.3', '10.0.0.57'}
    assert inventory.delete_asset(conn, plc['id']) and assets(conn) == []
    assert not inventory.delete_asset(conn, plc['id'])

def test_assets_are_checked_against_advisories(conn):
    advisories.import_advisories(conn, [('a.json', csaf('ICSA-24-001-01', [('Rockwell Automation', '1756-ENBT', '<=6.2', None)]))])
    add_session(conn, 'one', [PLC])
    plc = assets(conn)[0]
    assert plc['vulnerabilities'] == 1
    found = inventory.get_asset(conn, plc['id'])['vulnerabilities']
    assert [(v['advisory'], v['status']) for v in found] == [('ICSA-24-001-01', 'affected')]

# --- web pages

def test_uploads_are_added_to_the_inventory(client):
    upload(client, controllogix_pcap((20, 11)))
    host = client.get('/api/sessions/1/hosts/10.0.0.3').get_json()
    assert host['asset'] and host['asset']['sessions'] == 1
    with app_module.db() as c:
        assert c.execute("SELECT COUNT(*) FROM inventory_sessions").fetchone()[0] == 1
    upload(client, controllogix_pcap((20, 11)))
    assert client.get('/api/sessions/2/hosts/10.0.0.3').get_json()['asset']['sessions'] == 2

def test_inventory_pages(client):
    from packet_builder import pcap_bytes, tcp_frame
    request = tcp_frame('10.0.0.57', '10.0.0.3', 2578, 502, bytes.fromhex('000100000006010300000001'),
                        src_mac='00:00:00:00:00:57', dst_mac='00:00:bc:00:00:03')
    reply = tcp_frame('10.0.0.3', '10.0.0.57', 502, 2578, bytes.fromhex('0001000000050a03020007'),
                      src_mac='00:00:bc:00:00:03', dst_mac='00:00:00:00:00:57')
    upload(client, pcap_bytes([request, reply]))
    data = client.get('/api/inventory').get_json()
    assert data['sessions'] == 1 and len(data['assets']) == 2
    plc = next(a for a in data['assets'] if '10.0.0.3' in a['ips'])
    assert client.get('/inventory').status_code == 200
    page = client.get(f"/inventory/{plc['id']}")
    assert page.status_code == 200 and b'Sightings' in page.data and b'modbus.pcap' in page.data
    assert b'Saved.' in client.post(f"/inventory/{plc['id']}", data={'name': 'Line 2 <PLC>', 'notes': 'cabinet 4'}).data
    page = client.get(f"/inventory/{plc['id']}").data
    assert b'Line 2 &lt;PLC&gt;' in page and b'<PLC>' not in page
    assert client.post(f"/inventory/{plc['id']}", data={'name': 'x' * 101}).status_code == 400
    csv = client.get('/inventory.csv').data.decode()
    assert csv.startswith('id,given_name,name,ips') and 'Line 2 <PLC>' in csv
    other = next(a for a in data['assets'] if a['id'] != plc['id'])
    assert b'Merged asset' in client.post(f"/inventory/{plc['id']}/merge", data={'other': other['id']}).data
    assert client.post(f"/inventory/{plc['id']}/merge", data={'other': 'x'}).status_code == 400
    assert client.post(f"/inventory/{plc['id']}/merge", data={'other': 999}).status_code == 404
    assert client.post(f"/inventory/{plc['id']}/delete").status_code == 302
    assert client.get(f"/inventory/{plc['id']}").status_code == 404
    assert client.get('/api/inventory').get_json()['assets'] == []

def test_viewers_cant_change_the_inventory(client):
    from test_auth import accounts, sign_in
    upload(client, controllogix_pcap((20, 11)))
    accounts(alice='admin', vera='viewer')
    sign_in(client, 'vera')
    asset_id = client.get('/api/inventory').get_json()['assets'][0]['id']
    page = client.get(f'/inventory/{asset_id}')
    assert page.status_code == 200 and b'Merge or remove' not in page.data and b'Name and notes' not in page.data
    assert client.post(f'/inventory/{asset_id}', data={'name': 'x'}).status_code == 403
    assert client.post(f'/inventory/{asset_id}/delete').status_code == 403
