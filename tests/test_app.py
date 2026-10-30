import io
import json
import os
import tempfile

import pytest

# Point the app at throwaway storage before it initializes on import
_scratch = tempfile.mkdtemp(prefix='pylot-test-')
os.environ['PYLOT_DB_PATH'] = os.path.join(_scratch, 'import.sqlite3')
os.environ['PYLOT_UPLOAD_FOLDER'] = os.path.join(_scratch, 'uploads')

import app as app_module  # noqa: E402
import storage  # noqa: E402
from packet_builder import pcap_bytes, tcp_frame  # noqa: E402

MODBUS_PCAP = pcap_bytes([
    tcp_frame('10.0.0.57', '10.0.0.3', 2578, 502, bytes.fromhex('000100000006010300000001')),
    tcp_frame('10.0.0.3', '10.0.0.57', 502, 2578, bytes.fromhex('0001000000050a03020007')),
])

@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / 'test.sqlite3')
    storage.init_db(db_path)
    monkeypatch.setattr(app_module, 'DB_PATH', db_path)
    uploads = tmp_path / 'uploads'
    uploads.mkdir()
    monkeypatch.setitem(app_module.app.config, 'UPLOAD_FOLDER', str(uploads))
    # Run background analysis inline so tests see its results immediately
    monkeypatch.setattr(app_module, 'submit', lambda fn, *args: fn(*args))
    return app_module.app.test_client()

def upload(client, data=MODBUS_PCAP, name='modbus.pcap', **kwargs):
    return client.post('/upload', data={'pcap_file': (io.BytesIO(data), name)}, **kwargs)

def uploaded_files(client):
    return os.listdir(app_module.app.config['UPLOAD_FOLDER'])

def test_upload_creates_a_classified_session(client):
    response = upload(client)
    assert response.status_code == 302 and response.headers['Location'] == '/sessions/1'
    graph = client.get('/api/sessions/1/graph').get_json()
    nodes = {n['ip']: n for n in graph['nodes']}
    assert nodes['10.0.0.57']['properties']['Role']['values'] == ['MASTER']
    assert nodes['10.0.0.3']['properties']['Role']['values'] == ['SLAVE']
    assert graph['session']['name'] == 'modbus.pcap'
    assert b'modbus.pcap' in client.get('/').data
    assert client.get('/sessions/1').status_code == 200

def test_each_upload_is_its_own_session(client):
    upload(client, name='first.pcap')
    upload(client, name='second.pcap')
    page = client.get('/').data
    assert b'first.pcap' in page and b'second.pcap' in page
    assert client.get('/network').headers['Location'] == '/sessions/2'

def test_traversal_filename_stays_in_uploads(client):
    assert upload(client, name='../../../evil.pcap').status_code == 302
    [saved] = uploaded_files(client)
    assert saved.endswith('_evil.pcap')

def test_rejects_non_captures_and_missing_files(client):
    response = upload(client, data=b'MZ\x90\x00 not a capture', name='x.pcap')
    assert response.status_code == 400 and b'not a PCAP' in response.data
    response = client.post('/upload', data={})
    assert response.status_code == 400 and b'No file selected' in response.data
    assert uploaded_files(client) == []

def test_unreadable_capture_is_reported_and_discarded(client):
    response = upload(client, data=pcap_bytes([b'\x00' * 30], linktype=105))
    assert response.status_code == 400 and b'link type' in response.data
    assert uploaded_files(client) == [] and client.get('/api/sessions/1/graph').status_code == 404

def test_analysis_failures_mark_the_session_failed_and_are_escaped(client, monkeypatch):
    def explode(path):
        raise RuntimeError('<script>alert(1)</script>')
    monkeypatch.setattr(app_module, 'parse_file', explode)
    assert upload(client).status_code == 302
    session = client.get('/api/sessions/1').get_json()
    assert session['status'] == 'failed' and '<script>alert(1)</script>' in session['error']
    page = client.get('/').data
    assert b'&lt;script&gt;' in page and b'<script>alert' not in page
    assert uploaded_files(client) == []

def test_uploads_are_analyzed_in_the_background(client, monkeypatch):
    jobs = []
    monkeypatch.setattr(app_module, 'submit', lambda fn, *args: jobs.append((fn, args)))
    assert upload(client).status_code == 302
    assert client.get('/api/sessions/1').get_json()['status'] == 'processing'
    assert client.post('/sessions/1/delete').status_code == 409
    fn, args = jobs.pop()
    fn(*args)
    assert client.get('/api/sessions/1').get_json()['status'] == 'ready'

@pytest.mark.parametrize('headers', [{'Origin': 'http://evil.example'}, {'Referer': 'http://evil.example/page'}])
def test_cross_site_posts_are_refused(client, headers):
    assert upload(client, headers=headers).status_code == 403

def test_same_origin_posts_are_allowed(client):
    assert upload(client, headers={'Origin': 'http://localhost'}).status_code == 302

def test_untrusted_host_header_is_refused(client):
    assert client.get('/', base_url='http://evil.example').status_code == 400
    assert client.get('/', base_url='http://127.0.0.1:5000').status_code == 200

def test_oversized_upload(client, monkeypatch):
    monkeypatch.setitem(app_module.app.config, 'MAX_CONTENT_LENGTH', 1024)
    response = upload(client, data=MODBUS_PCAP + b'\x00' * 4096)
    assert response.status_code == 413 and b'upload limit' in response.data

def test_delete_session_removes_rows_and_capture_file(client):
    upload(client)
    assert client.post('/sessions/1/delete').status_code == 302
    assert uploaded_files(client) == []
    assert client.get('/sessions/1').status_code == 404

def test_capturing_sessions_cannot_be_deleted(client):
    with storage.connect(app_module.DB_PATH) as conn:
        session_id = storage.create_session(conn, 'Live capture on eth9', 'live', 'capturing')
    assert client.post(f'/sessions/{session_id}/delete').status_code == 409

def test_missing_sessions_are_404(client):
    assert client.get('/sessions/99').status_code == 404
    assert client.get('/api/sessions/99/graph').status_code == 404
    assert client.get('/api/sessions/99').get_json() == {'error': 'Not found'}
    assert client.post('/sessions/99/delete').status_code == 404
    assert client.post('/sessions/99/stop').status_code == 404

def test_host_and_flow_tables(client):
    upload(client)
    data = client.get('/api/sessions/1/hosts?sort=packets_sent&order=desc&limit=1').get_json()
    assert data['total'] == 2 and len(data['hosts']) == 1
    assert client.get('/api/sessions/1/hosts?q=slave').get_json()['hosts'][0]['ip'] == '10.0.0.3'
    flows = client.get('/api/sessions/1/flows?host=10.0.0.3&q=502').get_json()
    assert flows['total'] == 2 and {f['protocol'] for f in flows['flows']} == {'Modbus'}
    assert client.get('/api/sessions/1/flows?limit=abc').status_code == 400

def test_host_detail(client):
    upload(client)
    host = client.get('/api/sessions/1/hosts/10.0.0.3').get_json()
    assert host['role'] == 'SLAVE' and host['flow_count'] == 2
    assert {'fingerprint': 'MODBUS', 'name': 'Unit', 'value': '0A'}.items() <= next(e for e in host['evidence'] if e['name'] == 'Unit').items()
    assert client.get('/api/sessions/1/hosts/10.9.9.9').status_code == 404

def test_csv_exports(client):
    upload(client)
    hosts = client.get('/sessions/1/hosts.csv')
    assert hosts.mimetype == 'text/csv' and hosts.data.decode().splitlines()[0].startswith('ip,mac,vendor')
    assert 'MODBUS' in hosts.data.decode()
    flows = client.get('/sessions/1/flows.csv').data.decode().splitlines()
    assert flows[0].startswith('src,dst,transport') and len(flows) == 3

def test_start_capture_from_the_page(client, monkeypatch):
    launched = []
    monkeypatch.setattr(app_module.live_capture, 'list_interfaces', lambda: ['eth9'])
    monkeypatch.setattr(app_module.live_capture, 'launch', lambda *args: launched.append(args) or 7)
    response = client.post('/captures', data={'interface': 'eth9', 'capture_filter': 'not port 22'})
    assert response.headers['Location'] == '/sessions/7'
    assert launched == [('eth9', app_module.DB_PATH, 'not port 22')]
    assert client.post('/captures', data={'interface': 'wlan-evil'}).status_code == 400
    assert client.post('/captures', data={'interface': 'eth9', 'capture_filter': 'x' * 501}).status_code == 400

def test_capture_unavailable(client, monkeypatch):
    def unavailable():
        raise RuntimeError("dumpcap isn't installed")
    monkeypatch.setattr(app_module.live_capture, 'list_interfaces', unavailable)
    assert client.get('/api/interfaces').get_json() == {'interfaces': [], 'error': "dumpcap isn't installed"}
    assert client.post('/captures', data={'interface': 'eth9'}).status_code == 503

def test_stopping_a_capture_this_process_no_longer_runs(client):
    with storage.connect(app_module.DB_PATH) as conn:
        session_id = storage.create_session(conn, 'Live capture on eth9', 'live', 'capturing')
    assert client.post(f'/sessions/{session_id}/stop').status_code == 302
    assert client.get(f'/api/sessions/{session_id}').get_json()['status'] == 'stopped'

# --- Phase 3

from packet_builder import goose_frame, lldp_frame  # noqa: E402

SWITCH_TEXT = """sw-access-1#show mac address-table
  10    0050.0493.7067    DYNAMIC     Gi1/0/2
"""

def test_named_networks_api(client):
    response = client.post('/api/networks', json={'cidr': '10.0.0.0/24', 'name': 'Process control'})
    assert response.status_code == 201
    network = response.get_json()
    assert client.post('/api/networks', json={'cidr': '10.0.0.0/24'}).status_code == 400
    assert client.post('/api/networks', json={'cidr': 'nope'}).get_json()['error']
    assert client.post('/api/networks', data='not json').status_code == 400
    assert client.put(f"/api/networks/{network['id']}", json={'name': 'Cell 1'}).get_json()['name'] == 'Cell 1'
    upload(client)
    groups = client.get('/api/sessions/1/graph').get_json()['groups']
    assert groups[0]['label'] == 'Cell 1 (10.0.0.0/24)'
    assert client.get('/api/networks').get_json()['networks'][0]['name'] == 'Cell 1'
    assert client.delete(f"/api/networks/{network['id']}").status_code == 204
    assert client.delete(f"/api/networks/{network['id']}").status_code == 404
    assert client.get('/networks').status_code == 200

def test_settings_api(client):
    assert client.put('/api/settings', json={'auto_prefix_v4': 16}).get_json()['auto_prefix_v4'] == 16
    assert client.put('/api/settings', json={'auto_prefix_v4': '16'}).status_code == 400
    assert client.put('/api/settings', json={'nope': 1}).status_code == 400
    assert client.get('/api/networks').get_json()['settings'] == {'auto_prefix_v4': 16, 'auto_prefix_v6': 64}

def test_cross_site_json_writes_are_refused(client):
    assert client.post('/api/networks', json={'cidr': '10.0.0.0/24'}, headers={'Origin': 'http://evil.example'}).status_code == 403
    assert client.delete('/api/networks/1', headers={'Origin': 'http://evil.example'}).status_code == 403

def test_devices_and_physical_view(client):
    upload(client, pcap_bytes([lldp_frame('00:1b:54:cc:dd:01', 'sw-access-1', 'Gi1/0/5'), goose_frame('00:0e:8c:11:22:33'),
                               tcp_frame('10.0.0.57', '10.0.0.3', 2578, 502, b'')]))
    devices = client.get('/api/sessions/1/devices?sort=mac').get_json()
    assert devices['total'] == 3
    ied = client.get('/api/sessions/1/devices/00:0E:8C:11:22:33').get_json()
    assert ied['category'] == 'IED' and ied['l2_flows'][0]['protocol'] == 'IEC 61850 GOOSE'
    assert client.get('/api/sessions/1/devices/aa:bb:cc:dd:ee:ff').status_code == 404

    response = client.post('/api/sessions/1/switches', data={'config_file': (io.BytesIO(SWITCH_TEXT.encode()), 'sw1.txt')})
    assert response.status_code == 201 and response.get_json()['name'] == 'sw-access-1' and response.get_json()['macs'] == 1
    assert client.post('/api/sessions/1/switches', data={'config_text': 'nothing useful'}).status_code == 400
    assert client.post('/api/sessions/1/switches', data={'config_file': (io.BytesIO(b'\x00\x01'), 'x.bin')}).status_code == 400
    assert client.post('/api/sessions/1/switches', data={'config_text': SWITCH_TEXT, 'name': 'Pasted'}).get_json()['name'] == 'Pasted'

    graph = client.get('/api/sessions/1/physical').get_json()
    assert {s['name'] for s in graph['switches']} == {'sw-access-1', 'Pasted'}
    assert any(e['source'] == 'capture' for e in graph['edges'])
    switch_id = graph['switches'][0]['id']
    assert client.delete(f'/api/sessions/1/switches/{switch_id}').status_code == 204
    assert client.delete(f'/api/sessions/1/switches/{switch_id}').status_code == 404

    csv_text = client.get('/sessions/1/devices.csv').get_data(as_text=True)
    assert csv_text.splitlines()[0].startswith('mac,vendor,name,ips,vlans') and 'IEC 61850 GOOSE' in csv_text

def test_compare_sessions(client):
    upload(client)
    upload(client, pcap_bytes([tcp_frame('10.0.0.57', '10.0.0.9', 2578, 22, b'')]))
    diff = client.get('/api/sessions/2/compare?baseline=1').get_json()
    assert diff['baseline']['id'] == 1
    assert [h['ip'] for h in diff['new_hosts']['items']] == ['10.0.0.9']
    assert [h['ip'] for h in diff['missing_hosts']['items']] == ['10.0.0.3']
    assert client.get('/api/sessions/2/compare').status_code == 400
    assert client.get('/api/sessions/2/compare?baseline=99').status_code == 400
    assert client.get('/sessions/2/compare?baseline=1').status_code == 200

def test_graph_with_a_baseline(client):
    upload(client)
    upload(client, pcap_bytes([tcp_frame('10.0.0.57', '10.0.0.9', 2578, 22, b'')]))
    graph = client.get('/api/sessions/2/graph?baseline=1').get_json()
    assert graph['baseline']['new_hosts'] == 1
    assert next(n for n in graph['nodes'] if n['id'] == '10.0.0.9')['change'] == 'new'
    assert client.get('/api/sessions/2/graph?baseline=99').status_code == 400

def test_upload_zeek_conn_log(client):
    with open(os.path.join(os.path.dirname(__file__), 'data', 'conn.log'), 'rb') as f:
        data = f.read()
    assert upload(client, data=data, name='conn.log').headers['Location'] == '/sessions/1'
    hosts = client.get('/api/sessions/1/hosts').get_json()
    assert hosts['total'] == 4 and any(h['role'] == 'SLAVE' for h in hosts['hosts'])
    response = upload(client, data=b'{"not": "zeek"}\n', name='x.json')
    assert response.status_code == 400 and b'id.orig_h' in response.data
    assert upload(client, data=b'plain text', name='x.txt').status_code == 400

def test_reanalyze_session(client, monkeypatch):
    upload(client)
    client.post('/api/sessions/1/switches', data={'config_text': SWITCH_TEXT})
    with storage.connect(app_module.DB_PATH) as conn:
        conn.execute("UPDATE hosts SET vendor = 'Truncated Co.' WHERE session_id = 1")
    assert client.post('/sessions/1/reanalyze').headers['Location'] == '/sessions/1'
    hosts = client.get('/api/sessions/1/hosts').get_json()['hosts']
    assert hosts and 'Truncated Co.' not in {h['vendor'] for h in hosts}
    assert client.get('/api/sessions/1').get_json()['status'] == 'ready'
    assert len(client.get('/api/sessions/1/physical').get_json()['switches']) == 1  # imports survive
    assert len(uploaded_files(client)) == 1

def test_failed_reanalysis_keeps_the_file(client, monkeypatch):
    upload(client)
    working = app_module.parse_file
    def explode(path):
        raise RuntimeError('decoder bug')
    monkeypatch.setattr(app_module, 'parse_file', explode)
    client.post('/sessions/1/reanalyze')
    session = client.get('/api/sessions/1').get_json()
    assert session['status'] == 'failed' and 'decoder bug' in session['error'] and session['capture_file']
    assert len(uploaded_files(client)) == 1
    monkeypatch.setattr(app_module, 'parse_file', working)
    client.post('/sessions/1/reanalyze')
    assert client.get('/api/sessions/1').get_json()['status'] == 'ready'

def test_reanalyze_refusals(client, monkeypatch):
    with storage.connect(app_module.DB_PATH) as conn:
        live = storage.create_session(conn, 'Live capture on eth0', 'live', 'stopped')
    assert client.post(f'/sessions/{live}/reanalyze').status_code == 409
    queued = []
    monkeypatch.setattr(app_module, 'submit', lambda fn, *args: queued.append(args))
    upload(client)
    assert client.post('/sessions/2/reanalyze').status_code == 409  # still processing
    os.remove(os.path.join(app_module.app.config['UPLOAD_FOLDER'], uploaded_files(client)[0]))
    with storage.connect(app_module.DB_PATH) as conn:
        storage.update_session(conn, 2, status='ready')
    assert client.post('/sessions/2/reanalyze').status_code == 409  # file gone
    assert client.post('/sessions/99/reanalyze').status_code == 404

def test_reanalyze_all(client, monkeypatch):
    upload(client)
    upload(client)
    queued = []
    monkeypatch.setattr(app_module, 'submit', lambda fn, *args: queued.append(args))
    assert client.post('/sessions/reanalyze').status_code == 302
    assert [args[0] for args in queued] == [1, 2] and all(args[2] is False for args in queued)
    assert {s['status'] for s in (client.get(f'/api/sessions/{i}').get_json() for i in (1, 2))} == {'processing'}
    assert 'Re-analyze all uploads' in client.get('/').get_data(as_text=True)

# --- industrial operations and identity

def ics_pcap(firmware=(20, 11)):
    from packet_builder import enip_list_identity_reply, modbus_adu, udp_frame
    return pcap_bytes([
        tcp_frame('10.0.0.57', '10.0.0.3', 2578, 502, modbus_adu(6, b'\x00\x01\x00\x2a'), seq=100),
        tcp_frame('10.0.0.57', '10.0.0.3', 2578, 502, modbus_adu(3, b'\x00\x00\x00\x01', transaction=2), seq=112),
        udp_frame('10.0.0.3', '10.0.0.57', 44818, 2000, enip_list_identity_reply(revision=firmware, name='1756-L71=SUM(A1)')),
    ])

def test_operations_api_lists_writes_first_and_filters(client):
    upload(client, data=ics_pcap())
    data = client.get('/api/sessions/1/operations').get_json()
    assert [(o['operation'], o['kind']) for o in data['operations']] == [('Write Single Register', 'write'),
                                                                         ('Read Holding Registers', 'read')]
    assert data['kinds'] == {'write': 1, 'read': 1}
    assert client.get('/api/sessions/1/operations?kind=read').get_json()['total'] == 1
    assert client.get('/api/sessions/1/operations?q=holding').get_json()['total'] == 1
    edge = next(e for e in client.get('/api/sessions/1/graph').get_json()['edges'] if e['source'] == '10.0.0.57')
    assert edge['operations'] == ['read', 'write']

def test_host_detail_has_identity_and_operations(client):
    upload(client, data=ics_pcap())
    host = client.get('/api/sessions/1/hosts/10.0.0.3').get_json()
    assert (host['model'], host['firmware'], host['serial']) == ('1756-L71=SUM(A1)', '20.011', '0x00ABCDEF')
    assert host['device_vendor'] == 'Rockwell Automation/Allen-Bradley'
    assert host['operation_count'] == 2 and host['operations'][0]['operation'] == 'Write Single Register'
    assert client.get('/api/sessions/1/hosts?sort=firmware').status_code == 200

def test_csv_exports_include_operations_and_disarm_formulas(client):
    upload(client, data=ics_pcap())
    operations = client.get('/sessions/1/operations.csv').data.decode()
    assert operations.splitlines()[0] == 'src,dst,protocol,operation,kind,count,first_seen,last_seen,first_frame'
    assert 'Write Single Register,write' in operations
    hosts = client.get('/sessions/1/hosts.csv').data.decode()
    assert "'1756-L71=SUM(A1)" not in hosts and '1756-L71=SUM(A1)' in hosts  # only a leading = is a formula

def test_compare_reports_new_operations_and_firmware_changes(client):
    from packet_builder import enip_list_identity_reply, modbus_adu, udp_frame
    upload(client, data=pcap_bytes([
        tcp_frame('10.0.0.57', '10.0.0.3', 2578, 502, modbus_adu(3, b'\x00\x00\x00\x01')),
        udp_frame('10.0.0.3', '10.0.0.57', 44818, 2000, enip_list_identity_reply(revision=(20, 11)))]), name='before.pcap')
    upload(client, data=ics_pcap(firmware=(21, 3)), name='after.pcap')
    diff = client.get('/api/sessions/2/compare?baseline=1').get_json()
    assert [(o['operation'], o['kind']) for o in diff['new_operations']['items']] == [('Write Single Register', 'write')]
    changes = {c['what']: (c['before'], c['now']) for c in diff['changed_hosts']['items'][0]['changes']}
    assert changes == {'Firmware': ('20.011', '21.003'), 'Model': ('1756-L71/B LOGIX5571', '1756-L71=SUM(A1)'),
                       'Product': ('1756-L71/B LOGIX5571', '1756-L71=SUM(A1)')}

def test_identity_heard_in_only_one_session_is_not_a_change(client):
    from packet_builder import modbus_adu
    upload(client, data=pcap_bytes([tcp_frame('10.0.0.57', '10.0.0.3', 2578, 502, modbus_adu(3, b'\x00\x00\x00\x01'))]))
    upload(client, data=ics_pcap())
    diff = client.get('/api/sessions/2/compare?baseline=1').get_json()
    assert not any(c['what'] in ('Firmware', 'Product', 'Serial') for h in diff['changed_hosts']['items'] for c in h['changes'])

def test_reanalyze_clears_operations(client):
    upload(client, data=ics_pcap())
    with storage.connect(app_module.DB_PATH) as conn:
        assert storage.reset_analysis(conn, 1)
        assert storage.list_operations(conn, 1)[1] == 0

def test_alerts_api_csv_host_panel_and_compare(client):
    from packet_builder import modbus_adu
    upload(client, data=pcap_bytes([tcp_frame('10.0.0.57', '10.0.0.3', 2578, 502, modbus_adu(3, b'\x00\x00\x00\x01'))]),
           name='before.pcap')
    upload(client, data=ics_pcap(), name='after.pcap')
    data = client.get('/api/sessions/2/alerts').get_json()
    assert [(a['severity'], a['title']) for a in data['alerts']] == [('low', 'Writes to a device')]
    assert data['counts'] == {'high': 0, 'medium': 0, 'low': 1}
    assert client.get('/api/sessions/1/alerts').get_json()['alerts'] == []
    assert 'low,Writes to a device,10.0.0.57,10.0.0.3,Modbus,Write Single Register,1' in client.get('/sessions/2/alerts.csv').data.decode()
    assert [a['rule'] for a in client.get('/api/sessions/2/hosts/10.0.0.3').get_json()['alerts']] == ['write']
    diff = client.get('/api/sessions/2/compare?baseline=1').get_json()
    assert [a['rule'] for a in diff['new_alerts']['items']] == ['write']

# --- security advisories and vulnerabilities

def import_advisory(client, document, name='advisory.json'):
    return client.post('/advisories/import', data={'advisory_file': (io.BytesIO(json.dumps(document).encode()), name)})

def controllogix_pcap(firmware):
    from packet_builder import enip_list_identity_reply, udp_frame
    return pcap_bytes([udp_frame('10.0.0.3', '10.0.0.57', 44818, 2000, enip_list_identity_reply(revision=firmware))])

def test_advisories_page_imports_and_sessions_list_vulnerabilities(client):
    from test_advisories import csaf
    assert 'advisories' in client.get('/advisories').get_data(as_text=True)
    advisory = csaf('ICSA-24-001-01', [('Rockwell Automation', 'ControlLogix 5570 controllers', '<= 20.054', ())],
                    cves=(('CVE-2024-1111', 9.8),), title='Rockwell ControlLogix')
    page = import_advisory(client, advisory)
    assert page.status_code == 200 and 'Imported 1 new and 0 updated advisories.' in page.get_data(as_text=True)
    upload(client, data=controllogix_pcap((20, 11)), name='old.pcap')
    upload(client, data=controllogix_pcap((21, 3)), name='new.pcap')

    data = client.get('/api/sessions/1/vulnerabilities').get_json()
    assert data['advisories'] == 1 and data['counts'] == {'affected': 1, 'possible': 0, 'devices': 1}
    [v] = data['vulnerabilities']
    assert (v['ip'], v['advisory'], v['status'], v['match'], v['severity'], v['cves']) == (
        '10.0.0.3', 'ICSA-24-001-01', 'affected', 'product family', 'critical', ['CVE-2024-1111'])
    assert v['url'] == 'https://www.cisa.gov/news-events/ics-advisories/icsa-24-001-01'
    assert client.get('/api/sessions/2/vulnerabilities').get_json()['vulnerabilities'] == []  # firmware 21.003 is fixed
    assert [x['advisory'] for x in client.get('/api/sessions/1/hosts/10.0.0.3').get_json()['vulnerabilities']] == ['ICSA-24-001-01']
    rows = client.get('/sessions/1/vulnerabilities.csv').data.decode().splitlines()
    assert rows[0].startswith('status,severity,score,ip,module,vendor,model,firmware,advisory,title,cves')
    assert rows[1].startswith('affected,critical,9.8,10.0.0.3,,Rockwell Automation/Allen-Bradley,1756-L71/B LOGIX5571,20.011,ICSA-24-001-01')
    diff = client.get('/api/sessions/1/compare?baseline=2').get_json()
    assert [x['advisory'] for x in diff['new_vulnerabilities']['items']] == ['ICSA-24-001-01']
    assert client.get('/api/sessions/2/compare?baseline=1').get_json()['new_vulnerabilities']['total'] == 0

    assert client.post('/advisories/delete').status_code == 200
    assert client.get('/api/sessions/1/vulnerabilities').get_json() == {
        'vulnerabilities': [], 'counts': {'affected': 0, 'possible': 0, 'devices': 0}, 'advisories': 0}

def test_advisory_imports_that_hold_no_advisories(client):
    assert client.post('/advisories/import', data={}).status_code == 400
    assert import_advisory(client, {'document': {}}).status_code == 400
    assert client.post('/advisories/import', data={'advisory_file': (io.BytesIO(b'\x00\x01'), 'x.bin')}).status_code == 400

def test_fetching_advisories_without_internet(client, monkeypatch):
    import urllib.error

    def offline(conn):
        raise urllib.error.URLError('Name or service not known')
    monkeypatch.setattr(app_module.advisories, 'fetch_cisa', offline)
    page = client.post('/advisories/fetch')
    assert page.status_code == 502 and 'download the archive elsewhere' in page.get_data(as_text=True)
