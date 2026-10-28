import io
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
    monkeypatch.setattr(app_module, 'parse_pcap', explode)
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
