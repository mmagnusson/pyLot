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

def test_error_messages_are_escaped(client, monkeypatch):
    def explode(path):
        raise RuntimeError('<script>alert(1)</script>')
    monkeypatch.setattr(app_module, 'parse_pcap', explode)
    response = upload(client)
    assert response.status_code == 500 and b'&lt;script&gt;' in response.data and b'<script>alert' not in response.data

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
    assert client.post('/sessions/99/delete').status_code == 404
