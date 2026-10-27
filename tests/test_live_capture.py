import io

import pytest

import storage
from capture import live_capture
from packet_builder import pcap_bytes, tcp_frame

class FakeDumpcap:
    """Stands in for the dumpcap process: stdout serves a capture, then the process exits."""

    def __init__(self, stdout=b'', stderr=b'', returncode=0):
        self.stdout = io.BufferedReader(io.BytesIO(stdout))
        self._stderr = stderr
        self.returncode = None
        self._exit_code = returncode

    def terminate(self):
        pass

    def communicate(self):
        self.returncode = self._exit_code
        return b'', self._stderr

@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / 'live.sqlite3')
    storage.init_db(path)
    return path

def only_session(db_path):
    with storage.connect(db_path) as conn:
        [session] = storage.list_sessions(conn)
        return session, storage.session_graph(conn, session['id'])

def test_live_capture_saves_a_session(db_path, monkeypatch):
    frames = [tcp_frame('10.0.0.57', '10.0.0.3', 2578, 502, bytes.fromhex('000100000006010300000001'))] * 20
    commands = []
    monkeypatch.setattr(live_capture.subprocess, 'Popen', lambda cmd, **kw: commands.append(cmd) or FakeDumpcap(pcap_bytes(frames)))
    monkeypatch.setattr(live_capture, 'SAVE_INTERVAL', 0)  # save after every packet
    assert live_capture.start_live_capture('eth9', db_path, 'port 502') is True
    assert commands == [['dumpcap', '-i', 'eth9', '-P', '-q', '-w', '-', '-f', 'port 502']]
    session, graph = only_session(db_path)
    assert (session['source'], session['status'], session['packet_count']) == ('live', 'stopped', 20)
    assert [e['packets'] for e in graph['edges']] == [20]
    assert {n['ip']: n['properties'].get('Role', {}).get('values') for n in graph['nodes']}['10.0.0.57'] == ['MASTER']

def test_dumpcap_errors_mark_the_session_failed(db_path, monkeypatch):
    fake = FakeDumpcap(stderr=b"dumpcap: You don't have permission to capture on that device", returncode=1)
    monkeypatch.setattr(live_capture.subprocess, 'Popen', lambda cmd, **kw: fake)
    assert live_capture.start_live_capture('eth9', db_path) is False
    session, _ = only_session(db_path)
    assert session['status'] == 'failed' and 'permission' in session['error']

def test_missing_dumpcap_marks_the_session_failed(db_path, monkeypatch):
    def not_installed(cmd, **kwargs):
        raise FileNotFoundError(2, 'No such file or directory', 'dumpcap')
    monkeypatch.setattr(live_capture.subprocess, 'Popen', not_installed)
    assert live_capture.start_live_capture('eth9', db_path) is False
    session, _ = only_session(db_path)
    assert session['status'] == 'failed' and 'Could not start dumpcap' in session['error']
