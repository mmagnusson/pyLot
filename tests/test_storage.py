import pytest

import storage
from packet_builder import packet
from parser.analysis import CaptureAnalyzer
from parser.pcap_parser import engine

@pytest.fixture
def conn(tmp_path):
    path = str(tmp_path / 'test.sqlite3')
    storage.init_db(path)
    connection = storage.connect(path)
    yield connection
    connection.close()

def modbus_analyzer():
    analyzer = CaptureAnalyzer(engine)
    analyzer.add(packet(src='10.0.0.57', dst='10.0.0.3', src_port=2578, dst_port=502, payload=bytes.fromhex('000100000006010300000001')))
    analyzer.add(packet(src='10.0.0.3', dst='10.0.0.57', src_port=502, dst_port=2578, payload=bytes.fromhex('0001000000050a03020007')))
    return analyzer

def test_aggregate_properties_follows_grassmarlin():
    # The example from the GRASSMARLIN 3.2 user guide: the lower confidence number wins, ties keep both
    assert storage.aggregate_properties([('Model', 'Gruntmaster9000', 3), ('Model', 'Acorn', 2)]) == \
        {'Model': {'confidence': 2, 'values': ['Acorn']}}
    assert storage.aggregate_properties([('Model', 'Gruntmaster9000', 2), ('Model', 'Acorn', 2)]) == \
        {'Model': {'confidence': 2, 'values': ['Acorn', 'Gruntmaster9000']}}

def test_session_graph(conn):
    session_id = storage.create_session(conn, 'modbus.pcap', 'upload', 'ready')
    storage.save_analysis(conn, session_id, modbus_analyzer())
    graph = storage.session_graph(conn, session_id)
    nodes = {n['ip']: n for n in graph['nodes']}
    assert nodes['10.0.0.57']['properties']['Role'] == {'confidence': 4, 'values': ['MASTER']}
    assert nodes['10.0.0.3']['properties']['Unit'] == {'confidence': 4, 'values': ['0A']}
    assert {(e['source'], e['target']) for e in graph['edges']} == {('10.0.0.57', '10.0.0.3'), ('10.0.0.3', '10.0.0.57')}
    assert graph['edges'][0]['protocols'] == ['Modbus']
    assert storage.get_session(conn, session_id)['packet_count'] == 2

def test_saving_again_updates_rather_than_duplicates(conn):
    session_id = storage.create_session(conn, 'live', 'live', 'capturing')
    analyzer = modbus_analyzer()
    storage.save_analysis(conn, session_id, analyzer, only_dirty=True)
    analyzer.add(packet(src='10.0.0.57', dst='10.0.0.3', src_port=2578, dst_port=502, payload=b'\x00'))
    storage.save_analysis(conn, session_id, analyzer, only_dirty=True)
    flows = conn.execute("SELECT packets FROM flows WHERE session_id = ? AND dst_port = 502", (session_id,)).fetchall()
    assert [row['packets'] for row in flows] == [2]
    assert conn.execute("SELECT packets_sent FROM hosts WHERE ip = '10.0.0.57'").fetchone()[0] == 2

def test_delete_session_removes_its_rows(conn):
    session_id = storage.create_session(conn, 'x', 'upload', 'ready')
    storage.save_analysis(conn, session_id, modbus_analyzer())
    storage.delete_session(conn, session_id)
    for table in ('hosts', 'flows', 'evidence', 'mac_addresses'):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0

def test_init_db_stops_captures_left_over_from_a_previous_run(tmp_path):
    path = str(tmp_path / 'test.sqlite3')
    storage.init_db(path)
    with storage.connect(path) as conn:
        session_id = storage.create_session(conn, 'live', 'live', 'capturing')
    storage.init_db(path)
    with storage.connect(path) as conn:
        assert storage.get_session(conn, session_id)['status'] == 'stopped'

def test_update_session_rejects_unknown_fields(conn):
    with pytest.raises(ValueError):
        storage.update_session(conn, 1, id=5)
