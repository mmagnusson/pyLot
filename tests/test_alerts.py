import pytest

import alerts
import storage

ENG, MASTER, PLC, PLC2 = '10.0.0.5', '10.0.0.6', '10.0.0.20', '10.0.0.21'

@pytest.fixture
def conn(tmp_path):
    path = str(tmp_path / 'alerts.sqlite3')
    storage.init_db(path)
    connection = storage.connect(path)
    yield connection
    connection.close()

def session(conn, operations=(), flows=()):
    session_id = storage.create_session(conn, 'test', 'upload', 'ready')
    with conn:
        conn.executemany("INSERT INTO operations VALUES (?, ?, ?, ?, ?, ?, ?, 100.0, 200.0, 7)",
                         [(session_id,) + op for op in operations])
        conn.executemany("INSERT INTO flows VALUES (?, ?, ?, 6, 40000, ?, 'x', ?, 100, 100.0, 100.0)",
                         [(session_id,) + flow for flow in flows])
    return session_id

def found(conn, session_id):
    return [(a['severity'], a['rule'], a['src'], a['dst']) for a in alerts.session_alerts(conn, session_id)]

def test_operations_become_alerts_by_what_they_do(conn):
    session_id = session(conn, [
        (ENG, PLC, 'S7comm', 'Download Block', 'program', 40),
        (ENG, PLC, 'S7comm', 'PLC Stop', 'control', 1),
        (ENG, PLC, 'S7comm', 'Start Upload', 'program', 1),
        (MASTER, PLC2, 'DNP3', 'Direct Operate', 'control', 3),
        (MASTER, PLC2, 'DNP3', 'Write', 'write', 2),
        (MASTER, PLC2, 'IEC 104', 'C_CS_NA_1 Clock synchronization command', 'write', 1),
        (ENG, PLC, 'S7comm', 'PLC Password', 'session', 1),
        (ENG, PLC, 'S7comm', 'Read Var (Data blocks)', 'read', 500),
    ])
    assert found(conn, session_id) == [
        ('high', 'program-change', ENG, PLC), ('high', 'state-change', ENG, PLC),
        ('medium', 'control-command', MASTER, PLC2), ('medium', 'program-upload', ENG, PLC),
        ('low', 'clock-change', MASTER, PLC2), ('low', 'password', ENG, PLC), ('low', 'write', MASTER, PLC2)]
    [program] = [a for a in alerts.session_alerts(conn, session_id) if a['rule'] == 'program-change']
    assert (program['count'], program['operations'], program['first_frame']) == (40, ['Download Block'], 7)

def test_one_alert_per_client_and_device(conn):
    session_id = session(conn, [(MASTER, PLC, 'Modbus', 'Write Single Register', 'write', 5),
                                (MASTER, PLC, 'Modbus', 'Write Multiple Coils', 'write', 3)])
    [alert] = alerts.session_alerts(conn, session_id)
    assert alert['count'] == 8 and alert['operations'] == ['Write Multiple Coils', 'Write Single Register']

def test_a_device_changed_from_several_hosts(conn):
    session_id = session(conn, [(MASTER, PLC, 'Modbus', 'Write Single Register', 'write', 5),
                                (ENG, PLC, 'Modbus', 'Write Single Coil', 'write', 1)])
    [several] = [a for a in alerts.session_alerts(conn, session_id) if a['rule'] == 'several-controllers']
    assert (several['dst'], several['clients'], several['severity']) == (PLC, [ENG, MASTER], 'medium')
    assert {a['id'] for a in storage.host_alerts(alerts.session_alerts(conn, session_id), ENG)} >= {several['id']}

def test_fuzzing_errors_and_enumeration(conn):
    fuzz = [(ENG, PLC, 'Modbus', f'Function {code}', 'other', 1) for code in (100, 101, 102, 103, 104)]
    errors = [(ENG, PLC2, 'Modbus', 'Exception to Read Coils: Illegal Function', 'error', 25)]
    identify = [(ENG, f'10.0.1.{n}', 'S7comm', 'Read SZL 0x0011 (module identification)', 'diagnostic', 1) for n in range(5)]
    session_id = session(conn, fuzz + errors + identify)
    assert found(conn, session_id) == [('high', 'fuzzing', ENG, PLC), ('medium', 'enumeration', ENG, None),
                                       ('medium', 'errors', ENG, PLC2)]
    four = session(conn, identify[:4] + fuzz[:4] + [errors[0][:5] + (19,)])
    assert found(conn, four) == []

def test_scans_of_industrial_ports(conn):
    probes = [(ENG, f'10.0.2.{n}', port, 2) for n in range(5) for port in (502, 102)]
    polling = [(MASTER, f'10.0.3.{n}', 502, 5000) for n in range(20)]  # a busy master polling many slaves is no scan
    session_id = session(conn, flows=probes + polling)
    [scan] = alerts.session_alerts(conn, session_id)
    assert (scan['rule'], scan['src'], scan['count']) == ('ics-scan', ENG, 10)
