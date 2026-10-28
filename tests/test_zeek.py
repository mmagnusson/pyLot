import gzip
import json
import os

import pytest

import storage
from parser import zeek
from parser.pcap_parser import check_file, parse_file

CONN_LOG = os.path.join(os.path.dirname(__file__), 'data', 'conn.log')

def json_lines(tmp_path, gzipped=False):
    """The sample conn.log as Zeek's JSON output, with ISO timestamps as LogAscii::json_timestamps can write them."""
    records = []
    with open(CONN_LOG) as f:
        fields = next(line for line in f if line.startswith('#fields')).rstrip('\n').split('\t')[1:]
        f.seek(0)
        for line in f:
            if line.startswith('#'):
                continue
            record = {k: v for k, v in zip(fields, line.rstrip('\n').split('\t')) if v not in ('-', '(empty)')}
            for k in ('id.orig_p', 'id.resp_p', 'orig_pkts', 'resp_pkts', 'orig_ip_bytes', 'resp_ip_bytes'):
                if k in record:
                    record[k] = int(record[k])
            record['ts'] = '2023-11-14T22:13:20Z' if not records else float(record['ts'])
            records.append(record)
    path = tmp_path / ('conn.json.gz' if gzipped else 'conn.json')
    text = ''.join(json.dumps(r) + '\n' for r in records)
    path.write_bytes(gzip.compress(text.encode()) if gzipped else text.encode())
    return str(path)

def test_reads_tsv_conn_log():
    connections = list(zeek.read_conn_log(CONN_LOG))
    assert len(connections) == 4
    modbus, tls, icmp, syn = connections
    assert (modbus.orig_h, modbus.resp_p, modbus.transport, modbus.services) == ('10.0.0.57', 502, 6, ('modbus',))
    assert (modbus.orig_pkts, modbus.orig_bytes, modbus.duration) == (10, 520, 10.5)
    assert (modbus.orig_mac, modbus.resp_mac) == ('00:50:04:93:70:67', '00:0e:8c:11:22:33')
    assert (icmp.transport, icmp.orig_p, icmp.resp_p) == (1, 0, 0)  # Zeek's ICMP type/code aren't ports
    assert (syn.orig_pkts, syn.resp_pkts, syn.services, syn.orig_mac) == (1, 0, (), None)

@pytest.mark.parametrize('gzipped', [False, True])
def test_reads_json_conn_log(tmp_path, gzipped):
    connections = list(zeek.read_conn_log(json_lines(tmp_path, gzipped)))
    assert len(connections) == 4 and connections[0].ts == 1_700_000_000.0 and connections[0].services == ('modbus',)

def test_gzipped_tsv(tmp_path):
    path = tmp_path / 'conn.log.gz'
    with open(CONN_LOG, 'rb') as f:
        path.write_bytes(gzip.compress(f.read()))
    assert len(list(zeek.read_conn_log(str(path)))) == 4

def test_other_files_are_rejected(tmp_path):
    other = tmp_path / 'dns.log'
    other.write_text('#separator \\x09\n#path\tdns\n#fields\tts\tuid\tid.orig_h\n1700000000.0\tC1\t10.0.0.1\n')
    with pytest.raises(ValueError, match='dns.log'):
        check_file(str(other))
    notes = tmp_path / 'notes.json'
    notes.write_text('{"hello": "world"}\n')
    with pytest.raises(ValueError, match='id.orig_h'):
        check_file(str(notes))
    junk = tmp_path / 'junk.gz'
    junk.write_bytes(b'\x1f\x8bnot really gzip')
    with pytest.raises(ValueError):
        check_file(str(junk))

def test_conn_log_becomes_hosts_flows_and_classification(tmp_path):
    db = str(tmp_path / 'db.sqlite3')
    storage.init_db(db)
    conn = storage.connect(db)
    analyzer = parse_file(CONN_LOG)
    session_id = storage.create_session(conn, 'conn.log', 'upload', 'ready')
    storage.save_analysis(conn, session_id, analyzer)
    assert storage.get_session(conn, session_id)['packet_count'] == 10 + 10 + 6 + 5 + 1 + 1 + 1
    plc = storage.host_detail(conn, session_id, '10.0.0.3')
    assert plc['properties']['ICSProtocol']['values'] == ['MODBUS'] and plc['role'] == 'SLAVE'
    assert plc['mac'] == '00:0e:8c:11:22:33' and plc['packets_received'] == 10 + 1 + 1
    hmi = storage.host_detail(conn, session_id, '10.0.0.57')
    assert hmi['role'] == 'MASTER' and hmi['bytes_sent'] == 520 + 820 + 36
    flows = {(f['src'], f['dst'], f['dst_port']): f for f in storage.list_flows(conn, session_id)[0]}
    assert flows[('10.0.0.3', '10.0.0.57', 2578)]['packets'] == 10
    assert flows[('10.0.0.57', '10.0.0.3', 502)]['protocol'] == 'Modbus'
    assert flows[('10.0.0.57', '10.0.0.3', 502)]['last_seen'] == 1_700_000_010.5
    assert ('10.0.0.3', '10.0.0.9', 51000) not in flows  # no reply to the SYN
    remote = storage.host_detail(conn, session_id, '198.51.100.7')
    assert remote['mac'] == '00:80:f4:09:51:3b'  # a single remote host isn't enough to call its MAC a router's
    conn.close()
