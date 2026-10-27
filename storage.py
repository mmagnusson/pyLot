"""SQLite storage for capture sessions and what pyLot learned from them."""
import sqlite3
from collections import defaultdict

SCHEMA = '''
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    source TEXT NOT NULL,                -- 'upload' or 'live'
    capture_file TEXT,                   -- the stored upload, if any
    status TEXT NOT NULL,                -- 'ready', 'capturing', 'stopped' or 'failed'
    error TEXT,
    packet_count INTEGER NOT NULL DEFAULT 0,
    first_seen REAL,
    last_seen REAL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS hosts (
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    mac TEXT,                            -- the host's own MAC, when it is on the captured segment
    vendor TEXT,
    via_mac TEXT,                        -- the router MAC it was reached through, when it isn't
    kind TEXT NOT NULL,                  -- 'unicast', 'multicast', 'broadcast' or 'unspecified'
    packets_sent INTEGER NOT NULL,
    packets_received INTEGER NOT NULL,
    bytes_sent INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (session_id, ip)
);
CREATE TABLE IF NOT EXISTS flows (
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    transport INTEGER NOT NULL,          -- IP protocol number
    src_port INTEGER NOT NULL,           -- 0 when the transport has no ports
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    packets INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (session_id, src, dst, transport, src_port, dst_port)
);
CREATE TABLE IF NOT EXISTS mac_addresses (
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    mac TEXT NOT NULL,
    vendor TEXT,
    packets INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (session_id, mac)
);
CREATE TABLE IF NOT EXISTS arp_bindings (
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    mac TEXT NOT NULL,
    packets INTEGER NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (session_id, ip, mac)
);
CREATE TABLE IF NOT EXISTS evidence (
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    name TEXT NOT NULL,                  -- property, e.g. Category, Role, ICSProtocol or an extracted field
    value TEXT NOT NULL,
    confidence INTEGER NOT NULL,         -- 1 (high) to 5 (low), as in GRASSMARLIN
    count INTEGER NOT NULL,
    first_frame INTEGER NOT NULL,
    PRIMARY KEY (session_id, ip, fingerprint, name, value)
);
'''

def _upsert(table, columns, key):
    names = ', '.join(('session_id',) + columns)
    updates = ', '.join(f'{c} = excluded.{c}' for c in columns if c not in key)
    return (f"INSERT INTO {table} ({names}) VALUES ({', '.join('?' * (len(columns) + 1))}) "
            f"ON CONFLICT (session_id, {', '.join(key)}) DO UPDATE SET {updates}")

UPSERT_HOSTS = _upsert('hosts', ('ip', 'mac', 'vendor', 'via_mac', 'kind', 'packets_sent', 'packets_received',
                                 'bytes_sent', 'bytes_received', 'first_seen', 'last_seen'), ('ip',))
UPSERT_FLOWS = _upsert('flows', ('src', 'dst', 'transport', 'src_port', 'dst_port', 'protocol', 'packets', 'bytes',
                                 'first_seen', 'last_seen'), ('src', 'dst', 'transport', 'src_port', 'dst_port'))
UPSERT_MACS = _upsert('mac_addresses', ('mac', 'vendor', 'packets', 'bytes', 'first_seen', 'last_seen'), ('mac',))
UPSERT_ARP = _upsert('arp_bindings', ('ip', 'mac', 'packets', 'first_seen', 'last_seen'), ('ip', 'mac'))
UPSERT_EVIDENCE = _upsert('evidence', ('ip', 'fingerprint', 'name', 'value', 'confidence', 'count', 'first_frame'),
                          ('ip', 'fingerprint', 'name', 'value'))

SESSION_FIELDS = {'name', 'status', 'error', 'capture_file', 'packet_count', 'first_seen', 'last_seen'}

def connect(db_path):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def init_db(db_path):
    conn = connect(db_path)
    try:
        # WAL lets the web app read while live capture writes
        conn.execute('PRAGMA journal_mode = WAL')
        conn.executescript(SCHEMA)
        # Captures from a previous run can't still be going
        with conn:
            conn.execute("UPDATE sessions SET status = 'stopped' WHERE status = 'capturing'")
    finally:
        conn.close()

def create_session(conn, name, source, status, capture_file=None):
    with conn:
        cur = conn.execute("INSERT INTO sessions (name, source, status, capture_file) VALUES (?, ?, ?, ?)",
                           (name, source, status, capture_file))
    return cur.lastrowid

def update_session(conn, session_id, **fields):
    unknown = set(fields) - SESSION_FIELDS
    if unknown:
        raise ValueError(f'unknown session fields: {sorted(unknown)}')
    with conn:
        conn.execute(f"UPDATE sessions SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = ?",
                     (*fields.values(), session_id))

def save_analysis(conn, session_id, analyzer, only_dirty=False):
    """Write analyzer's results into session_id in one transaction (only what changed, if only_dirty)."""
    with conn:
        conn.executemany(UPSERT_HOSTS, [(session_id,) + row for row in analyzer.host_rows()])
        conn.executemany(UPSERT_FLOWS, [(session_id,) + row for row in analyzer.flow_rows(only_dirty)])
        conn.executemany(UPSERT_MACS, [(session_id,) + row for row in analyzer.mac_rows(only_dirty)])
        conn.executemany(UPSERT_ARP, [(session_id,) + row for row in analyzer.arp_rows(only_dirty)])
        conn.executemany(UPSERT_EVIDENCE, [(session_id,) + row for row in analyzer.evidence_rows(only_dirty)])
        conn.execute("UPDATE sessions SET packet_count = ?, first_seen = ?, last_seen = ? WHERE id = ?",
                     (analyzer.packet_count, analyzer.first_seen, analyzer.last_seen, session_id))
    analyzer.clear_dirty()

def list_sessions(conn):
    return [dict(row) for row in conn.execute(
        "SELECT s.*, (SELECT COUNT(*) FROM hosts h WHERE h.session_id = s.id) AS host_count "
        "FROM sessions s ORDER BY s.id DESC")]

def get_session(conn, session_id):
    row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    return dict(row) if row else None

def delete_session(conn, session_id):
    with conn:
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))

def aggregate_properties(evidence):
    """
    GRASSMARLIN's rule for a host's properties: for each name, the distinct values reported at the
    best (lowest-numbered) confidence. evidence is an iterable of (name, value, confidence).
    """
    best = {}
    for name, value, confidence in evidence:
        current = best.get(name)
        if current is None or confidence < current[0]:
            best[name] = (confidence, {value})
        elif confidence == current[0]:
            current[1].add(value)
    return {name: {'confidence': confidence, 'values': sorted(values)} for name, (confidence, values) in best.items()}

def session_graph(conn, session_id):
    """Hosts as nodes (with evidence and aggregated properties) and src->dst traffic as edges."""
    evidence = defaultdict(list)
    for row in conn.execute("SELECT ip, fingerprint, name, value, confidence, count FROM evidence "
                            "WHERE session_id = ? ORDER BY confidence, fingerprint, name", (session_id,)):
        evidence[row['ip']].append(dict(row))
    nodes = []
    for row in conn.execute("SELECT * FROM hosts WHERE session_id = ? ORDER BY ip", (session_id,)):
        node = dict(row)
        del node['session_id']
        node['evidence'] = [{k: e[k] for k in ('fingerprint', 'name', 'value', 'confidence', 'count')} for e in evidence[node['ip']]]
        node['properties'] = aggregate_properties((e['name'], e['value'], e['confidence']) for e in evidence[node['ip']])
        nodes.append(node)
    edges = [dict(row) for row in conn.execute(
        "SELECT src AS source, dst AS target, GROUP_CONCAT(DISTINCT protocol) AS protocols, COUNT(*) AS flows, "
        "SUM(packets) AS packets, SUM(bytes) AS bytes, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen "
        "FROM flows WHERE session_id = ? GROUP BY src, dst", (session_id,))]
    for edge in edges:
        edge['protocols'] = sorted(edge['protocols'].split(','))
    return {'nodes': nodes, 'edges': edges}
