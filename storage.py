"""SQLite storage for capture sessions and what pyLot learned from them."""
import ipaddress
import sqlite3
from collections import defaultdict

SCHEMA = '''
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    source TEXT NOT NULL,                -- 'upload' or 'live'
    capture_file TEXT,                   -- the stored upload, if any
    status TEXT NOT NULL,                -- 'processing', 'ready', 'capturing', 'stopped' or 'failed'
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
        # Work from a previous run can't still be going
        with conn:
            conn.execute("UPDATE sessions SET status = 'stopped' WHERE status = 'capturing'")
            conn.execute("UPDATE sessions SET status = 'failed', error = 'pyLot stopped before the analysis finished' "
                         "WHERE status = 'processing'")
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

def _evidence_by_ip(conn, session_id, ip=None):
    query = ("SELECT ip, fingerprint, name, value, confidence, count, first_frame FROM evidence WHERE session_id = ?"
             + (" AND ip = ?" if ip else "") + " ORDER BY confidence, fingerprint, name, value")
    evidence = defaultdict(list)
    for row in conn.execute(query, (session_id, ip) if ip else (session_id,)):
        evidence[row['ip']].append(dict(row))
    return evidence

def _host_dict(row, evidence):
    host = dict(row)
    host.pop('session_id', None)
    host['properties'] = aggregate_properties((e['name'], e['value'], e['confidence']) for e in evidence)
    host['fingerprints'] = sorted({e['fingerprint'] for e in evidence})
    for name in ('Category', 'Role'):
        prop = host['properties'].get(name)
        host[name.lower()] = ', '.join(prop['values']) if prop else None
    return host

def all_hosts(conn, session_id):
    evidence = _evidence_by_ip(conn, session_id)
    return [_host_dict(row, evidence[row['ip']])
            for row in conn.execute("SELECT * FROM hosts WHERE session_id = ? ORDER BY ip", (session_id,))]

def network_of(host):
    """The group a host is drawn in: its /24 (IPv4) or /64 (IPv6), its router, or the special addresses."""
    if host['kind'] != 'unicast':
        return 'special', 'Multicast, broadcast and unspecified'
    if host['via_mac']:
        return f"via:{host['via_mac']}", f"Reached via router {host['via_mac']}"
    network = str(ipaddress.ip_network(f"{host['ip']}/{64 if ':' in host['ip'] else 24}", strict=False))
    return network, network

# Above this many hosts behind routers, the graph shows one node per router instead of every host
COLLAPSE_EXTERNAL_THRESHOLD = 200

def session_graph(conn, session_id, collapse_external=None):
    """
    Hosts as nodes grouped by network, and src->dst traffic as edges. Hosts reached through a router
    are merged into one node per router when there are many of them (or when collapse_external is True).
    """
    hosts = all_hosts(conn, session_id)
    external_count = sum(1 for h in hosts if h['via_mac'])
    collapse = external_count > COLLAPSE_EXTERNAL_THRESHOLD if collapse_external is None else collapse_external
    nodes, node_of, merged, groups = [], {}, {}, {}
    for host in hosts:
        if collapse and host['via_mac']:
            node_id = node_of[host['ip']] = f"via:{host['via_mac']}"
            node = merged.get(node_id)
            if node is None:
                node = merged[node_id] = {'id': node_id, 'ip': None, 'merged': 0, 'via_mac': host['via_mac'], 'kind': 'merged',
                                          'properties': {}, 'fingerprints': [], 'category': None, 'role': None, 'group': None,
                                          'packets_sent': 0, 'packets_received': 0, 'bytes_sent': 0, 'bytes_received': 0}
                nodes.append(node)
            node['merged'] += 1
            for counter in ('packets_sent', 'packets_received', 'bytes_sent', 'bytes_received'):
                node[counter] += host[counter]
            continue
        group, label = network_of(host)
        groups[group] = label
        node_of[host['ip']] = host['ip']
        nodes.append({**host, 'id': host['ip'], 'group': group})

    edges = {}
    for row in conn.execute(
            "SELECT src, dst, GROUP_CONCAT(DISTINCT protocol) AS protocols, COUNT(*) AS flows, SUM(packets) AS packets, "
            "SUM(bytes) AS bytes, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen "
            "FROM flows WHERE session_id = ? GROUP BY src, dst", (session_id,)):
        source, target = node_of[row['src']], node_of[row['dst']]
        if source == target and source.startswith('via:'):
            continue  # traffic between two hosts that were merged into the same node
        edge = edges.get((source, target))
        if edge is None:
            edges[(source, target)] = {'source': source, 'target': target, 'protocols': set(row['protocols'].split(',')),
                                       'flows': row['flows'], 'packets': row['packets'], 'bytes': row['bytes'],
                                       'first_seen': row['first_seen'], 'last_seen': row['last_seen']}
        else:
            edge['protocols'].update(row['protocols'].split(','))
            for counter in ('flows', 'packets', 'bytes'):
                edge[counter] += row[counter]
            edge['first_seen'] = min(edge['first_seen'], row['first_seen'])
            edge['last_seen'] = max(edge['last_seen'], row['last_seen'])
    for edge in edges.values():
        edge['protocols'] = sorted(edge['protocols'])
    return {'nodes': nodes, 'edges': list(edges.values()), 'collapsed': collapse, 'external_hosts': external_count,
            'groups': [{'id': group, 'label': label} for group, label in sorted(groups.items())]}

HOST_SORTS = {'ip', 'mac', 'vendor', 'via_mac', 'kind', 'category', 'role', 'packets_sent', 'packets_received',
              'bytes_sent', 'bytes_received', 'first_seen', 'last_seen'}
FLOW_SORTS = {'src', 'dst', 'transport', 'src_port', 'dst_port', 'protocol', 'packets', 'bytes', 'first_seen', 'last_seen'}

def _sort_key(column):
    def key(row):
        value = row[column]
        if column in ('ip', 'src', 'dst'):
            address = ipaddress.ip_address(value)
            return (False, (address.version, int(address)))  # numeric order, IPv4 before IPv6
        return (value is None, value if value is not None else 0)
    return key

def list_hosts(conn, session_id, query='', sort='ip', descending=False, limit=None, offset=0):
    """(page of host dicts, total matching). query matches IP, MAC, vendor, kind and any property value."""
    hosts = all_hosts(conn, session_id)
    query = query.strip().lower()
    if query:
        hosts = [h for h in hosts if query in ' '.join(
            [h['ip'], h['mac'] or '', h['vendor'] or '', h['via_mac'] or '', h['kind'], ' '.join(h['fingerprints'])]
            + [v for p in h['properties'].values() for v in p['values']]).lower()]
    sort = sort if sort in HOST_SORTS else 'ip'
    hosts.sort(key=_sort_key(sort), reverse=descending)
    end = None if limit is None else offset + limit
    return hosts[offset:end], len(hosts)

def list_flows(conn, session_id, query='', sort='packets', descending=True, limit=None, offset=0, host=None, src=None, dst=None):
    """(page of flow dicts, total matching). query matches addresses, protocol name and port numbers."""
    where, params = ['session_id = ?'], [session_id]
    if host:
        where.append('(src = ? OR dst = ?)')
        params += [host, host]
    if src:
        where.append('src = ?')
        params.append(src)
    if dst:
        where.append('dst = ?')
        params.append(dst)
    query = query.strip()
    if query:
        where.append("(src LIKE ? OR dst LIKE ? OR protocol LIKE ? OR CAST(src_port AS TEXT) = ? OR CAST(dst_port AS TEXT) = ?)")
        params += [f'%{query}%'] * 3 + [query] * 2
    clause = ' AND '.join(where)
    total = conn.execute(f"SELECT COUNT(*) FROM flows WHERE {clause}", params).fetchone()[0]
    sort = sort if sort in FLOW_SORTS else 'packets'
    page = " LIMIT ? OFFSET ?" if limit is not None else ""
    rows = conn.execute(f"SELECT src, dst, transport, src_port, dst_port, protocol, packets, bytes, first_seen, last_seen "
                        f"FROM flows WHERE {clause} ORDER BY {sort} {'DESC' if descending else 'ASC'}, src, dst{page}",
                        params + ([limit, offset] if limit is not None else []))
    return [dict(row) for row in rows], total

def host_detail(conn, session_id, ip, flow_limit=100):
    row = conn.execute("SELECT * FROM hosts WHERE session_id = ? AND ip = ?", (session_id, ip)).fetchone()
    if row is None:
        return None
    evidence = _evidence_by_ip(conn, session_id, ip)[ip]
    host = _host_dict(row, evidence)
    host['evidence'] = evidence
    host['arp'] = [dict(r) for r in conn.execute("SELECT mac, packets, first_seen, last_seen FROM arp_bindings "
                                                  "WHERE session_id = ? AND ip = ?", (session_id, ip))]
    host['flows'], host['flow_count'] = list_flows(conn, session_id, host=ip, limit=flow_limit)
    return host
