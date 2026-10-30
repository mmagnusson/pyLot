"""SQLite storage for capture sessions and what pyLot learned from them."""
import ipaddress
import sqlite3
from collections import Counter, defaultdict

import alerts as alert_rules
from parser.mac_lookup import lookup_manufacturer
from parser.protocols import PORT_LABELS, label as protocol_label
from parser.switch_config import interface_name

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
CREATE INDEX IF NOT EXISTS flows_by_packets ON flows (session_id, packets);  -- the flow table's default order
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
CREATE TABLE IF NOT EXISTS l2_flows (           -- frames that carry neither IP nor ARP
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    src_mac TEXT NOT NULL,
    dst_mac TEXT NOT NULL,
    protocol TEXT NOT NULL,
    packets INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (session_id, src_mac, dst_mac, protocol)
);
CREATE TABLE IF NOT EXISTS mac_evidence (       -- what layer-2 protocols (LLDP, PROFINET DCP, GOOSE...) say about a MAC
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    mac TEXT NOT NULL,
    protocol TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    count INTEGER NOT NULL,
    first_frame INTEGER NOT NULL,
    PRIMARY KEY (session_id, mac, protocol, name, value)
);
CREATE TABLE IF NOT EXISTS mac_vlans (
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    mac TEXT NOT NULL,
    vlan INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    PRIMARY KEY (session_id, mac, vlan)
);
CREATE TABLE IF NOT EXISTS operations (         -- what clients asked servers to do, from decoded industrial protocols
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    protocol TEXT NOT NULL,
    operation TEXT NOT NULL,             -- e.g. Write Single Register, PLC Stop, Direct Operate
    kind TEXT NOT NULL,                  -- read, write, control, program, diagnostic, data, session, error or other
    count INTEGER NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    first_frame INTEGER NOT NULL,
    PRIMARY KEY (session_id, src, dst, protocol, operation)
);
CREATE TABLE IF NOT EXISTS switches (           -- imported switch configuration and tables, per session
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    filename TEXT,
    imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS switch_ports (
    switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    mode TEXT,
    vlan INTEGER,
    shutdown INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (switch_id, name)
);
CREATE TABLE IF NOT EXISTS switch_macs (
    switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    port TEXT NOT NULL,
    vlan INTEGER,
    mac TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS switch_neighbors (
    switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    port TEXT NOT NULL,
    device TEXT NOT NULL,
    remote_port TEXT,
    platform TEXT,
    address TEXT
);
CREATE TABLE IF NOT EXISTS networks (           -- named networks, used to group hosts in every session
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS advisories (           -- imported security advisories (CSAF), shared by every session
    id TEXT PRIMARY KEY,                 -- the advisory's tracking id, e.g. ICSA-24-004-01
    title TEXT NOT NULL,
    publisher TEXT,
    url TEXT,
    released TEXT,                       -- first and latest release, ISO 8601
    updated TEXT,
    score REAL,                          -- highest CVSS base score
    cves TEXT NOT NULL,                  -- comma-separated
    imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS advisory_products (   -- the products an advisory says are affected
    advisory_id TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,               -- product family and name, as the advisory writes them
    models TEXT,                         -- order or model numbers, space-separated
    versions TEXT,                       -- the affected versions as written ('vers:intdot/<4.5.0', '<= 5.008'), NULL for all
    cves TEXT NOT NULL,
    score REAL,
    fix TEXT                             -- the vendor's fix, when the advisory gives one
);
CREATE INDEX IF NOT EXISTS advisory_products_advisory ON advisory_products (advisory_id);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (      -- the inventory: devices tracked across sessions (see inventory.py)
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,                           -- given by a user
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS asset_observations (  -- an asset as one session saw it; kept when the session is deleted
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    session_id INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
    session_name TEXT NOT NULL,
    mac TEXT,
    ips TEXT NOT NULL,                   -- space-separated, '' for devices seen only at layer 2
    mac_vendor TEXT,
    device_vendor TEXT,
    model TEXT,
    firmware TEXT,
    serial TEXT,
    name TEXT,                           -- what the device calls itself (LLDP system name, PROFINET station name)
    category TEXT,
    role TEXT,
    properties TEXT NOT NULL,            -- JSON: the identity properties, for matching advisories
    first_seen REAL,
    last_seen REAL,
    packets INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS asset_observations_asset ON asset_observations (asset_id);
CREATE INDEX IF NOT EXISTS asset_observations_session ON asset_observations (session_id);
CREATE TABLE IF NOT EXISTS inventory_sessions (  -- sessions already added to the inventory
    session_id INTEGER PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (       -- accounts; while there are none, pyLot asks no one to sign in
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TEXT
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
UPSERT_L2_FLOWS = _upsert('l2_flows', ('src_mac', 'dst_mac', 'protocol', 'packets', 'bytes', 'first_seen', 'last_seen'),
                          ('src_mac', 'dst_mac', 'protocol'))
UPSERT_MAC_EVIDENCE = _upsert('mac_evidence', ('mac', 'protocol', 'name', 'value', 'confidence', 'count', 'first_frame'),
                              ('mac', 'protocol', 'name', 'value'))
UPSERT_VLANS = _upsert('mac_vlans', ('mac', 'vlan', 'packets'), ('mac', 'vlan'))
UPSERT_OPERATIONS = _upsert('operations', ('src', 'dst', 'protocol', 'operation', 'kind', 'count', 'first_seen', 'last_seen',
                                           'first_frame'), ('src', 'dst', 'protocol', 'operation'))

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
        conn.executemany(UPSERT_L2_FLOWS, [(session_id,) + row for row in analyzer.l2_flow_rows(only_dirty)])
        conn.executemany(UPSERT_MAC_EVIDENCE, [(session_id,) + row for row in analyzer.mac_evidence_rows(only_dirty)])
        conn.executemany(UPSERT_VLANS, [(session_id,) + row for row in analyzer.vlan_rows(only_dirty)])
        conn.executemany(UPSERT_OPERATIONS, [(session_id,) + row for row in analyzer.operation_rows(only_dirty)])
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

ANALYSIS_TABLES = ('hosts', 'flows', 'mac_addresses', 'arp_bindings', 'evidence', 'l2_flows', 'mac_evidence', 'mac_vlans',
                   'operations')

def reset_analysis(conn, session_id):
    """
    Clear what an upload session's analysis produced and mark it 'processing', so its file can be analyzed
    again; imported switch data is kept. Returns False, changing nothing, if the session isn't a finished
    upload that still has its file.
    """
    with conn:
        claimed = conn.execute("UPDATE sessions SET status = 'processing', error = NULL, packet_count = 0, first_seen = NULL, "
                               "last_seen = NULL WHERE id = ? AND source = 'upload' AND capture_file IS NOT NULL "
                               "AND status IN ('ready', 'failed')", (session_id,)).rowcount
        if claimed:
            for table in ANALYSIS_TABLES:
                conn.execute(f"DELETE FROM {table} WHERE session_id = ?", (session_id,))
            # Added to the inventory again once analyzed; its old observations stay until then, so assets keep their identity
            conn.execute("DELETE FROM inventory_sessions WHERE session_id = ?", (session_id,))
    return bool(claimed)

def reanalyzable_sessions(conn):
    return [row['id'] for row in conn.execute("SELECT id FROM sessions WHERE source = 'upload' AND capture_file IS NOT NULL "
                                              "AND status IN ('ready', 'failed') ORDER BY id")]

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

def _evidence_by_mac(conn, session_id, mac=None):
    query = ("SELECT mac, protocol, name, value, confidence, count, first_frame FROM mac_evidence WHERE session_id = ?"
             + (" AND mac = ?" if mac else "") + " ORDER BY confidence, protocol, name, value")
    evidence = defaultdict(list)
    for row in conn.execute(query, (session_id, mac) if mac else (session_id,)):
        evidence[row['mac']].append(dict(row))
    return evidence

# What a device says it is, from decoded identity replies and layer-2 announcements: the first property present wins
IDENTITY = (('model', ('Model', 'Product', 'OrderNumber', 'Platform')), ('firmware', ('Firmware', 'Software')),
            ('serial', ('Serial',)), ('device_vendor', ('Vendor',)))

def _classify(item, evidence, l2_evidence):
    """Add properties (fingerprints, decoded protocols and layer-2 announcements together), category, role and identity."""
    item['properties'] = aggregate_properties([(e['name'], e['value'], e['confidence']) for e in evidence]
                                              + [(e['name'], e['value'], e['confidence']) for e in l2_evidence])
    item['fingerprints'] = sorted({e['fingerprint'] for e in evidence})
    item['layer2'] = sorted({e['protocol'] for e in l2_evidence})
    for name in ('Category', 'Role'):
        prop = item['properties'].get(name)
        item[name.lower()] = ', '.join(prop['values']) if prop else None
    for key, names in IDENTITY:
        prop = next((item['properties'][name] for name in names if name in item['properties']), None)
        item[key] = ', '.join(prop['values']) if prop else None
    return item

def _host_dict(row, evidence, l2_evidence=()):
    host = dict(row)
    host.pop('session_id', None)
    return _classify(host, evidence, l2_evidence)

def all_hosts(conn, session_id):
    evidence = _evidence_by_ip(conn, session_id)
    l2_evidence = _evidence_by_mac(conn, session_id)
    return [_host_dict(row, evidence[row['ip']], l2_evidence[row['mac']] if row['mac'] else ())
            for row in conn.execute("SELECT * FROM hosts WHERE session_id = ? ORDER BY ip", (session_id,))]

# --- named networks and settings

SETTINGS = {'auto_prefix_v4': 24, 'auto_prefix_v6': 64}  # automatic grouping of hosts outside named networks; 0 is off
MAX_NETWORK_NAME = 100

def get_settings(conn):
    stored = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings")}
    return {key: int(stored.get(key, default)) for key, default in SETTINGS.items()}

def update_settings(conn, **values):
    """Raises ValueError for unknown settings or prefixes out of range."""
    for key, value in values.items():
        if key not in SETTINGS:
            raise ValueError(f'unknown setting {key}')
        limit = 32 if key.endswith('v4') else 128
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= limit:
            raise ValueError(f'{key} must be a prefix length from 0 to {limit}')
    with conn:
        conn.executemany("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                         [(key, str(value)) for key, value in values.items()])
    return get_settings(conn)

def _network_sort_key(network):
    parsed = ipaddress.ip_network(network['cidr'])
    return (parsed.version, int(parsed.network_address), parsed.prefixlen)

def list_networks(conn):
    return sorted((dict(row) for row in conn.execute("SELECT id, cidr, name, created_at FROM networks")), key=_network_sort_key)

def _clean_network(cidr, name):
    try:
        network = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError:
        raise ValueError(f'{cidr!r} is not a network address such as 10.1.2.0/24')
    name = str(name or '').strip() or str(network)
    if len(name) > MAX_NETWORK_NAME:
        raise ValueError(f'Network names can be at most {MAX_NETWORK_NAME} characters')
    return str(network), name

def add_network(conn, cidr, name=None):
    """Add a named network. Raises ValueError if cidr isn't a network or is already defined."""
    cidr, name = _clean_network(cidr, name)
    try:
        with conn:
            cur = conn.execute("INSERT INTO networks (cidr, name) VALUES (?, ?)", (cidr, name))
    except sqlite3.IntegrityError:
        raise ValueError(f'{cidr} is already defined')
    return get_network(conn, cur.lastrowid)

def get_network(conn, network_id):
    row = conn.execute("SELECT id, cidr, name, created_at FROM networks WHERE id = ?", (network_id,)).fetchone()
    return dict(row) if row else None

def update_network(conn, network_id, cidr=None, name=None):
    current = get_network(conn, network_id)
    if current is None:
        return None
    cidr, name = _clean_network(cidr if cidr is not None else current['cidr'], name if name is not None else current['name'])
    try:
        with conn:
            conn.execute("UPDATE networks SET cidr = ?, name = ? WHERE id = ?", (cidr, name, network_id))
    except sqlite3.IntegrityError:
        raise ValueError(f'{cidr} is already defined')
    return get_network(conn, network_id)

def delete_network(conn, network_id):
    with conn:
        return conn.execute("DELETE FROM networks WHERE id = ?", (network_id,)).rowcount > 0

class NetworkMap:
    """Assigns hosts to groups: the most specific named network, else their router, else an automatic prefix."""

    def __init__(self, networks=(), auto_prefix_v4=24, auto_prefix_v6=64):
        self.networks = sorted(((ipaddress.ip_network(n['cidr']), n) for n in networks), key=lambda item: -item[0].prefixlen)
        self.prefixes = {4: auto_prefix_v4, 6: auto_prefix_v6}

    @classmethod
    def load(cls, conn):
        settings = get_settings(conn)
        return cls(list_networks(conn), settings['auto_prefix_v4'], settings['auto_prefix_v6'])

    def named(self, ip):
        address = ipaddress.ip_address(ip)
        for network, row in self.networks:
            if network.version == address.version and address in network:
                return row
        return None

    def group_of(self, host):
        """(group id, label, named network or None)"""
        if host['kind'] != 'unicast':
            return 'special', 'Multicast, broadcast and unspecified', None
        named = self.named(host['ip'])
        if named:
            label = named['cidr'] if named['name'] == named['cidr'] else f"{named['name']} ({named['cidr']})"
            return f"net:{named['cidr']}", label, named
        if host['via_mac']:
            return f"via:{host['via_mac']}", f"Reached via router {host['via_mac']}", None
        address = ipaddress.ip_address(host['ip'])
        prefix = self.prefixes[address.version]
        if not prefix:
            return 'unassigned', 'Not in a named network', None
        network = str(ipaddress.ip_network(f"{host['ip']}/{prefix}", strict=False))
        return network, network, None

def network_of(host, network_map=None):
    """The group a host is drawn in, as (id, label)."""
    return (network_map or NetworkMap()).group_of(host)[:2]

# Above this many hosts behind routers, the graph shows one node per router instead of every host
COLLAPSE_EXTERNAL_THRESHOLD = 200

def session_graph(conn, session_id, collapse_external=None, baseline_id=None):
    """
    Hosts as nodes grouped by network, and src->dst traffic as edges. Hosts reached through a router
    are merged into one node per router when there are many of them (or when collapse_external is True),
    unless they are in a named network. With baseline_id, nodes and edges are marked with what is new
    or changed since that session.
    """
    diff = (compare_sessions(conn, session_id, baseline_id, limit=None, conversation_limit=0, include_alerts=False)
            if baseline_id else None)
    new_ips = {h['ip'] for h in diff['new_hosts']['items']} if diff else set()
    changed = {c['ip']: c['changes'] for c in diff['changed_hosts']['items']} if diff else {}
    # Directions that carried a new conversation; an edge is new only if its own flows were
    new_pairs = _new_flow_directions(conn, session_id) if diff and diff['new_conversations']['total'] else set()
    hosts = all_hosts(conn, session_id)
    network_map = NetworkMap.load(conn)
    placed = [(host, network_map.group_of(host)) for host in hosts]
    external_count = sum(1 for host, (_, _, named) in placed if host['via_mac'] and not named)
    collapse = external_count > COLLAPSE_EXTERNAL_THRESHOLD if collapse_external is None else collapse_external
    nodes, node_of, merged, groups = [], {}, {}, {}
    for host, (group, label, named) in placed:
        if collapse and host['via_mac'] and not named:
            node_id = node_of[host['ip']] = f"via:{host['via_mac']}"
            node = merged.get(node_id)
            if node is None:
                node = merged[node_id] = {'id': node_id, 'ip': None, 'merged': 0, 'via_mac': host['via_mac'], 'kind': 'merged',
                                          'properties': {}, 'fingerprints': [], 'layer2': [], 'category': None, 'role': None,
                                          'group': None, 'packets_sent': 0, 'packets_received': 0, 'bytes_sent': 0,
                                          'bytes_received': 0, 'new_hosts': 0, 'change': None}
                nodes.append(node)
            node['merged'] += 1
            if host['ip'] in new_ips:
                node['new_hosts'] += 1
                node['change'] = 'new'
            elif host['ip'] in changed and node['change'] is None:
                node['change'] = 'changed'
            for counter in ('packets_sent', 'packets_received', 'bytes_sent', 'bytes_received'):
                node[counter] += host[counter]
            continue
        if group not in groups:
            groups[group] = {'id': group, 'label': label, 'network_id': named['id'] if named else None,
                             'cidr': named['cidr'] if named else (group if '/' in group else None), 'hosts': 0}
        groups[group]['hosts'] += 1
        node_of[host['ip']] = host['ip']
        change = 'new' if host['ip'] in new_ips else ('changed' if host['ip'] in changed else None)
        nodes.append({**host, 'id': host['ip'], 'group': group, 'change': change, 'changes': changed.get(host['ip'], [])})

    edges = {}
    for row in conn.execute(
            "SELECT src, dst, GROUP_CONCAT(DISTINCT protocol) AS protocols, COUNT(*) AS flows, SUM(packets) AS packets, "
            "SUM(bytes) AS bytes, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen "
            "FROM flows WHERE session_id = ? GROUP BY src, dst", (session_id,)):
        source, target = node_of[row['src']], node_of[row['dst']]
        if source == target and source.startswith('via:'):
            continue  # traffic between two hosts that were merged into the same node
        is_new = (row['src'], row['dst']) in new_pairs
        edge = edges.get((source, target))
        if edge is None:
            edges[(source, target)] = {'source': source, 'target': target, 'protocols': set(row['protocols'].split(',')),
                                       'flows': row['flows'], 'packets': row['packets'], 'bytes': row['bytes'],
                                       'first_seen': row['first_seen'], 'last_seen': row['last_seen'], 'new': is_new}
        else:
            edge['new'] = edge['new'] or is_new
            edge['protocols'].update(row['protocols'].split(','))
            for counter in ('flows', 'packets', 'bytes'):
                edge[counter] += row[counter]
            edge['first_seen'] = min(edge['first_seen'], row['first_seen'])
            edge['last_seen'] = max(edge['last_seen'], row['last_seen'])
    for row in conn.execute("SELECT src, dst, GROUP_CONCAT(DISTINCT kind) AS kinds FROM operations WHERE session_id = ? "
                            "GROUP BY src, dst", (session_id,)):
        edge = edges.get((node_of.get(row['src']), node_of.get(row['dst'])))
        if edge is not None:
            edge.setdefault('operations', set()).update(row['kinds'].split(','))
    for edge in edges.values():
        edge['protocols'] = sorted(edge['protocols'])
        edge['operations'] = sorted(edge.get('operations', ()))  # kinds of industrial operations sent along it
    graph = {'nodes': nodes, 'edges': list(edges.values()), 'collapsed': collapse, 'external_hosts': external_count,
             'groups': [groups[group] for group in sorted(groups)]}
    if diff:
        graph['baseline'] = {'id': baseline_id, 'new_hosts': len(new_ips), 'changed_hosts': len(changed),
                             'new_conversations': diff['new_conversations']['total'], 'missing_hosts': diff['missing_hosts']['total']}
    return graph

HOST_SORTS = {'ip', 'mac', 'vendor', 'via_mac', 'kind', 'category', 'role', 'model', 'firmware', 'packets_sent',
              'packets_received', 'bytes_sent', 'bytes_received', 'first_seen', 'last_seen'}
FLOW_SORTS = {'src', 'dst', 'transport', 'src_port', 'dst_port', 'protocol', 'packets', 'bytes', 'first_seen', 'last_seen'}

def _ip_key(ip):
    address = ipaddress.ip_address(ip)
    return (address.version, int(address))  # numeric order, IPv4 before IPv6

def _sort_key(column):
    def key(row):
        value = row[column]
        if column in ('ip', 'src', 'dst'):
            return (False, _ip_key(value))
        return (value is None, value if value is not None else 0)
    return key

def list_hosts(conn, session_id, query='', sort='ip', descending=False, limit=None, offset=0):
    """(page of host dicts, total matching). query matches IP, MAC, vendor, kind and any property value."""
    hosts = all_hosts(conn, session_id)
    query = query.strip().lower()
    if query:
        hosts = [h for h in hosts if query in ' '.join(
            [h['ip'], h['mac'] or '', h['vendor'] or '', h['via_mac'] or '', h['kind'], ' '.join(h['fingerprints']),
             ' '.join(h['layer2'])]
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
    l2_evidence = _evidence_by_mac(conn, session_id, row['mac'])[row['mac']] if row['mac'] else []
    host = _host_dict(row, evidence, l2_evidence)
    host['evidence'] = evidence
    host['layer2_evidence'] = l2_evidence
    host['network'] = NetworkMap.load(conn).group_of(host)[1]
    host['arp'] = [dict(r) for r in conn.execute("SELECT mac, packets, first_seen, last_seen FROM arp_bindings "
                                                  "WHERE session_id = ? AND ip = ?", (session_id, ip))]
    host['flows'], host['flow_count'] = list_flows(conn, session_id, host=ip, limit=flow_limit)
    host['operations'], host['operation_count'] = list_operations(conn, session_id, host=ip, sort='kind', limit=flow_limit)
    host['alerts'] = host_alerts(alert_rules.session_alerts(conn, session_id), ip)
    return host

def host_alerts(alerts, ip):
    """The alerts a host is involved in, as client, server or one of several controlling clients."""
    return [a for a in alerts if ip in (a['src'], a['dst']) or ip in a.get('clients', ())]

OPERATION_SORTS = {'src', 'dst', 'protocol', 'operation', 'kind', 'count', 'first_seen', 'last_seen'}
# Most consequential first when sorting by kind
KIND_ORDER = "CASE kind WHEN 'program' THEN 0 WHEN 'control' THEN 1 WHEN 'write' THEN 2 WHEN 'error' THEN 3 ELSE 4 END"

def list_operations(conn, session_id, query='', sort='kind', descending=False, limit=None, offset=0, host=None, kind=None):
    """(page of operation dicts, total matching). query matches addresses, protocol and operation name."""
    where, params = ['session_id = ?'], [session_id]
    if host:
        where.append('(src = ? OR dst = ?)')
        params += [host, host]
    if kind:
        where.append('kind = ?')
        params.append(kind)
    query = query.strip()
    if query:
        where.append('(src LIKE ? OR dst LIKE ? OR protocol LIKE ? OR operation LIKE ?)')
        params += [f'%{query}%'] * 4
    clause = ' AND '.join(where)
    total = conn.execute(f"SELECT COUNT(*) FROM operations WHERE {clause}", params).fetchone()[0]
    sort = sort if sort in OPERATION_SORTS else 'kind'
    order = KIND_ORDER if sort == 'kind' else sort
    page = " LIMIT ? OFFSET ?" if limit is not None else ""
    rows = conn.execute(f"SELECT src, dst, protocol, operation, kind, count, first_seen, last_seen, first_frame FROM operations "
                        f"WHERE {clause} ORDER BY {order} {'DESC' if descending else 'ASC'}, protocol, operation, src, dst{page}",
                        params + ([limit, offset] if limit is not None else []))
    return [dict(row) for row in rows], total

def operation_kinds(conn, session_id):
    """Number of distinct operations of each kind in a session."""
    return {row['kind']: row['n'] for row in conn.execute(
        "SELECT kind, COUNT(*) AS n FROM operations WHERE session_id = ? GROUP BY kind", (session_id,))}

def list_l2_flows(conn, session_id, mac=None, limit=None):
    """Conversations that carried neither IP nor ARP (GOOSE, PROFINET, LLDP...), busiest first."""
    where, params = "session_id = ?", [session_id]
    if mac:
        where += " AND (src_mac = ? OR dst_mac = ?)"
        params += [mac, mac]
    page = " LIMIT ?" if limit else ""
    return [dict(row) for row in conn.execute(
        f"SELECT src_mac, dst_mac, protocol, packets, bytes, first_seen, last_seen FROM l2_flows WHERE {where} "
        f"ORDER BY packets DESC, src_mac, dst_mac{page}", params + ([limit] if limit else []))]

# --- imported switches

def save_switch(conn, session_id, data, filename=None, name=None):
    """Store a parsed switch_config.SwitchData for a session and return the switch's id."""
    with conn:
        switch_id = conn.execute("INSERT INTO switches (session_id, name, filename) VALUES (?, ?, ?)",
                                 (session_id, (name or data.hostname or filename or 'switch')[:MAX_NETWORK_NAME], filename)).lastrowid
        conn.executemany("INSERT OR REPLACE INTO switch_ports (switch_id, name, description, mode, vlan, shutdown) VALUES (?, ?, ?, ?, ?, ?)",
                         [(switch_id, p.name, p.description, p.mode, p.vlan, int(p.shutdown)) for p in data.ports.values()])
        conn.executemany("INSERT INTO switch_macs (switch_id, port, vlan, mac) VALUES (?, ?, ?, ?)",
                         [(switch_id, port, vlan, mac) for port, vlan, mac in data.macs])
        conn.executemany("INSERT INTO switch_neighbors (switch_id, port, device, remote_port, platform, address) VALUES (?, ?, ?, ?, ?, ?)",
                         [(switch_id, n.port, n.device, n.remote_port, n.platform, n.address) for n in data.neighbors])
    return switch_id

def list_switches(conn, session_id):
    return [dict(row) for row in conn.execute(
        "SELECT s.id, s.name, s.filename, s.imported_at, "
        "(SELECT COUNT(*) FROM switch_ports p WHERE p.switch_id = s.id) AS ports, "
        "(SELECT COUNT(*) FROM switch_macs m WHERE m.switch_id = s.id) AS macs, "
        "(SELECT COUNT(*) FROM switch_neighbors n WHERE n.switch_id = s.id) AS neighbors "
        "FROM switches s WHERE s.session_id = ? ORDER BY s.name, s.id", (session_id,))]

def delete_switch(conn, session_id, switch_id):
    with conn:
        return conn.execute("DELETE FROM switches WHERE id = ? AND session_id = ?", (switch_id, session_id)).rowcount > 0

def _switch_tables(conn, session_id):
    switches = {row['id']: {**row, 'ports': {}, 'macs': [], 'neighbors': []} for row in list_switches(conn, session_id)}
    ids = tuple(switches)
    if not ids:
        return switches
    marks = ', '.join('?' * len(ids))
    for row in conn.execute(f"SELECT * FROM switch_ports WHERE switch_id IN ({marks})", ids):
        switches[row['switch_id']]['ports'][row['name']] = dict(row)
    for row in conn.execute(f"SELECT * FROM switch_macs WHERE switch_id IN ({marks})", ids):
        switches[row['switch_id']]['macs'].append(dict(row))
    for row in conn.execute(f"SELECT * FROM switch_neighbors WHERE switch_id IN ({marks})", ids):
        switches[row['switch_id']]['neighbors'].append(dict(row))
    return switches

def _place_macs(switches):
    """
    mac -> (switch id, port): where each MAC is plugged in. A MAC appears on every switch between it and
    the capture, so prefer access ports over uplinks (trunks, port channels, ports with a CDP/LLDP
    neighbor), then the port that has learned the fewest MACs.
    """
    candidates = defaultdict(list)
    for switch_id, switch in switches.items():
        port_macs = Counter(m['port'] for m in switch['macs'])
        uplinks = {n['port'] for n in switch['neighbors']}
        uplinks |= {name for name, port in switch['ports'].items() if port['mode'] == 'trunk'}
        for entry in switch['macs']:
            port = entry['port']
            uplink = port in uplinks or port.startswith('Po')
            candidates[entry['mac']].append((uplink, port_macs[port], switch_id, port))
    return {mac: min(options)[2:] for mac, options in candidates.items()}

# --- layer-2 devices and the physical view

def _short_name(name):
    return (name or '').split('.')[0].lower()

def all_devices(conn, session_id):
    """
    One entry per MAC address seen sending in the capture or listed in an imported MAC table, with its IPs,
    VLANs, classification (from its IPs' fingerprints and its own layer-2 announcements) and switch port.
    """
    hosts = all_hosts(conn, session_id)
    l2_evidence = _evidence_by_mac(conn, session_id)
    ip_evidence = _evidence_by_ip(conn, session_id)
    ips, routed = defaultdict(set), Counter()
    for host in hosts:
        if host['mac']:
            ips[host['mac']].add(host['ip'])
        if host['via_mac']:
            routed[host['via_mac']] += 1
    for row in conn.execute("SELECT ip, mac FROM arp_bindings WHERE session_id = ?", (session_id,)):
        ips[row['mac']].add(row['ip'])
    vlans = defaultdict(set)
    for row in conn.execute("SELECT mac, vlan FROM mac_vlans WHERE session_id = ?", (session_id,)):
        vlans[row['mac']].add(row['vlan'])
    switches = _switch_tables(conn, session_id)
    placement = _place_macs(switches)
    devices = {}
    for row in conn.execute("SELECT mac, vendor, packets, bytes, first_seen, last_seen FROM mac_addresses WHERE session_id = ?", (session_id,)):
        devices[row['mac']] = {**dict(row), 'seen': True}
    for switch in switches.values():
        for entry in switch['macs']:
            vlans[entry['mac']].update([entry['vlan']] if entry['vlan'] is not None else [])
            devices.setdefault(entry['mac'], {'mac': entry['mac'], 'vendor': lookup_manufacturer(entry['mac']), 'packets': 0,
                                              'bytes': 0, 'first_seen': None, 'last_seen': None, 'seen': False})
    result = []
    for mac, device in devices.items():
        device_ips = sorted(ips.get(mac, ()), key=_ip_key)
        evidence = [e for ip in device_ips for e in ip_evidence.get(ip, ())]
        _classify(device, evidence, l2_evidence.get(mac, ()))
        if routed[mac] and device['category'] is None:
            device['category'] = 'NETWORK_DEVICE'
        name = device['properties'].get('SystemName') or device['properties'].get('NameOfStation')
        location = placement.get(mac)
        device.update(ips=device_ips, vlans=sorted(vlans.get(mac, ())), routes_for=routed[mac],
                      name=name['values'][0] if name else None,
                      switch=switches[location[0]]['name'] if location else None, port=location[1] if location else None,
                      switch_id=location[0] if location else None)
        result.append(device)
    result.sort(key=lambda d: d['mac'])
    return result

DEVICE_SORTS = {'mac', 'vendor', 'name', 'category', 'role', 'model', 'firmware', 'switch', 'port', 'packets', 'bytes',
                'first_seen', 'last_seen'}

def list_devices(conn, session_id, query='', sort='mac', descending=False, limit=None, offset=0):
    devices = all_devices(conn, session_id)
    query = query.strip().lower()
    if query:
        devices = [d for d in devices if query in ' '.join(
            [d['mac'], d['vendor'] or '', d['name'] or '', d['switch'] or '', d['port'] or '', ' '.join(d['ips']),
             ' '.join(d['layer2']), ' '.join(d['fingerprints']), ' '.join(f'vlan {v}' for v in d['vlans'])]
            + [v for p in d['properties'].values() for v in p['values']]).lower()]
    sort = sort if sort in DEVICE_SORTS else 'mac'
    devices.sort(key=_sort_key(sort), reverse=descending)
    end = None if limit is None else offset + limit
    return devices[offset:end], len(devices)

def device_detail(conn, session_id, mac):
    device = next((d for d in all_devices(conn, session_id) if d['mac'] == mac), None)
    if device is None:
        return None
    device['layer2_evidence'] = _evidence_by_mac(conn, session_id, mac)[mac]
    device['l2_flows'] = list_l2_flows(conn, session_id, mac=mac, limit=100)
    device['switch_entries'] = [dict(row) for row in conn.execute(
        "SELECT s.name AS switch, m.port, m.vlan FROM switch_macs m JOIN switches s ON s.id = m.switch_id "
        "WHERE s.session_id = ? AND m.mac = ? ORDER BY s.name, m.port", (session_id, mac))]
    return device

def physical_graph(conn, session_id):
    """
    Switches with their ports, the devices plugged into each port, links between switches, and where the
    capture itself was taken from (the switch and port that LLDP or CDP frames in the capture announced).
    Devices whose port isn't known are grouped by VLAN.
    """
    devices = all_devices(conn, session_id)
    switches = _switch_tables(conn, session_id)
    by_name = {_short_name(s['name']): s for s in switches.values()}
    nodes, edges, port_nodes = [], [], set()

    def port_node(switch_id, port):
        node_id = f'port:{switch_id}:{port}'
        if node_id not in port_nodes:
            port_nodes.add(node_id)
            info = switches[switch_id]['ports'].get(port, {})
            nodes.append({'id': node_id, 'type': 'port', 'label': port, 'parent': f'switch:{switch_id}', 'switch_id': switch_id,
                          'switch': switches[switch_id]['name'], 'port': port, 'description': info.get('description'),
                          'mode': info.get('mode'), 'vlan': info.get('vlan'), 'shutdown': bool(info.get('shutdown'))})
        return node_id

    for switch_id, switch in switches.items():
        nodes.append({'id': f'switch:{switch_id}', 'type': 'switch', 'label': switch['name'], 'switch_id': switch_id,
                      'ports': len(switch['ports']), 'macs': len(switch['macs'])})

    # Network gear that announced itself over LLDP or CDP is drawn as the imported switch of the same name, or
    # else as a switch of its own, with the ports it announced. Switches often announce from one MAC per port.
    announced, announced_only = {}, defaultdict(list)
    for device in devices:
        name = device['name'] if {'LLDP', 'CDP'} & set(device['layer2']) else None
        if name and _short_name(name) in by_name:
            announced[device['mac']] = by_name[_short_name(name)]['id']
        elif name:
            announced_only[_short_name(name)].append(device)

    remote = {}  # neighbor switches that weren't imported
    for switch_id, switch in switches.items():
        for neighbor in switch['neighbors']:
            other = by_name.get(_short_name(neighbor['device']))
            source = port_node(switch_id, neighbor['port'])
            if other is not None:
                if other['id'] == switch_id or other['id'] < switch_id and any(
                        _short_name(n['device']) == _short_name(switch['name']) for n in other['neighbors']):
                    continue  # the same link, already drawn from the other switch's side
                target = port_node(other['id'], neighbor['remote_port']) if neighbor['remote_port'] else f"switch:{other['id']}"
            else:
                target = remote.get(_short_name(neighbor['device']))
                if target is None:
                    target = remote[_short_name(neighbor['device'])] = f"neighbor:{_short_name(neighbor['device'])}"
                    nodes.append({'id': target, 'type': 'neighbor', 'label': neighbor['device'], 'platform': neighbor['platform'],
                                  'address': neighbor['address']})
            edges.append({'source': source, 'target': target, 'type': 'link',
                          'label': neighbor['remote_port'] if other is None and neighbor['remote_port'] else ''})

    capture_links = []
    for short, members in sorted(announced_only.items()):
        switch_node = f'announced:{short}'
        values = lambda name: sorted({v for d in members for v in d['properties'].get(name, {}).get('values', [])})
        nodes.append({'id': switch_node, 'type': 'announced', 'label': members[0]['name'], 'macs': [d['mac'] for d in members],
                      'vendor': members[0]['vendor'], 'platform': ', '.join(values('Platform')) or None,
                      'description': ', '.join(values('SystemDescription')) or None,
                      'addresses': values('ManagementAddress'), 'capabilities': ', '.join(values('Capabilities')) or None})
        for device in members:
            descriptions = device['properties'].get('PortDescription', {}).get('values', [])
            for port in device['properties'].get('PortID', {}).get('values', []):
                port_id = f'aport:{short}:{port}'
                if not any(n['id'] == port_id for n in nodes):
                    nodes.append({'id': port_id, 'type': 'port', 'label': port, 'parent': switch_node, 'switch': members[0]['name'],
                                  'port': port, 'description': ', '.join(descriptions) or None, 'mode': None, 'vlan': None,
                                  'shutdown': False, 'announced': True})
                    capture_links.append((port_id, None))
    absorbed = set(announced) | {d['mac'] for members in announced_only.values() for d in members}

    vlan_groups = set()
    for device in devices:
        if device['mac'] in absorbed:
            continue
        node = {**device, 'id': f"mac:{device['mac']}", 'type': 'device', 'label': _device_label(device)}
        if device['switch_id'] is not None:
            edges.append({'source': node['id'], 'target': port_node(device['switch_id'], device['port']), 'type': 'attached', 'label': ''})
        else:
            group = f"vlan:{device['vlans'][0]}" if len(device['vlans']) == 1 else 'vlan:unknown'
            vlan_groups.add(group)
            node['parent'] = group
        nodes.append(node)
    for group in sorted(vlan_groups):
        label = 'Port unknown' if group == 'vlan:unknown' else f"VLAN {group[5:]}, port unknown"
        nodes.append({'id': group, 'type': 'group', 'label': label})

    # The capture point: LLDP and CDP are link-local, so their senders are on the other end of the capture's cable
    for mac, switch_id in announced.items():
        device = next(d for d in devices if d['mac'] == mac)
        ports = device['properties'].get('PortID', {}).get('values', [])
        capture_links += [(port_node(switch_id, interface_name(port) or port), None) for port in ports] or [(f'switch:{switch_id}', None)]
    if capture_links:
        nodes.append({'id': 'capture', 'type': 'capture', 'label': 'Capture point'})
        for target, port in capture_links:
            edges.append({'source': 'capture', 'target': target, 'type': 'capture', 'label': port or ''})
    return {'nodes': nodes, 'edges': edges, 'switches': list_switches(conn, session_id)}

def _device_label(device):
    first = device['name'] or (device['ips'][0] if device['ips'] else device['mac'])
    second = device['vendor'] if device['vendor'] and device['vendor'] != 'Unknown Vendor' else device['mac']
    return f'{first}\n{second}' if first != second else first

# --- comparing a session with a baseline

# A conversation is (client, server, transport, service port), the same whichever direction a flow went. The
# service port is a well-known one if either end uses one (the destination's first), otherwise the lower port.
# Worked out in SQL, since a scanned network can have millions of flows.
_KNOWN_PORTS = ', '.join(str(transport * 65536 + port) for transport, port in sorted(PORT_LABELS))
_CLIENT_TO_SERVER = (f"(transport * 65536 + dst_port IN ({_KNOWN_PORTS}) OR "
                     f"(transport * 65536 + src_port NOT IN ({_KNOWN_PORTS}) AND dst_port <= src_port))")
_CONVERSATION = ("CASE WHEN forward THEN src ELSE dst END AS client, CASE WHEN forward THEN dst ELSE src END AS server, "
                 "transport, CASE WHEN forward THEN dst_port ELSE src_port END AS port")

def _flows_with_direction(columns):
    """A subquery of one session's flows with a 'forward' column: whether the flow went client to server."""
    return f"(SELECT {columns}, transport, src_port, dst_port, {_CLIENT_TO_SERVER} AS forward FROM flows WHERE session_id = ?)"
_SAME_CONVERSATION = "y.client = x.client AND y.server = x.server AND y.transport = x.transport AND y.port = x.port"

def _conversation_diff(conn, session_id, baseline_id, limit):
    """
    New and missing conversations, busiest first, each as (up to limit items, total). Leaves the temporary
    tables conversations_now and conversations_before on conn for _new_flow_directions.
    """
    for table, sid in (('conversations_now', session_id), ('conversations_before', baseline_id)):
        conn.execute(f"DROP TABLE IF EXISTS temp.{table}")
        conn.execute(f"CREATE TEMP TABLE {table} AS SELECT client, server, transport, port, SUM(packets) AS packets, "
                     f"SUM(bytes) AS bytes, MIN(first_seen) AS first_seen FROM (SELECT {_CONVERSATION}, packets, bytes, first_seen "
                     f"FROM {_flows_with_direction('src, dst, packets, bytes, first_seen')}) GROUP BY client, server, transport, port",
                     (sid,))
        conn.execute(f"CREATE UNIQUE INDEX temp.{table}_key ON {table} (client, server, transport, port)")

    def only_in(table, other):
        where = f"FROM {table} x WHERE NOT EXISTS (SELECT 1 FROM {other} y WHERE {_SAME_CONVERSATION})"
        total = conn.execute(f"SELECT COUNT(*) {where}").fetchone()[0]
        rows = conn.execute(f"SELECT client, server, transport, port, packets, bytes, first_seen {where} "
                            f"ORDER BY packets DESC, client, server" + (" LIMIT ?" if limit is not None else ""),
                            (limit,) if limit is not None else ())
        return [{**dict(row), 'protocol': protocol_label(row['transport'], 0, row['port'])} for row in rows], total

    return only_in('conversations_now', 'conversations_before'), only_in('conversations_before', 'conversations_now')

def _new_flow_directions(conn, session_id):
    """(src, dst) pairs whose flows include a conversation the baseline didn't have; after _conversation_diff."""
    return {(row['src'], row['dst']) for row in conn.execute(
        f"SELECT DISTINCT src, dst FROM (SELECT src, dst, {_CONVERSATION} FROM {_flows_with_direction('src, dst')}) x "
        f"WHERE NOT EXISTS (SELECT 1 FROM conversations_before y WHERE {_SAME_CONVERSATION})", (session_id,))}

COMPARED_PROPERTIES = ('Category', 'Role', 'ICSProtocol')
# What a device says it is: only a change when both sessions heard it, since not every capture asks
COMPARED_IDENTITY = ('Vendor', 'Model', 'Product', 'OrderNumber', 'Firmware', 'Serial')

def compare_sessions(conn, session_id, baseline_id, limit=500, conversation_limit=None, include_alerts=True):
    """
    What changed in session_id since baseline_id: new and missing hosts, MAC addresses and conversations,
    hosts whose MAC, classification or reported identity (model, firmware...) changed, new layer-2
    protocols, industrial operations clients hadn't sent before, and alerts the baseline didn't have
    (unless include_alerts is False). Lists are cut to limit items
    (conversations to conversation_limit, if given), with totals; None means no limit.
    """
    def summary(host):
        return {k: host.get(k) for k in ('ip', 'mac', 'vendor', 'via_mac', 'category', 'role', 'first_seen')}

    current = {h['ip']: h for h in all_hosts(conn, session_id) if h['kind'] == 'unicast'}
    baseline = {h['ip']: h for h in all_hosts(conn, baseline_id) if h['kind'] == 'unicast'}
    ordered = lambda ips: sorted(ips, key=_ip_key)
    new_hosts = [summary(current[ip]) for ip in ordered(current.keys() - baseline.keys())]
    missing_hosts = [summary(baseline[ip]) for ip in ordered(baseline.keys() - current.keys())]

    changed = []
    for ip in ordered(current.keys() & baseline.keys()):
        now, before = current[ip], baseline[ip]
        changes = []
        if now['mac'] and before['mac'] and now['mac'] != before['mac']:
            changes.append({'what': 'MAC', 'before': f"{before['mac']} ({before['vendor']})", 'now': f"{now['mac']} ({now['vendor']})"})
        if bool(now['via_mac']) != bool(before['via_mac']):
            changes.append({'what': 'Location', 'before': 'behind a router' if before['via_mac'] else 'local',
                            'now': 'behind a router' if now['via_mac'] else 'local'})
        for name in COMPARED_PROPERTIES:
            was = ', '.join(before['properties'].get(name, {}).get('values', [])) or None
            is_ = ', '.join(now['properties'].get(name, {}).get('values', [])) or None
            if was != is_:
                changes.append({'what': name, 'before': was, 'now': is_})
        for name in COMPARED_IDENTITY:
            was = ', '.join(before['properties'].get(name, {}).get('values', [])) or None
            is_ = ', '.join(now['properties'].get(name, {}).get('values', [])) or None
            if was and is_ and was != is_:
                changes.append({'what': name, 'before': was, 'now': is_})
        if changes:
            changed.append({'ip': ip, 'changes': changes})

    new_conversations, missing_conversations = _conversation_diff(
        conn, session_id, baseline_id, limit if conversation_limit is None else conversation_limit)

    macs = lambda sid: {row['mac']: dict(row) for row in conn.execute(
        "SELECT mac, vendor, packets, first_seen FROM mac_addresses WHERE session_id = ?", (sid,))}
    macs_now, macs_before = macs(session_id), macs(baseline_id)
    l2 = lambda sid: {(row['src_mac'], row['protocol']): dict(row) for row in conn.execute(
        "SELECT src_mac, protocol, SUM(packets) AS packets FROM l2_flows WHERE session_id = ? GROUP BY src_mac, protocol", (sid,))}
    l2_now, l2_before = l2(session_id), l2(baseline_id)

    def cut(items):
        items = list(items)
        return {'items': items[:limit], 'total': len(items)}

    return {'new_hosts': cut(new_hosts), 'missing_hosts': cut(missing_hosts), 'changed_hosts': cut(changed),
            'new_conversations': {'items': new_conversations[0], 'total': new_conversations[1]},
            'missing_conversations': {'items': missing_conversations[0], 'total': missing_conversations[1]},
            'new_macs': cut(sorted((macs_now[m] for m in macs_now.keys() - macs_before.keys()), key=lambda m: m['mac'])),
            'missing_macs': cut(sorted((macs_before[m] for m in macs_before.keys() - macs_now.keys()), key=lambda m: m['mac'])),
            'new_layer2': cut(sorted((l2_now[k] for k in l2_now.keys() - l2_before.keys()), key=lambda r: (r['protocol'], r['src_mac']))),
            'new_operations': cut(_new_operations(conn, session_id, baseline_id)),
            'new_alerts': cut(_new_alerts(conn, session_id, baseline_id) if include_alerts else [])}

def _new_alerts(conn, session_id, baseline_id):
    before = {(a['rule'], a['src'], a['dst']) for a in alert_rules.session_alerts(conn, baseline_id)}
    return [a for a in alert_rules.session_alerts(conn, session_id) if (a['rule'], a['src'], a['dst']) not in before]

def _new_operations(conn, session_id, baseline_id):
    """Operations a client sent a server that it didn't in the baseline, most consequential first."""
    return [dict(row) for row in conn.execute(
        f"SELECT src, dst, protocol, operation, kind, count, first_seen FROM operations o WHERE session_id = ? AND NOT EXISTS "
        f"(SELECT 1 FROM operations b WHERE b.session_id = ? AND b.src = o.src AND b.dst = o.dst AND b.protocol = o.protocol "
        f"AND b.operation = o.operation) ORDER BY {KIND_ORDER}, protocol, operation, src, dst", (session_id, baseline_id))]
