"""
The asset inventory: devices tracked across sessions, with when they were first and last seen and how
their identity changed.

Each finished session adds an observation of every device it saw: one per MAC address (with the IP
addresses it used, its classification and the identity it reported), plus one per private IP address
reached through a router, whose MAC the capture can't see. Addresses on the Internet aren't assets.

An observation joins the asset it most likely belongs to:
    1. the same serial number (from the same vendor, when both are known)
    2. else the same MAC address, unless both have serial numbers and they differ
    3. else the same IP address, if the asset was only ever seen through a router (no MAC) or the
       observation has no MAC either; the most recently seen such asset wins
and otherwise starts a new asset. So a replaced device at the same address, with a new MAC, is a new
asset, and a device whose address changed keeps its asset. Observations outlive their sessions, so the
inventory keeps devices from captures that have been deleted. Assets can be named, annotated, merged
when matching kept two apart, and removed.
"""
import ipaddress
import json
import re
import threading
from collections import defaultdict
from datetime import datetime, timezone

import advisories
import storage

# The properties kept with an observation: enough to describe the device and match it against advisories
IDENTITY_PROPERTIES = ('Vendor', 'Model', 'Product', 'Platform', 'OrderNumber', 'Firmware', 'Software', 'Serial', 'Module',
                       'SystemDescription', 'SystemName', 'NameOfStation', 'Category', 'Role')
OBSERVATION_FIELDS = ('mac', 'ips', 'mac_vendor', 'device_vendor', 'model', 'firmware', 'serial', 'name', 'category', 'role')
# Identity changes worth reporting, in the order they are listed
CHANGE_FIELDS = (('ips', 'IP address'), ('mac', 'MAC address'), ('device_vendor', 'Vendor'), ('model', 'Model'),
                 ('firmware', 'Firmware'), ('serial', 'Serial number'))
MAX_MATCHING_IPS = 16   # a MAC answering for more addresses than this is a router or proxy; its addresses don't identify it
MAX_NAME_LENGTH = 100
MAX_NOTES_LENGTH = 5000

_lock = threading.Lock()  # analysis and page requests both add sessions; one at a time

# --- observations

def _private(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.is_private and not (address.is_multicast or address.is_unspecified or address.is_loopback)

def _normal_serial(serial):
    """Serial numbers as compared: lower case without spaces; zeros and blanks are no serial at all."""
    if not serial:
        return None
    text = re.sub(r'\s+', '', str(serial)).lower()
    return None if not text or not text.strip('0x') else text

def _identity_properties(properties):
    return {name: properties[name]['values'] for name in IDENTITY_PROPERTIES if name in properties}

def _session_time(session):
    if session['first_seen'] is not None:
        return session['first_seen'], session['last_seen']
    try:
        created = datetime.strptime(session['created_at'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        created = None
    return created, created

def session_observations(conn, session_id):
    """What the inventory takes from one session: a list of observation dicts."""
    session = storage.get_session(conn, session_id)
    start, end = _session_time(session)
    observations, device_ips = [], set()

    def observe(item, mac, ips, mac_vendor, name, packets):
        observations.append({
            'mac': mac, 'ips': ips, 'mac_vendor': mac_vendor, 'device_vendor': item['device_vendor'], 'model': item['model'],
            'firmware': item['firmware'], 'serial': item['serial'], 'name': name, 'category': item['category'],
            'role': item['role'], 'properties': _identity_properties(item['properties']),
            'first_seen': item['first_seen'] if item['first_seen'] is not None else start,
            'last_seen': item['last_seen'] if item['last_seen'] is not None else end, 'packets': packets or 0})

    for device in storage.all_devices(conn, session_id):
        device_ips.update(device['ips'])
        observe(device, device['mac'], device['ips'], device['vendor'], device['name'], device['packets'])
    for host in storage.all_hosts(conn, session_id):
        if host['ip'] in device_ips or host['mac'] or host['kind'] != 'unicast' or not host['packets_sent'] or not _private(host['ip']):
            continue
        observe(host, None, [host['ip']], None, None, host['packets_sent'] + host['packets_received'])
    return observations

class _Keys:
    """What identifies each asset, from its observations, for matching new ones."""

    def __init__(self, conn):
        self.serials = defaultdict(set)         # serial -> assets
        self.macs = {}                          # mac -> asset (the latest seen with it)
        self.ips = defaultdict(dict)            # ip -> {asset: last seen}
        self.asset_serials = defaultdict(set)
        self.asset_vendors = defaultdict(set)
        self.asset_macs = defaultdict(set)
        for row in conn.execute("SELECT asset_id, mac, ips, device_vendor, serial, last_seen FROM asset_observations "
                                "ORDER BY COALESCE(last_seen, 0)"):
            self.add(row['asset_id'], {'mac': row['mac'], 'ips': row['ips'].split(), 'device_vendor': row['device_vendor'],
                                       'serial': row['serial'], 'last_seen': row['last_seen']})

    def add(self, asset, observation):
        serial = _normal_serial(observation['serial'])
        if serial:
            self.serials[serial].add(asset)
            self.asset_serials[asset].add(serial)
        if observation['device_vendor']:
            self.asset_vendors[asset].update(advisories.vendor_keys(observation['device_vendor']))
        if observation['mac']:
            self.macs[observation['mac']] = asset
            self.asset_macs[asset].add(observation['mac'])
        if len(observation['ips']) <= MAX_MATCHING_IPS:
            for ip in observation['ips']:
                self.ips[ip][asset] = max(observation['last_seen'] or 0, self.ips[ip].get(asset, 0))

    def _serial_conflict(self, asset, serial):
        return bool(serial and self.asset_serials[asset] and serial not in self.asset_serials[asset])

    def match(self, observation, taken):
        """The asset this observation belongs to, or None for a new one. taken: assets this session already matched."""
        serial = _normal_serial(observation['serial'])
        if serial:
            vendors = advisories.vendor_keys(observation['device_vendor']) if observation['device_vendor'] else set()
            candidates = [a for a in self.serials.get(serial, ())
                          if a not in taken and not (vendors and self.asset_vendors[a] and not vendors & self.asset_vendors[a])]
            if len(candidates) == 1:
                return candidates[0]
        mac = observation['mac']
        if mac:
            asset = self.macs.get(mac)
            if asset is not None and asset not in taken and not self._serial_conflict(asset, serial):
                return asset
        if len(observation['ips']) <= MAX_MATCHING_IPS:
            candidates = {}
            for ip in observation['ips']:
                for asset, seen in self.ips.get(ip, {}).items():
                    if asset in taken or self._serial_conflict(asset, serial) or (mac and self.asset_macs[asset]):
                        continue
                    candidates[asset] = max(seen, candidates.get(asset, 0))
            if candidates:
                return max(candidates, key=lambda a: (candidates[a], a))
        return None

def _record(conn, session_id, keys):
    session = storage.get_session(conn, session_id)
    observations = session_observations(conn, session_id)
    taken, assigned = set(), []
    for observation in observations:  # matched while the session's previous observations, if any, still count
        asset = keys.match(observation, taken)
        if asset is not None:
            taken.add(asset)
        assigned.append(asset)
    with conn:
        conn.execute("DELETE FROM asset_observations WHERE session_id = ?", (session_id,))
        for observation, asset in zip(observations, assigned):
            if asset is None:
                asset = conn.execute("INSERT INTO assets DEFAULT VALUES").lastrowid
                taken.add(asset)
            conn.execute(
                "INSERT INTO asset_observations (asset_id, session_id, session_name, mac, ips, mac_vendor, device_vendor, model, "
                "firmware, serial, name, category, role, properties, first_seen, last_seen, packets) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (asset, session_id, session['name'], observation['mac'], ' '.join(observation['ips']), observation['mac_vendor'],
                 observation['device_vendor'], observation['model'], observation['firmware'], observation['serial'],
                 observation['name'], observation['category'], observation['role'], json.dumps(observation['properties']),
                 observation['first_seen'], observation['last_seen'], observation['packets']))
            keys.add(asset, observation)
        conn.execute("INSERT OR REPLACE INTO inventory_sessions (session_id) VALUES (?)", (session_id,))
    return len(observations)

def sync(conn, session_ids=None):
    """
    Add finished sessions that aren't in the inventory yet (all of them, or just these), oldest capture
    first. Returns how many sessions were added.
    """
    with _lock:
        query = ("SELECT id FROM sessions WHERE status IN ('ready', 'stopped') "
                 "AND id NOT IN (SELECT session_id FROM inventory_sessions)")
        pending = [row['id'] for row in conn.execute(query + " ORDER BY COALESCE(first_seen, 0), id")]
        if session_ids is not None:
            pending = [sid for sid in pending if sid in set(session_ids)]
        if not pending:
            return 0
        keys = _Keys(conn)
        for session_id in pending:
            _record(conn, session_id, keys)
        # Assets that lost every observation to a re-analysis are gone, unless someone named or annotated them
        with conn:
            conn.execute("DELETE FROM assets WHERE name IS NULL AND notes IS NULL "
                         "AND id NOT IN (SELECT asset_id FROM asset_observations)")
        return len(pending)

# --- reading the inventory

def _observation_dict(row):
    observation = dict(row)
    observation['ips'] = observation['ips'].split()
    observation['properties'] = json.loads(observation['properties'])
    return observation

def _observations(conn, asset_id=None):
    query = "SELECT * FROM asset_observations" + (" WHERE asset_id = ?" if asset_id is not None else "")
    grouped = defaultdict(list)
    for row in conn.execute(query + " ORDER BY COALESCE(first_seen, 0), id", () if asset_id is None else (asset_id,)):
        grouped[row['asset_id']].append(_observation_dict(row))
    return grouped

def changes(observations):
    """How an asset's identity changed between sightings, oldest first. observations: oldest first."""
    found, previous = [], {}
    for observation in observations:
        for field, label in CHANGE_FIELDS:
            value = observation[field]
            if not value:
                continue
            old = previous.get(field)
            # A device seen using more or fewer of its addresses hasn't moved; only a wholly new set counts
            moved = old is not None and (not set(old) & set(value) if field == 'ips' else old != value)
            if moved:
                found.append({'field': field, 'label': label, 'old': ' '.join(old) if field == 'ips' else old,
                              'new': ' '.join(value) if field == 'ips' else value, 'session_id': observation['session_id'],
                              'session_name': observation['session_name'], 'seen': observation['first_seen']})
            previous[field] = value
    return found

def _summary(asset, observations):
    """An asset as it was last seen: each field from the newest observation that has it."""
    latest = observations[::-1]
    summary = {'id': asset['id'], 'given_name': asset['name'], 'notes': asset['notes'], 'created_at': asset['created_at']}
    for field in OBSERVATION_FIELDS:
        summary[field] = next((o[field] for o in latest if o[field]), [] if field == 'ips' else None)
    addresses = set(ip for o in observations for ip in o['ips'])
    seen = [o['first_seen'] for o in observations if o['first_seen'] is not None]
    last = [o['last_seen'] for o in observations if o['last_seen'] is not None]
    summary.update(
        # Not the model: fingerprints guess it, sometimes as a list of candidates
        label=asset['name'] or summary['name'] or (summary['ips'][0] if summary['ips'] else summary['mac']),
        all_ips=sorted(addresses, key=storage._ip_key),
        sessions=len({o['session_id'] or -o['id'] for o in observations}),
        first_seen=min(seen) if seen else None, last_seen=max(last) if last else None,
        changes=len(changes(observations)),
        properties=next((o['properties'] for o in latest if o['properties']), {}))
    return summary

def _assets(conn, asset_id=None):
    query = "SELECT id, name, notes, created_at FROM assets" + (" WHERE id = ?" if asset_id is not None else "")
    observations = _observations(conn, asset_id)
    return [_summary(row, observations.get(row['id'], [])) for row in conn.execute(query + " ORDER BY id",
                                                                                  () if asset_id is None else (asset_id,))]

def _as_host(asset):
    # Matching sorts by IP address, so each asset stands in as the IPv6 address of its id (::7 for asset 7)
    return {'ip': str(ipaddress.IPv6Address(asset['id'])), 'vendor': asset['mac_vendor'],
            'properties': {name: {'values': values} for name, values in asset['properties'].items()}}

def _vulnerabilities(conn, assets):
    found = defaultdict(list)
    for v in advisories.match_hosts(conn, [_as_host(a) for a in assets if a['properties']]):
        found[int(ipaddress.IPv6Address(v.pop('ip')))].append(v)
    return found

def list_assets(conn):
    """Every asset with its current identity, addresses, first and last seen, and counts of sessions, changes and advisories."""
    sync(conn)
    assets = _assets(conn)
    vulnerabilities = _vulnerabilities(conn, assets)
    latest_session = conn.execute("SELECT session_id FROM asset_observations WHERE session_id IS NOT NULL "
                                  "GROUP BY session_id ORDER BY MAX(last_seen) DESC LIMIT 1").fetchone()
    latest_session = latest_session[0] if latest_session else None
    in_latest = {row[0] for row in conn.execute("SELECT DISTINCT asset_id FROM asset_observations WHERE session_id = ?",
                                                (latest_session,))}
    for asset in assets:
        found = vulnerabilities.get(asset['id'], [])
        asset['vulnerabilities'] = sum(v['status'] == 'affected' for v in found)
        asset['possible_vulnerabilities'] = len(found) - asset['vulnerabilities']
        asset['in_latest_session'] = asset['id'] in in_latest
        asset.pop('properties')
    return assets

def get_asset(conn, asset_id):
    """One asset with its sightings (newest first), identity changes and matching advisories, or None."""
    sync(conn)
    assets = _assets(conn, asset_id)
    if not assets:
        return None
    asset = assets[0]
    observations = _observations(conn, asset_id).get(asset_id, [])
    asset['changes'] = changes(observations)[::-1]
    asset['sightings'] = observations[::-1]
    asset['vulnerabilities'] = _vulnerabilities(conn, [asset]).get(asset_id, [])
    return asset

def asset_for(conn, session_id, ip=None, mac=None):
    """The asset a session's host (by IP) or device (by MAC) belongs to: {id, label, sessions, first_seen}, or None."""
    sync(conn, [session_id])
    rows = conn.execute("SELECT asset_id, ips, mac FROM asset_observations WHERE session_id = ?", (session_id,)).fetchall()
    asset_id = next((row['asset_id'] for row in rows if (mac and row['mac'] == mac) or (ip and ip in row['ips'].split())), None)
    if asset_id is None:
        return None
    asset = _assets(conn, asset_id)[0]
    return {key: asset[key] for key in ('id', 'label', 'sessions', 'first_seen', 'last_seen', 'changes')}

# --- changing the inventory

def update_asset(conn, asset_id, name=None, notes=None):
    """Set an asset's name and notes (blank clears them). Raises ValueError if they're too long, KeyError if it doesn't exist."""
    name = (name or '').strip() or None
    notes = (notes or '').strip() or None
    if name and len(name) > MAX_NAME_LENGTH:
        raise ValueError(f'names can have at most {MAX_NAME_LENGTH} characters')
    if notes and len(notes) > MAX_NOTES_LENGTH:
        raise ValueError(f'notes can have at most {MAX_NOTES_LENGTH} characters')
    with conn:
        if not conn.execute("UPDATE assets SET name = ?, notes = ? WHERE id = ?", (name, notes, asset_id)).rowcount:
            raise KeyError(asset_id)

def merge_assets(conn, asset_id, other_id):
    """Move every observation of other_id to asset_id and remove other_id, keeping asset_id's name and notes (or other's, if it has none)."""
    if asset_id == other_id:
        raise ValueError("an asset can't be merged with itself")
    with _lock, conn:
        rows = {row['id']: row for row in conn.execute("SELECT * FROM assets WHERE id IN (?, ?)", (asset_id, other_id))}
        if len(rows) != 2:
            raise KeyError(other_id if asset_id in rows else asset_id)
        keep, gone = rows[asset_id], rows[other_id]
        conn.execute("UPDATE assets SET name = ?, notes = ? WHERE id = ?",
                     (keep['name'] or gone['name'], keep['notes'] or gone['notes'], asset_id))
        conn.execute("UPDATE asset_observations SET asset_id = ? WHERE asset_id = ?", (asset_id, other_id))
        conn.execute("DELETE FROM assets WHERE id = ?", (other_id,))

def delete_asset(conn, asset_id):
    """Remove an asset and its observations. A later session that sees the device adds it again."""
    with _lock, conn:
        return bool(conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,)).rowcount)
