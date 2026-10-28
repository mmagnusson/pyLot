"""
Risky activity in a session, from the industrial operations and flows pyLot stored for it: programs
changed or controllers stopped, control commands and writes, devices controlled from several hosts,
protocol fuzzing, device enumeration and scans of industrial ports.

Alerts are worked out when asked for rather than stored, so they follow re-analysis and live capture.
Each is about one client and one server (or one client and many servers), so the same activity
between the same hosts is one alert however often it happened.
"""
import re
from collections import defaultdict

from parser.protocols import ICS_PORTS

SEVERITIES = ('high', 'medium', 'low')

# Changes to what a controller is doing, as opposed to commands it carries out as part of the process
STATE_CHANGE = re.compile(r'PLC Stop|Stop PLC|PLC Start|Start PLC|Restart|Stop Application|Start Application|'
                          r'Initialize Application|Initialize Data|^Reset |^Stop |^Start |Reset process|Force Listen Only')
UPLOAD = re.compile(r'Upload')
CLOCK = re.compile(r'Clock|Time|C_CS_NA_1')
PASSWORD = re.compile(r'Password|Authentication Request|authenticate')
# Requests a device answers with what it is: an engineering tool, an inventory scan or reconnaissance
IDENTIFY = re.compile(r'Read Device Identification|Report Server ID|Read SZL 0x0011|Read SZL 0x001C|Read SZL 0x0111|'
                      r'Read SZL 0x011C|List Identity|Get_Attributes_All Identity|UMAS Read ID|UMAS Read PLC Info')
# Function codes no decoder knows: nothing legitimate sends many different ones
UNKNOWN_FUNCTION = re.compile(r'^Function (\d+|0x[0-9A-F]+)$')

ENUMERATION_SERVERS = 5     # identification requests to this many devices
ERROR_BURST = 20            # failed requests between one client and one server
UNKNOWN_FUNCTIONS = 5       # distinct unknown function codes from one client
SCAN_TARGETS = 10           # industrial services probed by one host
PROBE_PACKETS = 3           # a flow this small to an industrial port is a probe, not a session

def session_alerts(conn, session_id):
    """Every alert in a session, most severe first."""
    operations = [dict(row) for row in conn.execute(
        "SELECT src, dst, protocol, operation, kind, count, first_seen, last_seen, first_frame FROM operations "
        "WHERE session_id = ?", (session_id,))]
    alerts = Alerts()
    _operation_rules(operations, alerts)
    _controlled_by_several(operations, alerts)
    _enumeration(operations, alerts)
    _errors_and_fuzzing(operations, alerts)
    _ics_scans(conn, session_id, alerts)
    return alerts.sorted()

class Alerts:
    def __init__(self):
        self.items = {}

    def add(self, rule, severity, title, description, src, dst, operation=None):
        """Add an operation (a row from the operations table, or a dict with count and times) to an alert."""
        key = (rule, src, dst)
        alert = self.items.get(key)
        if alert is None:
            alert = self.items[key] = {
                'id': f'{rule}:{src}:{dst}', 'rule': rule, 'severity': severity, 'title': title, 'description': description,
                'src': src, 'dst': dst, 'protocols': set(), 'operations': set(), 'count': 0,
                'first_seen': None, 'last_seen': None, 'first_frame': None}
        if operation:
            if operation.get('protocol'):
                alert['protocols'].add(operation['protocol'])
            if operation.get('operation'):
                alert['operations'].add(operation['operation'])
            alert['count'] += operation.get('count', 1)
            for key, pick in (('first_seen', min), ('last_seen', max), ('first_frame', min)):
                if operation.get(key) is not None:
                    alert[key] = operation[key] if alert[key] is None else pick(alert[key], operation[key])
        return alert

    def sorted(self):
        result = []
        for alert in self.items.values():
            result.append({**alert, 'protocols': sorted(alert['protocols']), 'operations': sorted(alert['operations'])})
        result.sort(key=lambda a: (SEVERITIES.index(a['severity']), a['first_seen'] or 0, a['rule'], a['src'], a['dst'] or ''))
        return result

def _operation_rules(operations, alerts):
    for op in operations:
        name, kind = op['operation'], op['kind']
        if kind == 'program' and UPLOAD.search(name):
            alerts.add('program-upload', 'medium', 'Program read from a controller',
                       "A client uploaded the controller's program or configuration. Engineering tools do this; so does "
                       "someone copying the logic.", op['src'], op['dst'], op)
        elif kind == 'program':
            alerts.add('program-change', 'high', 'Controller program changed',
                       'A client downloaded, deleted or activated program blocks or files on the controller. Make sure '
                       'this was a planned change from an engineering workstation.', op['src'], op['dst'], op)
        elif kind == 'control' and STATE_CHANGE.search(name):
            alerts.add('state-change', 'high', 'Controller stopped, started or restarted',
                       'A client changed what the controller or device is running: stop, start, restart, reset or '
                       'listen-only mode. Outside maintenance this halts the process it controls.', op['src'], op['dst'], op)
        elif kind == 'control':
            alerts.add('control-command', 'medium', 'Control commands',
                       'A client sent commands that operate equipment (DNP3 Operate, IEC 104 commands and the like). '
                       'Normal from the SCADA master; worth a look from anywhere else.', op['src'], op['dst'], op)
        elif op['protocol'] == 'SNMP' and kind == 'write':
            alerts.add('snmp-set', 'medium', 'SNMP Set',
                       "A client changed a device's settings over SNMP.", op['src'], op['dst'], op)
        elif kind == 'write' and CLOCK.search(name):
            alerts.add('clock-change', 'low', 'Clock set',
                       "A client set the device's clock. Expected from a time master; elsewhere it can upset logging "
                       'and time-stamped data.', op['src'], op['dst'], op)
        elif kind == 'write':
            alerts.add('write', 'low', 'Writes to a device',
                       "A client changed values in the device's memory, registers, tags or objects.", op['src'], op['dst'], op)
        elif kind == 'session' and PASSWORD.search(name):
            alerts.add('password', 'low', 'Password or authentication sent',
                       'A client authenticated to the device. In S7comm the password travels lightly obfuscated, so '
                       'anyone capturing this traffic can recover it.', op['src'], op['dst'], op)

def _controlled_by_several(operations, alerts):
    clients = defaultdict(set)
    for op in operations:
        if op['kind'] in ('program', 'control', 'write') and op['protocol'] != 'SNMP':
            clients[op['dst']].add(op['src'])
    for op in operations:
        if op['kind'] in ('program', 'control', 'write') and len(clients.get(op['dst'], ())) > 1:
            alert = alerts.add('several-controllers', 'medium', 'Changed from several hosts',
                               f"{len(clients[op['dst']])} hosts sent writes, commands or program changes to this device. "
                               'Usually only its master or engineering workstation does.', None, op['dst'], op)
            alert['clients'] = sorted(clients[op['dst']])

def _enumeration(operations, alerts):
    servers = defaultdict(set)
    for op in operations:
        if IDENTIFY.search(op['operation']):
            servers[op['src']].add(op['dst'])
    for op in operations:
        if IDENTIFY.search(op['operation']) and len(servers[op['src']]) >= ENUMERATION_SERVERS:
            alerts.add('enumeration', 'medium', 'Devices asked to identify themselves',
                       f"This host asked {len(servers[op['src']])} devices for their model and firmware. Inventory tools "
                       'do this; so does reconnaissance before an attack.', op['src'], None, op)

def _errors_and_fuzzing(operations, alerts):
    errors, unknown = defaultdict(list), defaultdict(list)
    for op in operations:
        if op['kind'] == 'error':
            errors[(op['src'], op['dst'])].append(op)
        if UNKNOWN_FUNCTION.match(op['operation']):
            unknown[(op['src'], op['dst'])].append(op)
    for (src, dst), ops in unknown.items():
        if len(ops) >= UNKNOWN_FUNCTIONS:
            for op in ops:
                alerts.add('fuzzing', 'high', 'Protocol fuzzing or scanning',
                           f'This client sent {len(ops)} different function codes no standard defines, typical of a fuzzer '
                           'or a scanner probing what the device supports. Malformed requests have crashed controllers.',
                           src, dst, op)
    for (src, dst), ops in errors.items():
        if sum(op['count'] for op in ops) >= ERROR_BURST:
            for op in ops:
                alerts.add('errors', 'medium', 'Many failed requests',
                           "The device refused or couldn't answer many of this client's requests: a misconfigured "
                           'master, a device that is failing, or someone probing it.', src, dst, op)

def _ics_scans(conn, session_id, alerts):
    """Hosts that touched many industrial services with a handful of packets each."""
    services = ', '.join(str(transport * 65536 + port) for transport, port in ICS_PORTS)
    rows = conn.execute(
        f"SELECT src, COUNT(DISTINCT dst || ':' || dst_port) AS targets, COUNT(DISTINCT dst) AS hosts, SUM(packets) AS packets, "
        f"MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen, GROUP_CONCAT(DISTINCT protocol) AS protocols "
        f"FROM flows WHERE session_id = ? AND packets <= ? AND transport * 65536 + dst_port IN ({services}) "
        f"GROUP BY src HAVING targets >= ?", (session_id, PROBE_PACKETS, SCAN_TARGETS))
    for row in rows:
        alert = alerts.add('ics-scan', 'medium', 'Scan of industrial services',
                           f"This host probed {row['targets']} industrial services on {row['hosts']} hosts with only a few "
                           'packets each, as a port scanner does.', row['src'], None,
                           {'count': row['targets'], 'first_seen': row['first_seen'], 'last_seen': row['last_seen']})
        alert['protocols'].update(row['protocols'].split(','))
