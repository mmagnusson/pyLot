"""
Read Zeek conn.log files, in Zeek's tab-separated format or as JSON lines, optionally gzipped. Each
record is one connection with packet and byte counts per direction, which pyLot maps onto the same
hosts and flows a capture would give, minus payload-based fingerprinting.
"""
import gzip
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional

GZIP_MAGIC = b'\x1f\x8b'
TRANSPORTS = {'tcp': 6, 'udp': 17, 'icmp': 1}

# Zeek service names (including CISA's ICSNPP analyzers) -> (ICSProtocol, originator role, responder role)
ICS_SERVICES = {
    'modbus': ('MODBUS', 'MASTER', 'SLAVE'),
    'dnp3_tcp': ('DNP3', 'MASTER', 'SLAVE'), 'dnp3_udp': ('DNP3', 'MASTER', 'SLAVE'), 'dnp3': ('DNP3', 'MASTER', 'SLAVE'),
    'enip': ('ETHERNETIP', 'CLIENT', 'SERVER'), 'cip': ('ETHERNETIP', 'CLIENT', 'SERVER'),
    'bacnet': ('BACNET', 'CLIENT', 'SERVER'),
    's7comm': ('S7', 'CLIENT', 'SERVER'), 's7comm_plus': ('S7', 'CLIENT', 'SERVER'),
    'iec104': ('IEC 60870-5-104', 'MASTER', 'SLAVE'), 'iec60870_5_104': ('IEC 60870-5-104', 'MASTER', 'SLAVE'),
    'opcua_binary': ('OPC UA', 'CLIENT', 'SERVER'),
    'profinet': ('PROFINET', 'CLIENT', 'SERVER'), 'profinet_io_cm': ('PROFINET', 'CLIENT', 'SERVER'),
    'ge_srtp': ('GE SRTP', 'CLIENT', 'SERVER'), 'genisys': ('GENISYS', 'MASTER', 'SLAVE'),
    'hart_ip': ('HART-IP', 'CLIENT', 'SERVER'), 'omron_fins': ('OMRON FINS', 'CLIENT', 'SERVER'),
    'synchrophasor': ('IEEE C37.118', 'CLIENT', 'SERVER'), 'c37118': ('IEEE C37.118', 'CLIENT', 'SERVER'),
}

@dataclass(slots=True)
class Connection:
    ts: float
    duration: float
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    transport: int
    services: tuple
    orig_pkts: int
    resp_pkts: int
    orig_bytes: int                  # IP bytes, the closest thing to a capture's frame lengths
    resp_bytes: int
    orig_mac: Optional[str] = None   # only when Zeek logs layer-2 addresses
    resp_mac: Optional[str] = None

def _open_text(path):
    with open(path, 'rb') as f:
        gzipped = f.read(2) == GZIP_MAGIC
    return gzip.open(path, 'rt', encoding='utf-8', errors='replace') if gzipped else open(path, encoding='utf-8', errors='replace')

def looks_like_log(head):
    """Whether the first bytes of an upload could be a Zeek log (gzip, a TSV header, or JSON lines)."""
    return head.startswith(GZIP_MAGIC) or head.startswith(b'#sep') or head.lstrip().startswith(b'{')

def check_log(path):
    """Raise ValueError unless path is a Zeek conn.log pyLot can read."""
    try:
        for _ in read_conn_log(path, limit=1):
            pass
    except (OSError, EOFError, gzip.BadGzipFile) as e:
        raise ValueError(f'Not a readable Zeek log: {e}') from e

def read_conn_log(path, limit=None) -> Iterator[Connection]:
    """Yield the connections in a conn.log. Raises ValueError if it isn't one."""
    with _open_text(path) as f:
        first = f.readline()
        if first.startswith('#separator'):
            yield from _read_tsv(first, f, limit)
        elif first.lstrip().startswith('{'):
            yield from _read_json(first, f, limit)
        else:
            raise ValueError('Not a Zeek conn.log: expected a #separator header or JSON lines')

def _read_tsv(first, f, limit):
    separator = first.split(None, 1)[1].strip().encode().decode('unicode_escape') if ' ' in first else '\t'
    fields = unset = empty = None
    path = None
    count = 0
    for line in f:
        line = line.rstrip('\n')
        if line.startswith('#'):
            key, _, value = line[1:].partition(separator)
            if key == 'fields':
                fields = value.split(separator)
            elif key == 'unset_field':
                unset = value
            elif key == 'empty_field':
                empty = value
            elif key == 'path':
                path = value
            continue
        if fields is None:
            raise ValueError('Not a Zeek conn.log: no #fields header')
        if path not in (None, 'conn'):
            raise ValueError(f'This is a Zeek {path}.log; pyLot reads conn.log')
        values = line.split(separator)
        record = {name: (None if value in (unset, empty) else value) for name, value in zip(fields, values)}
        connection = _connection(record)
        if connection:
            yield connection
            count += 1
            if limit and count >= limit:
                return
    if fields is None:
        raise ValueError('Not a Zeek conn.log: no #fields header')

def _read_json(first, f, limit):
    count = 0
    for number, line in enumerate(_lines(first, f), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f'Not a Zeek JSON log: line {number} is not JSON') from e
        if 'id.orig_h' not in record:
            if number == 1:
                raise ValueError('Not a Zeek conn.log: records have no id.orig_h')
            continue
        connection = _connection(record)
        if connection:
            yield connection
            count += 1
            if limit and count >= limit:
                return

def _lines(first, f):
    yield first
    yield from f

def _number(value, kind=int):
    if value in (None, '', '-'):
        return kind(0)
    try:
        return kind(value)
    except (TypeError, ValueError):
        return kind(0)

def _timestamp(value):
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()

def _mac(value):
    return value.lower() if value and len(value) == 17 else None

def _connection(record):
    orig, resp = record.get('id.orig_h'), record.get('id.resp_h')
    if not orig or not resp or record.get('ts') is None:
        return None
    transport = TRANSPORTS.get(str(record.get('proto') or '').lower(), 0)
    if transport == 1 and ':' in orig:
        transport = 58  # ICMPv6
    service = record.get('service') or ''
    services = tuple(service) if isinstance(service, list) else tuple(s for s in str(service).split(',') if s)
    # Zeek puts ICMP type and code in the port fields; flows from captures have no ports for ICMP
    has_ports = transport in (6, 17)
    orig_pkts, resp_pkts = _number(record.get('orig_pkts')), _number(record.get('resp_pkts'))
    return Connection(
        ts=_timestamp(record['ts']), duration=_number(record.get('duration'), float),
        orig_h=orig, orig_p=_number(record.get('id.orig_p')) if has_ports else 0,
        resp_h=resp, resp_p=_number(record.get('id.resp_p')) if has_ports else 0,
        transport=transport, services=services,
        orig_pkts=orig_pkts or (0 if resp_pkts else 1),  # every logged connection had at least one packet
        resp_pkts=resp_pkts,
        orig_bytes=_number(record.get('orig_ip_bytes')) or _number(record.get('orig_bytes')),
        resp_bytes=_number(record.get('resp_ip_bytes')) or _number(record.get('resp_bytes')),
        orig_mac=_mac(record.get('orig_l2_addr')), resp_mac=_mac(record.get('resp_l2_addr')))
