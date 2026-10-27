"""
Evaluate GRASSMARLIN fingerprints against decoded packets.

This follows GRASSMARLIN 3.2's engine (FProcessor and PayloadFunctions): a payload runs when any filter
group with its For name matches, its Always returns fire first, then its operations run in order, and
a content match leaves the main cursor at the start of the match.

Deliberate differences, each fixing a GRASSMARLIN bug:
- HEX content is decoded byte for byte (GRASSMARLIN dropped leading 00 bytes and could add a sign byte)
- content and pattern searches cover the whole Offset..Depth window, including the last payload byte
- Pattern is a regular-expression search over the raw bytes (GRASSMARLIN never matched a pattern)
- NoCase applies to content as well as patterns
- reads past the end of the payload fail instead of returning 0, and ByteJump honours Relative
- Extract accepts END_OF_PAYLOAD, and an Extract with no Post conversion is reported as HEX
Like GRASSMARLIN, Within and Reverse are ignored and ByteTest AND/OR behave like EQ.
"""
import csv
import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass

from parser.fingerprint_loader import Anchor, ByteJump, ByteTest, IsDataAt, Match, Return

logger = logging.getLogger(__name__)

REFERENCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reference')

@dataclass(slots=True)
class Annotation:
    fingerprint: str
    payload: str
    ip: str                          # the host this result describes
    confidence: int                  # 1 (high) to 5 (low)
    properties: dict                 # e.g. {'Category': 'PLC', 'Role': 'SLAVE', 'ICSProtocol': 'MODBUS'}

class _Cursor:
    __slots__ = ('start', 'main', 'end')

    def __init__(self):
        self.start = self.main = self.end = 0

_CHECKS = {
    'ack': lambda p, v: p.ack == v,
    'dsize': lambda p, v: len(p.payload) == v,
    'dsizewithin': lambda p, v: v[0] <= len(p.payload) <= v[1],
    'dstport': lambda p, v: p.dst_port == v,
    'ethertype': lambda p, v: p.ethertype == v,
    'flags': lambda p, v: p.tcp_flags is not None and p.tcp_flags & v == v,
    'mss': lambda p, v: p.mss == v,
    'seq': lambda p, v: p.seq == v,
    'srcport': lambda p, v: p.src_port == v,
    'transportprotocol': lambda p, v: p.transport == v,
    'ttl': lambda p, v: p.ttl == v,
    'ttlwithin': lambda p, v: p.ttl is not None and v[0] <= p.ttl <= v[1],
    'window': lambda p, v: p.window == v,
}

_TESTS = {
    'gt': lambda a, b: a > b,
    'lt': lambda a, b: a < b,
    'gte': lambda a, b: a >= b,
    'lte': lambda a, b: a <= b,
    'eq': lambda a, b: a == b,
    'and': lambda a, b: a == b,
    'or': lambda a, b: a == b,
}

class Lookups:
    """Name tables for Extract lookups, read from parser/reference/<LOOKUP>.csv (id,name) when present."""

    def __init__(self, directory=REFERENCE_DIR):
        self.directory = directory
        self.tables = {}

    def name(self, lookup, ident):
        if lookup not in self.tables:
            self.tables[lookup] = self._load(lookup)
        # Without a table, the numeric ID is still worth reporting
        return self.tables[lookup].get(ident, str(ident))

    def _load(self, lookup):
        table = {}
        path = os.path.join(self.directory, f'{lookup}.csv')
        try:
            with open(path, newline='', encoding='utf-8') as f:
                for row in csv.reader(f):
                    if len(row) >= 2 and row[0].strip().isdigit():
                        table[int(row[0])] = row[1].strip()
        except OSError:
            logger.info("No %s lookup table at %s; reporting numeric IDs", lookup, path)
        return table

class FingerprintEngine:
    def __init__(self, fingerprints, lookups=None):
        self.fingerprints = fingerprints
        self.lookups = lookups or Lookups()
        # Role/Category/Detail values per Return; shared across packets, so treat as read-only
        self._fixed_properties = {}
        # Index filter groups by the port they require, so each packet only checks plausible groups
        self._by_dst_port = defaultdict(list)
        self._by_src_port = defaultdict(list)
        self._unindexed = []
        for fp in fingerprints:
            for group in fp.filters:
                checks = [(_CHECKS[kind], value) for kind, value in group.conditions]
                entry = (fp, group.payload, checks)
                ports = dict(group.conditions)
                if 'dstport' in ports:
                    self._by_dst_port[ports['dstport']].append(entry)
                elif 'srcport' in ports:
                    self._by_src_port[ports['srcport']].append(entry)
                else:
                    self._unindexed.append(entry)

    def evaluate(self, pkt):
        """Return the Annotations every matching fingerprint payload produces for pkt."""
        if pkt.src_ip is None:
            return []
        candidates = self._unindexed
        if pkt.dst_port is not None:
            candidates = self._by_dst_port.get(pkt.dst_port, []) + self._by_src_port.get(pkt.src_port, []) + candidates
        enabled = {}
        for fp, payload_name, checks in candidates:
            for check, value in checks:
                if not check(pkt, value):
                    break
            else:
                enabled.setdefault(id(fp), (fp, set()))[1].add(payload_name)
        results = []
        for fp, names in enabled.values():
            for payload in fp.payloads:
                if payload.name in names:
                    cursor = _Cursor()
                    for ret in payload.always:
                        self._apply_return(fp, payload, ret, pkt, cursor, results)
                    self._run(fp, payload, payload.operations, pkt, cursor, results)
        return results

    def _run(self, fp, payload, ops, pkt, cursor, results):
        data = pkt.payload
        for op in ops:
            if isinstance(op, Return):
                self._apply_return(fp, payload, op, pkt, cursor, results)
            elif not data:
                continue
            elif isinstance(op, Match):
                if _match(op, data, cursor):
                    self._run(fp, payload, op.and_then, pkt, cursor, results)
            elif isinstance(op, ByteTest):
                if _byte_test(op, data, cursor):
                    self._run(fp, payload, op.and_then, pkt, cursor, results)
            elif isinstance(op, IsDataAt):
                position = op.offset + (cursor.main if op.relative else 0)
                if 0 <= position < len(data):
                    self._run(fp, payload, op.and_then, pkt, cursor, results)
            elif isinstance(op, ByteJump):
                _byte_jump(op, data, cursor)
                # GRASSMARLIN runs a jump's AndThen whether or not the jump moved the cursor
                self._run(fp, payload, op.and_then, pkt, cursor, results)
            elif isinstance(op, Anchor):
                _anchor(op, data, cursor)

    def _apply_return(self, fp, payload, ret, pkt, cursor, results):
        properties = self._fixed_properties.get(id(ret))
        if properties is None:
            properties = self._fixed_properties[id(ret)] = {
                **({'Role': ret.role} if ret.role else {}), **({'Category': ret.category} if ret.category else {}), **ret.details}
        if ret.extracts and pkt.payload:
            properties = dict(properties)
            for extract in ret.extracts:
                value = self._extract(extract, pkt.payload, cursor)
                if value:
                    properties[extract.name] = value
        if properties:
            ip = pkt.src_ip if ret.direction == 'SOURCE' else pkt.dst_ip
            results.append(Annotation(fp.name, payload.name, ip, ret.confidence, properties))

    def _extract(self, extract, data, cursor):
        start, end = _resolve(extract.start, data, cursor), _resolve(extract.end, data, cursor)
        low, high = min(start, end), max(start, end)
        high = min(high, low + extract.max_length, len(data))
        if low < 0 or low >= high:
            return None
        raw = data[low:high]
        if extract.little_endian:
            raw = raw[::-1]
        if extract.convert is None and extract.lookup:
            return self.lookups.name(extract.lookup, int.from_bytes(raw, 'big', signed=True))
        convert = extract.convert or 'HEX'
        if convert == 'INTEGER':
            return str(int.from_bytes(raw, 'big'))
        if convert == 'STRING':
            return raw.decode('utf-8', 'replace').strip('\x00').strip()
        if convert == 'RAW_BYTES':
            # Java's Arrays.toString(byte[]) format, as GRASSMARLIN showed it
            return '[' + ', '.join(str(b - 256 if b > 127 else b) for b in raw) + ']'
        return raw.hex().upper()

def _resolve(position, data, cursor):
    if isinstance(position, int):
        return position
    return {'START_OF_PAYLOAD': 0, 'END_OF_PAYLOAD': len(data), 'CURSOR_START': cursor.start,
            'CURSOR_MAIN': cursor.main, 'CURSOR_END': cursor.end}[position]

def _match(op, data, cursor):
    start = max(op.offset + (cursor.main if op.relative else 0), 0)
    end = len(data) if op.depth <= 0 else min(len(data), start + op.depth)
    if start >= end:
        return False
    if op.pattern is not None:
        found = op.pattern.search(data[start:end])
        if not found:
            return False
        if op.move_cursors:
            cursor.start, cursor.end = start + found.start(), start + found.end()
        cursor.main = start + found.end()
        return True
    haystack = data[start:end].lower() if op.no_case else data[start:end]
    location = haystack.find(op.content)
    if not op.content or location < 0:
        return False
    location += start
    if op.move_cursors:
        cursor.start, cursor.end = location, location + len(op.content)
    cursor.main = location
    return True

def _read_int(data, position, size, little_endian):
    if position < 0 or position + size > len(data):
        return None
    return int.from_bytes(data[position:position + size], 'little' if little_endian else 'big')

def _byte_test(op, data, cursor):
    value = _read_int(data, op.offset + (cursor.main if op.relative else 0), op.size, op.little_endian)
    cursor.main += op.post_offset
    return value is not None and _TESTS[op.test](value, op.value)

def _byte_jump(op, data, cursor):
    value = _read_int(data, op.offset + (cursor.main if op.relative else 0), op.size, op.little_endian)
    if value is None:
        return
    location = (_calculate(op.calc, value) if op.calc else value) + op.post_offset
    if location < len(data):
        if op.relative:
            cursor.main += location
        else:
            cursor.main = location

def _calculate(expression, x):
    """Evaluate a ByteJump Calc such as 'x*2+4' (integers, x, + - * /) with normal precedence."""
    tokens = re.findall(r'\d+|x|[-+*/]', expression.replace(' ', ''))
    terms, operators = [], []
    for token in tokens:
        if token in '+-*/':
            operators.append(token)
            continue
        value = x if token == 'x' else int(token)
        if operators and operators[-1] in '*/':
            op, previous = operators.pop(), terms.pop()
            value = previous * value if op == '*' else (previous // value if value else 0)
        terms.append(value)
    total = terms[0] if terms else x
    for op, value in zip(operators, terms[1:]):
        total = total + value if op == '+' else total - value
    return total

def _anchor(op, data, cursor):
    offset = op.offset
    if op.relative:
        offset += cursor.main
    elif op.position:
        offset += _resolve(op.position, data, cursor)
    setattr(cursor, op.cursor.lower(), offset)
