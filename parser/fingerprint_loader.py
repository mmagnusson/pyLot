"""
Load GRASSMARLIN fingerprints into one model, from either format:
- native GRASSMARLIN 3 XML (fingerprint3.xsd), so stock and custom GRASSMARLIN fingerprints work as-is
- the YAML conversions in fingerprints/, where XML attributes and child elements became lowercase
  keys and element text became '_text'
"""
import logging
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional, Union

import yaml

from parser.packets import TCP_FLAGS

logger = logging.getLogger(__name__)

FINGERPRINTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'fingerprints')

FILTER_TYPES = {'ack', 'mss', 'dsize', 'dsizewithin', 'dstport', 'ethertype', 'flags', 'seq', 'srcport',
                'transportprotocol', 'ttl', 'ttlwithin', 'window'}
BYTE_TESTS = ('gt', 'lt', 'gte', 'lte', 'eq', 'and', 'or')
POSITIONS = {'START_OF_PAYLOAD', 'END_OF_PAYLOAD', 'CURSOR_START', 'CURSOR_MAIN', 'CURSOR_END'}

class FingerprintError(ValueError):
    pass

@dataclass
class Extract:
    name: str
    start: Union[int, str]           # byte offset or one of POSITIONS
    end: Union[int, str]
    max_length: int = 1024
    little_endian: bool = False
    convert: Optional[str] = None    # HEX, INTEGER, RAW_BYTES or STRING
    lookup: Optional[str] = None     # BACNET, ENIPVENDOR or ENIPDEVICE

@dataclass
class Return:
    confidence: int                  # 1 (high) to 5 (low), as in GRASSMARLIN
    direction: str = 'SOURCE'        # which end of the packet the result describes
    category: Optional[str] = None
    role: Optional[str] = None
    details: dict = field(default_factory=dict)
    extracts: list = field(default_factory=list)

@dataclass
class Match:
    content: Optional[bytes] = None
    pattern: Optional[re.Pattern] = None
    offset: int = 0
    depth: int = 0
    relative: bool = True
    no_case: bool = False
    move_cursors: bool = True
    and_then: list = field(default_factory=list)

@dataclass
class ByteTest:
    test: str
    value: int
    offset: int = 0
    relative: bool = False
    post_offset: int = 0
    size: int = 1
    little_endian: bool = False
    and_then: list = field(default_factory=list)

@dataclass
class IsDataAt:
    offset: int
    relative: bool = False
    and_then: list = field(default_factory=list)

@dataclass
class ByteJump:
    offset: int = 0
    relative: bool = False
    size: int = 4
    little_endian: bool = False
    post_offset: int = 0
    calc: Optional[str] = None
    and_then: list = field(default_factory=list)

@dataclass
class Anchor:
    cursor: str                      # START, MAIN or END
    position: Optional[str] = None
    relative: bool = False
    offset: int = 0

@dataclass
class FilterGroup:
    payload: str                     # the For name of the payload this group enables
    name: Optional[str]
    conditions: list                 # (filter type, value) pairs; all must match

@dataclass
class Payload:
    name: str
    description: Optional[str]
    always: list                     # Returns that fire whenever the payload runs
    operations: list

@dataclass
class Fingerprint:
    name: str
    description: Optional[str]
    source: str
    filters: list
    payloads: list

class _XmlNode:
    def __init__(self, element):
        self.element = element
        self.attrs = {k.lower(): v for k, v in element.attrib.items()}

    def get(self, key):
        """Attribute or child-element text named key (case-insensitive)."""
        if key in self.attrs:
            return self.attrs[key]
        for tag, child in self.children():
            if tag == key:
                return child.text()
        return None

    def text(self):
        return self.element.text or ''

    def children(self):
        return [(child.tag.lower(), _XmlNode(child)) for child in self.element]

class _YamlNode:
    def __init__(self, data):
        self.data = data if isinstance(data, dict) else {'_text': data}

    def get(self, key):
        value = self.data.get(key)
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, dict):
            value = value.get('_text')
        return None if value is None else str(value)

    def text(self):
        value = self.data.get('_text')
        return '' if value is None else str(value)

    def children(self):
        # Dict order follows the source document; repeated elements were collected into lists
        for key, value in self.data.items():
            if key != '_text':
                for item in value if isinstance(value, list) else [value]:
                    yield key, _YamlNode(item)

def load_fingerprints(directory=FINGERPRINTS_DIR):
    """Load every .yaml/.yml/.xml fingerprint in directory. Invalid files are logged and skipped."""
    fingerprints = []
    for fname in sorted(os.listdir(directory)):
        path = os.path.join(directory, fname)
        try:
            if fname.endswith(('.yaml', '.yml')):
                with open(path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                root = _YamlNode(data.get('fingerprint', data))
            elif fname.endswith('.xml'):
                root = _XmlNode(ET.parse(path).getroot())
            else:
                continue
            fingerprints.append(build_fingerprint(root, path))
        except (FingerprintError, ValueError, TypeError, AttributeError, yaml.YAMLError, ET.ParseError) as e:
            logger.warning("Skipping fingerprint %s: %s", fname, e)
    logger.info("Loaded %d fingerprints from %s", len(fingerprints), os.path.abspath(directory))
    return fingerprints

def build_fingerprint(root, source):
    header = _first_child(root, 'header')
    name = header.get('name') if header else None
    if not name:
        raise FingerprintError('missing Header/Name')
    filters = [FilterGroup(payload=node.get('for') or '', name=node.get('name'), conditions=_conditions(node))
               for tag, node in root.children() if tag == 'filter']
    payloads = [_payload(node) for tag, node in root.children() if tag == 'payload']
    return Fingerprint(name=name.strip(), description=(header.get('description') or '').strip() or None, source=source,
                       filters=filters, payloads=payloads)

def _first_child(node, tag):
    return next((child for child_tag, child in node.children() if child_tag == tag), None)

def _int(value, default=0):
    return default if value is None or str(value).strip() == '' else int(str(value).strip())

def _bool(value, default):
    return default if value is None or str(value).strip() == '' else str(value).strip().lower() == 'true'

def _conditions(node):
    conditions = []
    for tag, child in node.children():
        if tag not in FILTER_TYPES:
            continue
        if tag in ('dsizewithin', 'ttlwithin'):
            conditions.append((tag, (_int(child.get('min')), _int(child.get('max')))))
        elif tag == 'flags':
            names = re.findall(r'NS|CWR|ECE|URG|ACK|PSH|RST|SYN|FIN', child.text().upper())
            conditions.append((tag, sum(TCP_FLAGS[n] for n in set(names))))
        else:
            conditions.append((tag, _int(child.text())))
    return conditions

def _payload(node):
    always = _first_child(node, 'always')
    return Payload(name=node.get('for') or '', description=(node.get('description') or '').strip() or None,
                   always=[_return(r) for tag, r in always.children() if tag == 'return'] if always else [],
                   operations=_operations(node))

def _operations(node):
    ops = []
    for tag, child in node.children():
        if tag == 'match':
            ops.append(_match(child))
        elif tag == 'bytetest':
            test = next((t for t in BYTE_TESTS if child.get(t) is not None), None)
            if test is None:
                raise FingerprintError('ByteTest without a comparison')
            ops.append(ByteTest(test=test, value=_int(child.get(test)), offset=_int(child.get('offset')),
                                relative=_bool(child.get('relative'), False), post_offset=_int(child.get('postoffset')),
                                size=_int(child.get('bytes'), 1), little_endian=child.get('endian') == 'LITTLE',
                                and_then=_and_then(child)))
        elif tag == 'isdataat':
            ops.append(IsDataAt(offset=_int(child.get('offset')), relative=_bool(child.get('relative'), False),
                                and_then=_and_then(child)))
        elif tag == 'bytejump':
            ops.append(ByteJump(offset=_int(child.get('offset')), relative=_bool(child.get('relative'), False),
                                size=_int(child.get('bytes'), 4), little_endian=child.get('endian') == 'LITTLE',
                                post_offset=_int(child.get('postoffset')), calc=child.get('calc'),
                                and_then=_and_then(child)))
        elif tag == 'anchor':
            ops.append(Anchor(cursor=(child.get('cursor') or 'MAIN').upper(), position=child.get('position'),
                              relative=_bool(child.get('relative'), False), offset=_int(child.get('offset'))))
        elif tag == 'return':
            ops.append(_return(child))
    return ops

def _and_then(node):
    child = _first_child(node, 'andthen')
    return _operations(child) if child else []

def _match(node):
    content = pattern = None
    no_case = _bool(node.get('nocase'), False)
    content_node = _first_child(node, 'content')
    if content_node:
        content = _content_bytes((content_node.get('type') or 'HEX').upper(), content_node.text())
        if no_case:
            content = content.lower()
    elif node.get('pattern') is not None:
        flags = re.DOTALL | (re.IGNORECASE if no_case else 0)
        pattern = re.compile(node.get('pattern').encode('latin-1'), flags)
    else:
        raise FingerprintError('Match without Content or Pattern')
    # Defaults come from fingerprint3.xsd: Match is relative and moves cursors unless told otherwise
    return Match(content=content, pattern=pattern, offset=_int(node.get('offset')), depth=_int(node.get('depth')),
                 relative=_bool(node.get('relative'), True), no_case=no_case,
                 move_cursors=_bool(node.get('movecursors'), True), and_then=_and_then(node))

def _content_bytes(kind, text):
    if kind in ('HEX', 'RAW_BYTES'):
        return bytes.fromhex(''.join(text.split()))
    if kind == 'STRING':
        return text.encode('utf-8')
    if kind == 'INTEGER':
        # Same bytes as Java's BigInteger.toByteArray(), which GRASSMARLIN used
        n = int(text.strip())
        return n.to_bytes(n.bit_length() // 8 + 1, 'big', signed=True)
    raise FingerprintError(f'unknown Content type {kind}')

def _position(value):
    if value is None:
        raise FingerprintError('Extract without From/To')
    value = value.strip()
    return value if value in POSITIONS else int(value)

def _return(node):
    confidence = node.get('confidence')
    if confidence is None:
        raise FingerprintError('Return without Confidence')
    ret = Return(confidence=_int(confidence), direction=(node.get('direction') or 'SOURCE').upper())
    details = _first_child(node, 'details')
    if details:
        ret.category = (details.get('category') or '').strip() or None
        ret.role = (details.get('role') or '').strip() or None
        for tag, detail in details.children():
            if tag == 'detail' and detail.get('name'):
                ret.details[detail.get('name')] = detail.text().strip()
    for tag, extract in node.children():
        if tag == 'extract':
            post = _first_child(extract, 'post')
            ret.extracts.append(Extract(name=extract.get('name'), start=_position(extract.get('from')),
                                        end=_position(extract.get('to')), max_length=_int(extract.get('maxlength'), 1024),
                                        little_endian=extract.get('endian') == 'LITTLE',
                                        convert=post.get('convert') if post else None,
                                        lookup=post.get('lookup') if post else None))
    return ret
