"""
What IT services on industrial devices say about the device: SNMP system description and name, and the
software named in HTTP Server headers and FTP and SSH greetings. SNMP requests are listed as operations,
since a Set aimed at a controller or switch changes it.
"""
from parser.ics.common import text

class _Protocol:
    PROTOCOL = None

    def __init__(self, name, decode):
        self.NAME = name
        self.decode = decode

HTTP_PORTS = (80, 8000, 8008, 8080, 8081, 8888)
MAX_HEADER = 4096

def _http(payload, out):
    if not payload.startswith(b'HTTP/1.'):
        return
    for line in payload[:MAX_HEADER].split(b'\r\n\r\n', 1)[0].split(b'\r\n')[1:]:
        name, _, value = line.partition(b':')
        if name.strip().lower() == b'server':
            out.fact(out.src, 'HTTPServer', text(value))

def _ftp(payload, out):
    if payload[:4] in (b'220 ', b'220-'):
        out.fact(out.src, 'FTPBanner', text(payload[4:].split(b'\r\n', 1)[0][:200]))

def _ssh(payload, out):
    if payload.startswith(b'SSH-'):
        out.fact(out.src, 'SSHServer', text(payload.split(b'\r\n', 1)[0].split(b'\n', 1)[0][:200]))

http = _Protocol('HTTP', _http)
ftp = _Protocol('FTP', _ftp)
ssh = _Protocol('SSH', _ssh)

# --- SNMP v1 and v2c

SEQUENCE, INTEGER, OCTET_STRING, OID = 0x30, 0x02, 0x04, 0x06
REQUESTS = {0xA0: ('SNMP Get', 'read'), 0xA1: ('SNMP GetNext', 'read'), 0xA3: ('SNMP Set', 'write'),
            0xA5: ('SNMP GetBulk', 'read')}
RESPONSE = 0xA2
SYSTEM = {'1.3.6.1.2.1.1.1.0': 'SystemDescription', '1.3.6.1.2.1.1.2.0': 'SNMPObjectID',
          '1.3.6.1.2.1.1.5.0': 'SystemName', '1.3.6.1.2.1.1.6.0': 'Location'}

def _element(data, pos):
    """(tag, value start, value end) of the BER element at pos."""
    tag, length, pos = data[pos], data[pos + 1], pos + 2
    if length & 0x80:
        size = length & 0x7F
        if not 1 <= size <= 4:
            raise ValueError('unsupported BER length')
        length, pos = int.from_bytes(data[pos:pos + size], 'big'), pos + size
    if pos + length > len(data):
        raise IndexError('BER element runs past the end of the message')
    return tag, pos, pos + length

def _oid(data):
    parts = [data[0] // 40, data[0] % 40] if data else []
    value = 0
    for byte in data[1:]:
        value = value << 7 | byte & 0x7F
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return '.'.join(map(str, parts))

def _snmp(payload, out):
    tag, pos, end = _element(payload, 0)
    if tag != SEQUENCE:
        return
    tag, start, pos = _element(payload, pos)
    if tag != INTEGER or payload[start:pos] not in (b'\x00', b'\x01'):
        return  # SNMPv3 messages are encrypted or laid out differently
    tag, _, pos = _element(payload, pos)          # community
    if tag != OCTET_STRING:
        return
    pdu, pos, end = _element(payload, pos)
    if out.request and pdu in REQUESTS:
        out.op(*REQUESTS[pdu])
        return
    if out.request or pdu != RESPONSE:
        return
    for _ in range(3):                            # request ID, error status, error index
        _, _, pos = _element(payload, pos)
    tag, pos, end = _element(payload, pos)
    while pos < end:
        _, start, pos = _element(payload, pos)    # one variable binding
        tag, name_start, name_end = _element(payload, start)
        name = SYSTEM.get(_oid(payload[name_start:name_end])) if tag == OID else None
        if name:
            tag, value_start, value_end = _element(payload, name_end)
            value = payload[value_start:value_end]
            if tag == OID and len(value) > 1:
                out.fact(out.src, name, _oid(value))
            elif tag == OCTET_STRING:
                out.fact(out.src, name, text(value))

snmp = _Protocol('SNMP', _snmp)
