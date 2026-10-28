"""DNP3 over TCP or UDP: link frames (checked against their header CRC) and the application function codes."""
from parser.ics.common import u16le

NAME = 'DNP3'
PROTOCOL = 'DNP3'
START = b'\x05\x64'

FUNCTIONS = {
    1: ('Read', 'read'), 2: ('Write', 'write'), 3: ('Select', 'control'), 4: ('Operate', 'control'),
    5: ('Direct Operate', 'control'), 6: ('Direct Operate No Ack', 'control'), 7: ('Immediate Freeze', 'control'),
    8: ('Immediate Freeze No Ack', 'control'), 9: ('Freeze and Clear', 'control'), 10: ('Freeze and Clear No Ack', 'control'),
    11: ('Freeze at Time', 'control'), 12: ('Freeze at Time No Ack', 'control'), 13: ('Cold Restart', 'control'),
    14: ('Warm Restart', 'control'), 15: ('Initialize Data', 'control'), 16: ('Initialize Application', 'control'),
    17: ('Start Application', 'control'), 18: ('Stop Application', 'control'), 19: ('Save Configuration', 'program'),
    20: ('Enable Unsolicited Responses', 'write'), 21: ('Disable Unsolicited Responses', 'write'), 22: ('Assign Class', 'write'),
    23: ('Delay Measurement', 'diagnostic'), 24: ('Record Current Time', 'write'), 25: ('Open File', 'other'),
    26: ('Close File', 'other'), 27: ('Delete File', 'program'), 28: ('Get File Info', 'read'),
    29: ('Authenticate File', 'session'), 30: ('Abort File', 'other'), 31: ('Activate Configuration', 'program'),
    32: ('Authentication Request', 'session'), 33: ('Authentication Error', 'session'),
}
RESPONSE, UNSOLICITED_RESPONSE = 129, 130
USER_DATA = (3, 4)  # link functions that carry transport segments: confirmed and unconfirmed user data

def _crc_table():
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
        table.append(crc)
    return table

_CRC_TABLE = _crc_table()

def crc(data):
    value = 0
    for byte in data:
        value = (value >> 8) ^ _CRC_TABLE[(value ^ byte) & 0xFF]
    return ~value & 0xFFFF

def frame_length(data):
    if len(data) < 2:
        return 0 if data in (b'', b'\x05') else -1
    if data[:2] != START:
        return -1
    if len(data) < 10:
        return 0
    if data[2] < 5 or crc(data[:8]) != u16le(data, 8):
        return -1
    user = data[2] - 5  # the length counts control and addresses, then user data in 16-byte blocks with a CRC each
    return 10 + user + 2 * ((user + 15) // 16)

def user_data(frame):
    data, pos, remaining = bytearray(), 10, frame[2] - 5
    while remaining > 0:
        size = min(16, remaining)
        data += frame[pos:pos + size]
        pos += size + 2
        remaining -= size
    return bytes(data)

def decode(frame, out):
    control, source = frame[3], u16le(frame, 6)
    out.fact(out.src, 'DNP3Address', source)
    data = user_data(frame)
    # Primary user-data frames, and only the first transport segment of an application fragment has its header
    if not control & 0x40 or control & 0x0F not in USER_DATA or len(data) < 3 or not data[0] & 0x40:
        return
    function = data[2]
    if function in (RESPONSE, UNSOLICITED_RESPONSE):
        out.roles('MASTER', 'SLAVE', client=out.dst, server=out.src)
        if function == UNSOLICITED_RESPONSE:
            out.op('Unsolicited Response', 'data', out.dst, out.src)
    elif function in FUNCTIONS:
        out.roles('MASTER', 'SLAVE', client=out.src, server=out.dst)
        out.op(*FUNCTIONS[function])
