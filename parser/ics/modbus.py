"""Modbus/TCP (and Modbus over UDP with the same MBAP header), including Schneider's UMAS function 90."""
from parser.ics.common import text, u16be

NAME = 'Modbus'
PROTOCOL = 'MODBUS'  # as GRASSMARLIN's fingerprints spell it

FUNCTIONS = {
    1: ('Read Coils', 'read'), 2: ('Read Discrete Inputs', 'read'), 3: ('Read Holding Registers', 'read'),
    4: ('Read Input Registers', 'read'), 5: ('Write Single Coil', 'write'), 6: ('Write Single Register', 'write'),
    7: ('Read Exception Status', 'diagnostic'), 8: ('Diagnostics', 'diagnostic'), 11: ('Get Comm Event Counter', 'diagnostic'),
    12: ('Get Comm Event Log', 'diagnostic'), 15: ('Write Multiple Coils', 'write'), 16: ('Write Multiple Registers', 'write'),
    17: ('Report Server ID', 'diagnostic'), 20: ('Read File Record', 'read'), 21: ('Write File Record', 'write'),
    22: ('Mask Write Register', 'write'), 23: ('Read/Write Multiple Registers', 'write'), 24: ('Read FIFO Queue', 'read'),
    43: ('Encapsulated Interface Transport', 'other'), 90: ('UMAS', 'other'),
}
# Diagnostics sub-functions that change the server's state, or only its counters, rather than report on it
DIAGNOSTICS = {1: ('Restart Communications Option', 'control'), 4: ('Force Listen Only Mode', 'control'),
               10: ('Clear Counters and Diagnostic Register', 'diagnostic'), 20: ('Clear Overrun Counter and Flag', 'diagnostic')}
MEI_TYPES = {13: ('CANopen General Reference', 'other'), 14: ('Read Device Identification', 'diagnostic')}
# Schneider Electric UMAS (Unity/EcoStruxure engineering protocol, carried in function 90)
UMAS = {
    0x01: ('Initialize Communication', 'session'), 0x02: ('Read ID', 'diagnostic'), 0x03: ('Read Project Info', 'diagnostic'),
    0x04: ('Read PLC Info', 'diagnostic'), 0x06: ('Read Card Info', 'diagnostic'), 0x0A: ('Repeat', 'other'),
    0x10: ('Take PLC Reservation', 'session'), 0x11: ('Release PLC Reservation', 'session'), 0x12: ('Keep Alive', 'session'),
    0x20: ('Read Memory Block', 'read'), 0x22: ('Read Variables', 'read'), 0x23: ('Write Variables', 'write'),
    0x24: ('Read Coils and Registers', 'read'), 0x25: ('Write Coils and Registers', 'write'),
    0x30: ('Initialize Download', 'program'), 0x31: ('Download Block', 'program'), 0x32: ('End Download', 'program'),
    0x33: ('Initialize Upload', 'program'), 0x34: ('Upload Block', 'program'), 0x35: ('End Upload', 'program'),
    0x36: ('Backup', 'program'), 0x37: ('Restore', 'program'), 0x40: ('Start PLC', 'control'), 0x41: ('Stop PLC', 'control'),
    0x50: ('Monitor PLC', 'read'), 0x58: ('Check PLC', 'diagnostic'), 0x70: ('Read I/O Object', 'read'),
    0x71: ('Write I/O Object', 'write'), 0x73: ('Get Status Module', 'diagnostic'),
}
EXCEPTIONS = {1: 'Illegal Function', 2: 'Illegal Data Address', 3: 'Illegal Data Value', 4: 'Server Device Failure',
              5: 'Acknowledge', 6: 'Server Device Busy', 8: 'Memory Parity Error', 10: 'Gateway Path Unavailable',
              11: 'Gateway Target Device Failed to Respond'}
# Read Device Identification object IDs
DEVICE_OBJECTS = {0: 'Vendor', 1: 'ProductCode', 2: 'Firmware', 3: 'VendorURL', 4: 'Product', 5: 'Model', 6: 'Application'}

def frame_length(data):
    """Length of the MBAP-framed message at the start of data: 0 if more is needed, -1 if it isn't one."""
    if len(data) < 4:
        return 0
    if data[2:4] != b'\0\0':  # protocol identifier: always 0 for Modbus
        return -1
    if len(data) < 6:
        return 0
    length = u16be(data, 4)
    return 6 + length if 2 <= length <= 254 else -1

def describe(function, pdu):
    """(name, kind) of a request PDU's function."""
    if function == 8 and len(pdu) >= 2:
        sub = u16be(pdu, 0)
        return DIAGNOSTICS.get(sub, (f'Diagnostics ({sub})', 'diagnostic'))
    if function == 43 and pdu:
        return MEI_TYPES.get(pdu[0], (f'Encapsulated Interface Transport ({pdu[0]})', 'other'))
    if function == 90 and len(pdu) >= 2:
        name, kind = UMAS.get(pdu[1], (f'0x{pdu[1]:02X}', 'other'))
        return f'UMAS {name}', kind
    return FUNCTIONS.get(function, (f'Function {function}', 'other'))

def decode(frame, out):
    unit, function, pdu = frame[6], frame[7], frame[8:]
    if out.request is None:
        return  # both ends on port 502: no telling requests from replies
    out.roles('MASTER', 'SLAVE')
    if out.request:
        name, kind = describe(function, pdu)
        out.op(name, kind)
        out.fact(out.server, 'ModbusUnit', unit)
        return
    if function & 0x80:
        name, _ = FUNCTIONS.get(function & 0x7F, (f'Function {function & 0x7F}', 'other'))
        code = pdu[0] if pdu else None
        out.op(f'Exception to {name}: {EXCEPTIONS.get(code, f"code {code}")}', 'error', out.client, out.server)
    elif function == 43 and pdu[:1] == b'\x0e':
        _device_identification(pdu, out)

def _device_identification(pdu, out):
    # MEI type, ReadDevId code, conformity level, more follows, next object ID, number of objects, then objects
    count, pos = pdu[5], 6
    for _ in range(count):
        if pos + 2 > len(pdu):
            break
        object_id, length = pdu[pos], pdu[pos + 1]
        name = DEVICE_OBJECTS.get(object_id)
        if name:
            out.identity(out.src, name, text(pdu[pos + 2:pos + 2 + length]))
        pos += 2 + length
