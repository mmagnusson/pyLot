"""
Siemens S7comm over ISO-on-TCP (TPKT and COTP on port 102): job functions, user-data functions, and the
module and component identification a CPU returns when asked for SZL 0x0011 and 0x001C. S7comm-plus
(S7-1200 and S7-1500) is recognised but its functions aren't decoded.
"""
import re

from parser.ics.common import text, u16be

NAME = 'S7comm'
PROTOCOL = 'S7COMM'
PLUS_PROTOCOL = 'S7COMM-PLUS'
COTP_DATA = 0xF0
S7_MAGIC, S7_PLUS_MAGIC = 0x32, 0x72
JOB, ACK, ACK_DATA, USERDATA = 1, 2, 3, 7

FUNCTIONS = {
    0x00: ('CPU Services', 'other'), 0x04: ('Read Var', 'read'), 0x05: ('Write Var', 'write'),
    0x1A: ('Request Download', 'program'), 0x1B: ('Download Block', 'program'), 0x1C: ('Download Ended', 'program'),
    0x1D: ('Start Upload', 'program'), 0x1E: ('Upload', 'program'), 0x1F: ('End Upload', 'program'),
    0x28: ('PI Service', 'control'), 0x29: ('PLC Stop', 'control'), 0xF0: ('Setup Communication', 'session'),
}
PI_SERVICES = {
    'P_PROGRAM': ('PLC Start (PI service P_PROGRAM)', 'control'), '_INSE': ('Activate Block (PI service _INSE)', 'program'),
    '_DELE': ('Delete Block (PI service _DELE)', 'program'), '_GARB': ('Compress Memory (PI service _GARB)', 'program'),
    '_MODU': ('Copy RAM to ROM (PI service _MODU)', 'program'), '_EXEC': ('Execute (PI service _EXEC)', 'control'),
}
SYMBOLIC_1200, DB_READ = 0xB2, 0xB0   # S7-1200/1500 symbolic addressing, and S7-400 DB reads
SYMBOLIC_DB = 0x8A0E
SYMBOLIC_AREAS = {0x50: 'Inputs', 0x51: 'Outputs', 0x52: 'Flags', 0x53: 'Counters', 0x54: 'Timers'}
AREAS = {0x03: 'System info', 0x05: 'System flags', 0x06: 'Analog inputs', 0x07: 'Analog outputs', 0x1C: 'Counters',
         0x1D: 'Timers', 0x1E: 'IEC counters', 0x1F: 'IEC timers', 0x80: 'Peripheral I/O', 0x81: 'Inputs',
         0x82: 'Outputs', 0x83: 'Flags', 0x84: 'Data blocks', 0x85: 'Instance data blocks', 0x86: 'Local data'}
# (user-data function group, subfunction) -> (name, kind), named as Wireshark names them
USERDATA_FUNCTIONS = {
    (1, 1): ('Request Diagnostic Data', 'diagnostic'), (1, 2): ('Variable Status', 'read'), (1, 8): ('Modify Variable', 'write'),
    (1, 13): ('Disable Job', 'diagnostic'), (1, 14): ('Enable Job', 'diagnostic'), (1, 15): ('Delete Job', 'diagnostic'),
    (1, 16): ('Read Job List', 'diagnostic'), (1, 19): ('Block Status', 'diagnostic'), (1, 22): ('Flash LED', 'diagnostic'),
    (2, 1): ('Cyclic Transfer', 'read'), (2, 4): ('Cyclic Transfer Unsubscribe', 'read'), (2, 5): ('Change Driven Transfer', 'read'),
    (2, 7): ('Change Driven Transfer Modify', 'read'), (2, 8): ('Read Data Record (RDREC)', 'read'),
    (3, 1): ('List Blocks', 'diagnostic'), (3, 2): ('List Blocks of Type', 'diagnostic'), (3, 3): ('Get Block Info', 'diagnostic'),
    (4, 1): ('Read SZL', 'diagnostic'), (4, 2): ('Message Service', 'diagnostic'), (4, 19): ('ALARM Query', 'diagnostic'),
    (5, 1): ('PLC Password', 'session'), (5, 2): ('Clear Password', 'session'),
    (7, 1): ('Read Clock', 'read'), (7, 2): ('Set Clock', 'write'), (7, 3): ('Read Clock (following)', 'read'),
    (7, 4): ('Set Clock', 'write'),
}
USERDATA_GROUPS = {0: ('Mode Transition', 'data'), 1: ('Programmer Command', 'diagnostic'), 2: ('Cyclic Data', 'read'),
                   3: ('Block Function', 'diagnostic'), 4: ('CPU Function', 'diagnostic'), 5: ('Security Function', 'session'),
                   6: ('PBC BSEND/BRECV', 'data'), 7: ('Time Function', 'other'), 15: ('NC Programming', 'program')}
SZL_NAMES = {0x0000: 'list of SZL IDs', 0x0011: 'module identification', 0x0111: 'module identification',
             0x001C: 'component identification', 0x011C: 'component identification', 0x0131: 'communication capabilities',
             0x0132: 'communication status', 0x0232: 'protection level', 0x0424: 'operating mode', 0x00A0: 'diagnostic buffer',
             0x0074: 'status LEDs', 0x0019: 'status LEDs', 0x0F14: 'system areas'}
# SZL 0x001C entry index -> property
COMPONENTS = {1: 'Name', 2: 'ModuleName', 3: 'PlantID', 5: 'Serial', 7: 'Model', 8: 'MemoryCardSerial', 11: 'Location'}
REQUEST, RESPONSE = 4, 8  # user-data parameter types

def frame_length(data):
    if data[0] != 0x03:
        return -1
    if len(data) < 4:
        return 0 if len(data) < 2 or data[1] == 0 else -1
    if data[1] != 0:
        return -1
    length = u16be(data, 2)
    return length if length >= 7 else -1

def decode(frame, out):
    if out.request is None or frame[5] & 0xF0 != COTP_DATA:
        return  # connection setup and teardown, or ISO traffic other than COTP data
    pdu = frame[5 + frame[4]:]
    if not pdu:
        return
    if pdu[0] == S7_PLUS_MAGIC:
        for ip, role in ((out.client, 'MASTER'), (out.server, 'SLAVE')):
            out.fact(ip, 'ICSProtocol', PLUS_PROTOCOL)
            out.fact(ip, 'Role', role)
        return
    if pdu[0] != S7_MAGIC or len(pdu) < 10:
        return  # MMS and other ISO protocols share port 102
    rosctr = pdu[1]
    header = 12 if rosctr in (ACK, ACK_DATA) else 10
    parameters_length, data_length = u16be(pdu, 6), u16be(pdu, 8)
    parameters = pdu[header:header + parameters_length]
    data = pdu[header + parameters_length:header + parameters_length + data_length]
    if rosctr not in (JOB, ACK, ACK_DATA, USERDATA):
        return
    out.roles('MASTER', 'SLAVE')
    if rosctr == JOB and parameters:
        # During a download the PLC sends the Download Block jobs, asking the station for each block; it is still
        # the station programming the PLC, so the operation is listed from client to server either way
        out.op(*_job(parameters), out.client, out.server)
    elif rosctr in (ACK, ACK_DATA):
        error_class, error_code = pdu[10], pdu[11]
        if error_class:
            name = FUNCTIONS.get(parameters[0], (f'Function 0x{parameters[0]:02X}',))[0] if parameters else 'a job'
            out.op(f'Error response to {name} (class 0x{error_class:02X}, code 0x{error_code:02X})', 'error', out.client, out.server)
    elif rosctr == USERDATA and len(parameters) >= 8:
        _userdata(parameters, data, out)

def _job(parameters):
    function = parameters[0]
    name, kind = FUNCTIONS.get(function, (f'Function 0x{function:02X}', 'other'))
    if function in (0x04, 0x05) and len(parameters) >= 2:
        areas = sorted(filter(None, map(_area, _items(parameters))))
        if areas:
            name = f'{name} ({", ".join(areas)})'
    elif function == 0x28:
        service = _pi_service(parameters)
        if service:
            name, kind = PI_SERVICES.get(service, (f'PI Service {service}', 'control'))
    return name, kind

def _items(parameters):
    """The address items of a Read Var or Write Var job, from their syntax ID on."""
    pos = 2
    for _ in range(parameters[1]):
        if pos + 2 > len(parameters) or parameters[pos] != 0x12:
            return
        length = parameters[pos + 1]
        yield parameters[pos + 2:pos + 2 + length]
        pos += 2 + length

def _area(item):
    """The memory area an address item reads or writes, or None if it can't be told."""
    if not item:
        return None
    if item[0] == 0x10 and len(item) >= 10:  # S7ANY: transport size, length, DB number, area, address
        return AREAS.get(item[6], f'area 0x{item[6]:02X}')
    if item[0] == SYMBOLIC_1200 and len(item) >= 6:  # reserved, root areas, CRC, substructures
        return 'Data blocks' if u16be(item, 2) == SYMBOLIC_DB else SYMBOLIC_AREAS.get(u16be(item, 4))
    if item[0] == DB_READ:
        return 'Data blocks'
    return None

def _pi_service(parameters):
    # function, 7 reserved bytes, parameter block length and block, then the service name with its length
    if len(parameters) >= 11:
        pos = 10 + u16be(parameters, 8)
        if pos < len(parameters):
            name = text(parameters[pos + 1:pos + 1 + parameters[pos]])
            if name:
                return name
    match = re.search(rb'(P_PROGRAM|_[A-Z]{4})', parameters)
    return match.group(1).decode() if match else None

def _userdata(parameters, data, out):
    method, kind_group, subfunction = parameters[4], parameters[5], parameters[6]
    kind, group = kind_group >> 4, kind_group & 0x0F
    if kind == REQUEST:
        group_name, group_kind = USERDATA_GROUPS.get(group, (f'Group {group}', 'other'))
        name, op_kind = USERDATA_FUNCTIONS.get((group, subfunction), (f'{group_name} {subfunction}', group_kind))
        if (group, subfunction) == (4, 1) and len(data) >= 8 and data[0] == 0xFF:
            szl = u16be(data, 4)
            name = f'Read SZL 0x{szl:04X}' + (f' ({SZL_NAMES[szl]})' if szl in SZL_NAMES else '')
        out.op(name, op_kind)
    elif kind == RESPONSE and (group, subfunction) == (4, 1) and len(parameters) >= 12:
        if u16be(parameters, 10) == 0 and len(data) >= 12 and data[0] == 0xFF:
            _szl(data, out)

def _szl(data, out):
    # return code, transport size, length; then SZL ID, index, entry length and count, and the entries
    szl, entry_length, count = u16be(data, 4), u16be(data, 8), u16be(data, 10)
    entries = [data[pos:pos + entry_length] for pos in range(12, 12 + entry_length * count, entry_length)
               if pos + entry_length <= len(data)] if entry_length else []
    if szl & 0xFF == 0x11 and entry_length >= 28:
        for entry in entries:
            index = u16be(entry, 0)
            if index == 1:
                order = text(entry[2:22])
                out.identity(out.src, 'OrderNumber', order)
                if order and order.startswith('6ES7'):
                    out.identity(out.src, 'Vendor', 'Siemens')
            elif index == 7 and entry[24] == ord('V'):
                out.identity(out.src, 'Firmware', f'V{entry[25]}.{entry[26]}.{entry[27]}')
    elif szl & 0xFF == 0x1C and entry_length >= 34:
        for entry in entries:
            name = COMPONENTS.get(u16be(entry, 0))
            if name:
                out.identity(out.src, name, text(entry[2:34]))
