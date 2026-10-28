"""
EtherNet/IP encapsulation and the CIP requests it carries: List Identity replies, explicit messages
(including Unconnected Send and Multiple Service Packet, unwrapped), Logix tag services and the identity
a device returns for Get_Attributes_All on its Identity object. CIP replies don't repeat what they answer,
so requests are remembered per connection until their reply arrives.
"""
from parser.ics.common import lookups, text, u16le, u32le

NAME = 'EtherNet/IP'
PROTOCOL = 'ETHERNETIP'  # as GRASSMARLIN's fingerprints spell it
STATEFUL = True

COMMANDS = {0x0000: 'NOP', 0x0004: 'List Services', 0x0063: 'List Identity', 0x0064: 'List Interfaces',
            0x0065: 'Register Session', 0x0066: 'Unregister Session', 0x006F: 'SendRRData', 0x0070: 'SendUnitData',
            0x0072: 'Indicate Status', 0x0073: 'Cancel'}
COMMAND_KINDS = {0x0004: 'diagnostic', 0x0063: 'diagnostic', 0x0064: 'diagnostic', 0x0065: 'session', 0x0066: 'session'}
LIST_IDENTITY, SEND_RR_DATA, SEND_UNIT_DATA = 0x0063, 0x006F, 0x0070
IDENTITY_ITEM, CONNECTED_DATA, UNCONNECTED_DATA = 0x000C, 0x00B1, 0x00B2

SERVICES = {
    0x01: ('Get_Attributes_All', 'read'), 0x02: ('Set_Attributes_All', 'write'), 0x03: ('Get_Attribute_List', 'read'),
    0x04: ('Set_Attribute_List', 'write'), 0x05: ('Reset', 'control'), 0x06: ('Start', 'control'), 0x07: ('Stop', 'control'),
    0x08: ('Create', 'write'), 0x09: ('Delete', 'write'), 0x0A: ('Multiple_Service_Packet', 'other'),
    0x0D: ('Apply_Attributes', 'write'), 0x0E: ('Get_Attribute_Single', 'read'), 0x10: ('Set_Attribute_Single', 'write'),
    0x11: ('Find_Next_Object_Instance', 'read'), 0x15: ('Restore', 'program'), 0x16: ('Save', 'program'),
    0x17: ('No_Operation', 'other'), 0x18: ('Get_Member', 'read'), 0x19: ('Set_Member', 'write'),
    0x1A: ('Insert_Member', 'write'), 0x1B: ('Remove_Member', 'write'), 0x1C: ('Group_Sync', 'other'),
}
# Object-specific services, by class
CONNECTION_MANAGER, FILE_OBJECT, PCCC_OBJECT, SYMBOL_OBJECT = 0x06, 0x37, 0x67, 0x6B
CLASS_SERVICES = {
    CONNECTION_MANAGER: {0x4E: ('Forward_Close', 'session'), 0x52: ('Unconnected_Send', 'other'), 0x54: ('Forward_Open', 'session'),
                         0x56: ('Get_Connection_Data', 'read'), 0x57: ('Search_Connection_Data', 'read'),
                         0x5A: ('Get_Connection_Owner', 'read'), 0x5B: ('Large_Forward_Open', 'session')},
    FILE_OBJECT: {0x4B: ('Initiate_Upload', 'program'), 0x4C: ('Initiate_Download', 'program'),
                  0x4D: ('Initiate_Partial_Read', 'read'), 0x4E: ('Initiate_Partial_Write', 'write'),
                  0x4F: ('Upload_Transfer', 'program'), 0x50: ('Download_Transfer', 'program'), 0x51: ('Clear_File', 'program')},
    PCCC_OBJECT: {0x4B: ('Execute PCCC', 'other')},
}
# Rockwell Logix controllers: services addressed to a tag name or the Symbol object
LOGIX_SERVICES = {0x4C: ('Read Tag', 'read'), 0x4D: ('Write Tag', 'write'), 0x4E: ('Read Modify Write Tag', 'write'),
                  0x52: ('Read Tag Fragmented', 'read'), 0x53: ('Write Tag Fragmented', 'write'),
                  0x55: ('Get Instance Attribute List', 'read')}
CLASSES = {0x01: 'Identity', 0x02: 'Message Router', 0x04: 'Assembly', 0x06: 'Connection Manager', 0x37: 'File',
           0x47: 'Device Level Ring', 0x48: 'QoS', 0x67: 'PCCC', 0x6B: 'Symbol', 0x6C: 'Template', 0xF4: 'Port',
           0xF5: 'TCP/IP Interface', 0xF6: 'Ethernet Link'}
STATUSES = {0x01: 'connection failure', 0x02: 'resource unavailable', 0x03: 'invalid parameter value',
            0x04: 'path segment error', 0x05: 'path destination unknown', 0x08: 'service not supported',
            0x09: 'invalid attribute value', 0x0C: 'object state conflict', 0x0E: 'attribute not settable',
            0x0F: 'privilege violation', 0x10: 'device state conflict', 0x11: 'reply data too large',
            0x13: 'not enough data', 0x14: 'attribute not supported', 0x15: 'too much data', 0x16: 'object does not exist',
            0x1E: 'embedded service error', 0x20: 'invalid parameter', 0x26: 'path size invalid'}
PARTIAL_TRANSFER = 0x06  # more data follows: a success
IDENTITY_CLASS = 0x01
MAX_PENDING = 1000  # requests awaiting replies, per connection
# Identity object attributes, for Get_Attribute_Single replies
IDENTITY_ATTRIBUTES = {1: 'vendor', 2: 'device type', 3: 'product code', 4: 'revision', 6: 'serial', 7: 'product name'}

class Request:
    __slots__ = ('service', 'cls', 'attribute', 'slot', 'name', 'kind')

    def __init__(self, service, cls, attribute, slot, name, kind):
        self.service, self.cls, self.attribute, self.slot = service, cls, attribute, slot
        self.name, self.kind = name, kind

def frame_length(data):
    if len(data) < 2:
        return 0
    if u16le(data, 0) not in COMMANDS:
        return -1
    if len(data) < 4:
        return 0
    return 24 + u16le(data, 2)

def decode(frame, out):
    command, length, status = u16le(frame, 0), u16le(frame, 2), u32le(frame, 8)
    context, body = frame[12:20], frame[24:24 + length]
    if command == LIST_IDENTITY:
        if out.request is not False:
            out.op('List Identity', 'diagnostic')
        if out.request is not True and status == 0:
            for item_type, item in _items(body, 0):
                if item_type == IDENTITY_ITEM and len(item) >= 18:
                    out.fact(out.src, 'ICSProtocol', PROTOCOL)
                    _identity(item[18:], out, out.src)
        return
    if out.request is None:
        return
    out.roles('CLIENT', 'SERVER')
    if command in COMMAND_KINDS and out.request:
        out.op(COMMANDS[command], COMMAND_KINDS[command])
    if command not in (SEND_RR_DATA, SEND_UNIT_DATA) or len(body) < 8:
        return
    for item_type, item in _items(body, 6):  # after the interface handle and timeout
        if item_type == UNCONNECTED_DATA and item:
            _message(item, ('rr', context), out)
        elif item_type == CONNECTED_DATA and len(item) > 2:
            _message(item[2:], ('unit', u16le(item, 0)), out)  # replies echo the request's sequence count

def _items(body, pos):
    """The common packet format items: (type, data)."""
    count, pos = u16le(body, pos), pos + 2
    for _ in range(count):
        if pos + 4 > len(body):
            return
        item_type, length = u16le(body, pos), u16le(body, pos + 2)
        yield item_type, body[pos + 4:pos + 4 + length]
        pos += 4 + length

def _message(message, key, out):
    pending = out.state.setdefault('pending', {})
    if out.request:
        requests = list(_requests(message, None))
        for request in requests:
            out.op(request.name, request.kind)
        if requests:
            if len(pending) >= MAX_PENDING:
                pending.clear()  # replies that never came
            pending[key] = requests
    else:
        requests = pending.pop(key, None)
        _reply(message, requests, out)

def _requests(message, slot):
    """The requests a CIP message makes, with Unconnected Send and Multiple Service Packet unwrapped."""
    if len(message) < 2 or message[0] & 0x80:
        return
    service, words = message[0], message[1]
    path, rest = message[2:2 + 2 * words], message[2 + 2 * words:]
    cls, instance, attribute, symbolic = _path(path)
    if service == 0x52 and cls == CONNECTION_MANAGER and len(rest) >= 4:
        size = u16le(rest, 2)
        embedded = rest[4:4 + size]
        route = rest[4 + size + (size & 1):]
        yield from _requests(embedded, _slot(route[2:2 + 2 * route[0]]) if route else None)
        return
    if service == 0x0A and len(rest) >= 2:
        count = u16le(rest, 0)
        offsets = [u16le(rest, 2 + 2 * i) for i in range(count) if 4 + 2 * i <= len(rest)]
        for start, end in zip(offsets, offsets[1:] + [len(rest)]):
            yield from _requests(rest[start:end], slot)
        return
    yield Request(service, cls, attribute, slot, *_describe(service, cls, symbolic))

def _describe(service, cls, symbolic):
    """(name, kind) of a request."""
    target = CLASSES.get(cls, f'class 0x{cls:02X}') if cls is not None else ('tag' if symbolic else None)
    if service in SERVICES:
        name, kind = SERVICES[service]
        return (f'{name} {target}' if target else name), kind
    if (symbolic or cls in (SYMBOL_OBJECT, None)) and service in LOGIX_SERVICES:
        return LOGIX_SERVICES[service]
    if service in CLASS_SERVICES.get(cls, {}):
        return CLASS_SERVICES[cls][service]
    # Vendor-specific: the service code means different things on different objects
    return f'Service 0x{service:02X}' + (f' {target}' if target else ''), 'other'

def _path(path):
    """(class, instance, attribute, has a symbolic segment) from a padded EPATH."""
    cls = instance = attribute = None
    symbolic, pos = False, 0
    while pos < len(path):
        segment = path[pos]
        if segment in (0x20, 0x24, 0x30, 0x28, 0x2C):
            value, pos = path[pos + 1], pos + 2
        elif segment in (0x21, 0x25, 0x31, 0x29, 0x2D):
            value, pos = u16le(path, pos + 2), pos + 4
        elif segment == 0x91:  # ANSI extended symbol: a tag name
            symbolic = True
            pos += 2 + path[pos + 1] + (path[pos + 1] & 1)
            continue
        else:
            break
        if segment in (0x20, 0x21):
            cls = value
        elif segment in (0x24, 0x25):
            instance = value
        elif segment in (0x30, 0x31):
            attribute = value
    return cls, instance, attribute, symbolic

def _slot(route):
    """The backplane slot a route path ends at, when it is a single backplane hop."""
    if len(route) >= 2 and route[0] == 0x01:  # port 1 (backplane), one-byte link address
        return route[1]
    return None

def _reply(message, requests, out):
    if len(message) < 4 or not message[0] & 0x80:
        return
    service, status, extended = message[0] & 0x7F, message[2], message[3]
    data = message[4 + 2 * extended:]
    request = requests[0] if requests and len(requests) == 1 else None
    if service == 0x0A and requests and len(requests) > 1 and status in (0, 0x1E) and len(data) >= 2:
        count = u16le(data, 0)
        offsets = [u16le(data, 2 + 2 * i) for i in range(count) if 4 + 2 * i <= len(data)]
        for inner, start, end in zip(requests, offsets, offsets[1:] + [len(data)]):
            _reply(data[start:end], [inner], out)
        return
    if status not in (0, PARTIAL_TRANSFER):
        name = request.name if request else f'service 0x{service:02X}'
        out.op(f'Error response to {name}: {STATUSES.get(status, f"status 0x{status:02X}")}', 'error', out.client, out.server)
        return
    if request is None or request.cls != IDENTITY_CLASS or request.service != service:
        return
    if service == 0x01:
        _identity(data, out, out.src, request.slot)
    elif service == 0x0E and request.attribute in IDENTITY_ATTRIBUTES and request.slot is None:
        _attribute(request.attribute, data, out)

def _identity(data, out, ip, slot=None):
    """Identity object attributes 1 to 7, as List Identity and Get_Attributes_All return them."""
    if len(data) < 15:
        return
    vendor, device_type, product_code = u16le(data, 0), u16le(data, 2), u16le(data, 4)
    major, minor, serial = data[6], data[7], u32le(data, 10)
    product = text(data[15:15 + data[14]])
    firmware = f'{major}.{minor:03d}'
    if slot is not None:
        # Asked through the backplane: a module in the chassis, not the device at this address
        out.identity(ip, 'Module', f'slot {slot}: {product or "?"} (firmware {firmware})')
        return
    out.identity(ip, 'Vendor', lookups.name('ENIPVENDOR', vendor))
    out.identity(ip, 'DeviceType', lookups.name('ENIPDEVICE', device_type))
    out.identity(ip, 'ProductCode', product_code)
    out.identity(ip, 'Firmware', firmware)
    out.identity(ip, 'Serial', f'0x{serial:08X}')
    out.identity(ip, 'Product', product)

def _attribute(attribute, data, out):
    if attribute == 1 and len(data) >= 2:
        out.identity(out.src, 'Vendor', lookups.name('ENIPVENDOR', u16le(data, 0)))
    elif attribute == 2 and len(data) >= 2:
        out.identity(out.src, 'DeviceType', lookups.name('ENIPDEVICE', u16le(data, 0)))
    elif attribute == 3 and len(data) >= 2:
        out.identity(out.src, 'ProductCode', u16le(data, 0))
    elif attribute == 4 and len(data) >= 2:
        out.identity(out.src, 'Firmware', f'{data[0]}.{data[1]:03d}')
    elif attribute == 6 and len(data) >= 4:
        out.identity(out.src, 'Serial', f'0x{u32le(data, 0):08X}')
    elif attribute == 7 and data:
        out.identity(out.src, 'Product', text(data[1:1 + data[0]]))
