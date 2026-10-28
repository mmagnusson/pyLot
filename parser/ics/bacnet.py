"""
BACnet/IP: BVLC and NPDU headers, the APDU service of each message, and the identity a device gives in
I-Am and in replies to ReadProperty and ReadPropertyMultiple for its Device object. Messages routed from
another BACnet network describe a device behind the router, not the address they came from, so they only
count as operations.
"""
from parser.ics.common import lookups, text, u16be

NAME = 'BACnet'
PROTOCOL = 'BACNET'  # as GRASSMARLIN's fingerprints spell it

CONFIRMED = {
    0: ('acknowledgeAlarm', 'control'), 1: ('confirmedCOVNotification', 'data'), 2: ('confirmedEventNotification', 'data'),
    3: ('getAlarmSummary', 'read'), 4: ('getEnrollmentSummary', 'read'), 5: ('subscribeCOV', 'read'),
    6: ('atomicReadFile', 'read'), 7: ('atomicWriteFile', 'write'), 8: ('addListElement', 'write'),
    9: ('removeListElement', 'write'), 10: ('createObject', 'write'), 11: ('deleteObject', 'write'),
    12: ('readProperty', 'read'), 13: ('readPropertyConditional', 'read'), 14: ('readPropertyMultiple', 'read'),
    15: ('writeProperty', 'write'), 16: ('writePropertyMultiple', 'write'), 17: ('deviceCommunicationControl', 'control'),
    18: ('confirmedPrivateTransfer', 'other'), 19: ('confirmedTextMessage', 'other'), 20: ('reinitializeDevice', 'control'),
    21: ('vtOpen', 'session'), 22: ('vtClose', 'session'), 23: ('vtData', 'other'), 24: ('authenticate', 'session'),
    25: ('requestKey', 'session'), 26: ('readRange', 'read'), 27: ('lifeSafetyOperation', 'control'),
    28: ('subscribeCOVProperty', 'read'), 29: ('getEventInformation', 'read'), 30: ('subscribeCOVPropertyMultiple', 'read'),
    31: ('confirmedCOVNotificationMultiple', 'data'), 32: ('confirmedAuditNotification', 'data'), 33: ('auditLogQuery', 'read'),
}
UNCONFIRMED = {
    0: ('i-Am', 'diagnostic'), 1: ('i-Have', 'diagnostic'), 2: ('unconfirmedCOVNotification', 'data'),
    3: ('unconfirmedEventNotification', 'data'), 4: ('unconfirmedPrivateTransfer', 'other'),
    5: ('unconfirmedTextMessage', 'other'), 6: ('timeSynchronization', 'write'), 7: ('who-Has', 'diagnostic'),
    8: ('who-Is', 'diagnostic'), 9: ('utcTimeSynchronization', 'write'), 10: ('writeGroup', 'write'),
    11: ('unconfirmedCOVNotificationMultiple', 'data'), 12: ('unconfirmedAuditNotification', 'data'),
    13: ('who-Am-I', 'diagnostic'), 14: ('you-Are', 'write'),
}
CONFIRMED_REQUEST, UNCONFIRMED_REQUEST, SIMPLE_ACK, COMPLEX_ACK, SEGMENT_ACK, ERROR, REJECT, ABORT = range(8)
I_AM, READ_PROPERTY, READ_PROPERTY_MULTIPLE = 0, 12, 14
DEVICE_OBJECT = 8
CHARACTER_STRING, UNSIGNED, OBJECT_IDENTIFIER = 7, 2, 12
# Device object properties that say what the device is
DEVICE_PROPERTIES = {121: 'Vendor', 120: 'Vendor', 70: 'Model', 44: 'Firmware', 12: 'Software', 77: 'Name', 58: 'Location'}
VENDOR_IDENTIFIER = 120

class Tag:
    __slots__ = ('number', 'context', 'marker', 'start', 'end')

    def __init__(self, number, context, marker, start, end):
        self.number, self.context, self.marker, self.start, self.end = number, context, marker, start, end

def frame_length(data):
    if data[0] != 0x81:
        return -1
    return len(data)  # one BVLC message per datagram

def read_tag(data, pos):
    first = data[pos]
    number, context, value = first >> 4, bool(first & 0x08), first & 0x07
    pos += 1
    if number == 15:
        number, pos = data[pos], pos + 1
    if context and value in (6, 7):
        return Tag(number, True, 'open' if value == 6 else 'close', pos, pos)
    if not context and number == 1:  # application-tagged boolean: the value is in the tag
        return Tag(number, False, None, pos, pos)
    if value == 5:
        value, pos = data[pos], pos + 1
        if value == 254:
            value, pos = u16be(data, pos), pos + 2
        elif value == 255:
            value, pos = int.from_bytes(data[pos:pos + 4], 'big'), pos + 4
    if pos + value > len(data):
        raise IndexError('tag runs past the end of the message')
    return Tag(number, context, None, pos, pos + value)

def _unsigned(data, tag):
    return int.from_bytes(data[tag.start:tag.end], 'big')

def _string(data, tag):
    encoding, value = data[tag.start], data[tag.start + 1:tag.end]
    if encoding == 4:  # UCS-2
        return text(value.decode('utf-16-be', 'replace'))
    if encoding == 0:  # UTF-8, though older devices send Latin-1 here too
        try:
            return text(value.decode('utf-8'))
        except UnicodeDecodeError:
            return text(value.decode('latin-1'))
    return text(value)

def decode(frame, out):
    function = frame[1]
    if function in (0x0A, 0x0B):        # original unicast and broadcast NPDUs
        npdu = frame[4:]
    elif function == 0x04:              # forwarded NPDU: the original sender's address comes first
        npdu = frame[10:]
    else:
        return
    if len(npdu) < 2 or npdu[0] != 0x01:
        return
    control, pos = npdu[1], 2
    if control & 0x20:
        pos += 3 + npdu[pos + 2]        # destination network, address length, address
    routed = bool(control & 0x08)
    if routed:
        pos += 3 + npdu[pos + 2]        # source network and address: sent on behalf of a device elsewhere
    if control & 0x20:
        pos += 1                        # hop count
    if control & 0x80:
        return                          # network-layer message, not an application one
    apdu = npdu[pos:]
    if not apdu:
        return
    pdu_type, segmented = apdu[0] >> 4, apdu[0] & 0x08
    out.fact(out.src, 'ICSProtocol', PROTOCOL)
    if pdu_type == CONFIRMED_REQUEST and len(apdu) >= 4:
        service = apdu[5] if segmented else apdu[3]
        out.op(*CONFIRMED.get(service, (f'Confirmed service {service}', 'other')))
        if not routed:
            out.fact(out.src, 'Role', 'CLIENT')
        if not control & 0x20:
            out.fact(out.dst, 'Role', 'SERVER')
    elif pdu_type == UNCONFIRMED_REQUEST and len(apdu) >= 2:
        service = apdu[1]
        out.op(*UNCONFIRMED.get(service, (f'Unconfirmed service {service}', 'other')))
        if service == I_AM and not routed:
            _i_am(apdu, 2, out)
    elif pdu_type == COMPLEX_ACK and len(apdu) >= 3 and not routed:
        service, body = (apdu[4], 5) if segmented else (apdu[2], 3)
        if segmented and apdu[2] != 0:
            return  # only the first segment starts at the beginning of the reply
        if service == READ_PROPERTY:
            _read_property_ack(apdu, body, out)
        elif service == READ_PROPERTY_MULTIPLE:
            _read_property_multiple_ack(apdu, body, out)
    elif pdu_type in (ERROR, REJECT, ABORT) and len(apdu) >= 3:
        if pdu_type == ERROR:
            service = CONFIRMED.get(apdu[2], (f'service {apdu[2]}',))[0]
            out.op(f'Error response to {service}', 'error', out.dst, out.src)
        else:
            out.op('Reject' if pdu_type == REJECT else 'Abort', 'error', out.dst, out.src)

def _i_am(apdu, pos, out):
    tag = read_tag(apdu, pos)
    if tag.context or tag.number != OBJECT_IDENTIFIER or tag.end - tag.start != 4:
        return
    object_id = _unsigned(apdu, tag)
    if object_id >> 22 != DEVICE_OBJECT:
        return
    out.identity(out.src, 'DeviceInstance', object_id & 0x3FFFFF)
    unsigned = []
    pos = tag.end
    while pos < len(apdu):                  # max APDU length, segmentation, vendor ID
        tag = read_tag(apdu, pos)
        if not tag.context and tag.number == UNSIGNED:
            unsigned.append(_unsigned(apdu, tag))
        pos = tag.end
    if len(unsigned) >= 2:
        out.identity(out.src, 'Vendor', lookups.name('BACNET', unsigned[1]))

def _device_property(apdu, object_id, prop, tag, out):
    if object_id >> 22 != DEVICE_OBJECT or prop not in DEVICE_PROPERTIES or tag.context:
        return
    if tag.number == CHARACTER_STRING and tag.end > tag.start:
        if prop != VENDOR_IDENTIFIER:
            out.identity(out.src, DEVICE_PROPERTIES[prop], _string(apdu, tag))
    elif tag.number == UNSIGNED and prop == VENDOR_IDENTIFIER:
        out.identity(out.src, 'Vendor', lookups.name('BACNET', _unsigned(apdu, tag)))

def _read_property_ack(apdu, pos, out):
    object_tag = read_tag(apdu, pos)
    property_tag = read_tag(apdu, object_tag.end)
    if (object_tag.number, property_tag.number) != (0, 1) or not object_tag.context:
        return
    tag = read_tag(apdu, property_tag.end)
    if tag.context and tag.number == 2:     # array index
        tag = read_tag(apdu, tag.end)
    if tag.marker == 'open' and tag.number == 3:
        _device_property(apdu, _unsigned(apdu, object_tag), _unsigned(apdu, property_tag), read_tag(apdu, tag.end), out)

def _read_property_multiple_ack(apdu, pos, out):
    while pos < len(apdu):
        object_tag = read_tag(apdu, pos)
        opening = read_tag(apdu, object_tag.end)
        if not object_tag.context or object_tag.number != 0 or opening.marker != 'open' or opening.number != 1:
            return
        object_id, pos = _unsigned(apdu, object_tag), opening.end
        prop = None
        while pos < len(apdu):
            tag = read_tag(apdu, pos)
            if tag.marker == 'close' and tag.number == 1:
                pos = tag.end
                break
            if tag.context and tag.number == 2 and not tag.marker:
                prop, pos = _unsigned(apdu, tag), tag.end
            elif tag.marker == 'open' and tag.number == 4:
                value = read_tag(apdu, tag.end)
                if prop is not None and not value.marker:
                    _device_property(apdu, object_id, prop, value, out)
                pos = _skip(apdu, tag.end, 4)
            elif tag.marker == 'open' and tag.number == 5:
                pos = _skip(apdu, tag.end, 5)   # an error for this property
            else:
                pos = tag.end

def _skip(apdu, pos, number):
    """Position after the closing tag that matches an opening tag numbered number."""
    depth = 1
    while pos < len(apdu):
        tag = read_tag(apdu, pos)
        if tag.marker == 'open':
            depth += 1
        elif tag.marker == 'close':
            depth -= 1
            if depth == 0 and tag.number == number:
                return tag.end
        pos = tag.end
    return pos
