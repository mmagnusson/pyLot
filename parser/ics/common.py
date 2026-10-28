"""Pieces the protocol decoders share."""
from parser.fingerprint_matcher import Lookups

# What an operation does to the device it is sent to
KINDS = ('read', 'write', 'control', 'program', 'diagnostic', 'data', 'session', 'error', 'other')
# Decoded protocol traffic outranks GRASSMARLIN's port-and-byte fingerprints (mostly 4 and 5); what a device
# reports about itself when asked is as good as it gets
PROTOCOL_CONFIDENCE = 2
IDENTITY_CONFIDENCE = 1

lookups = Lookups()  # vendor and device-type names from parser/reference

def text(data):
    """Printable text from a fixed-width or length-prefixed field (bytes or str), or None when there is none."""
    value = data if isinstance(data, str) else bytes(data).decode('latin-1')
    value = value.split('\0', 1)[0]
    value = ''.join(c for c in value if c.isprintable()).strip()
    return value or None

def u16le(data, pos):
    return data[pos] | data[pos + 1] << 8

def u16be(data, pos):
    return data[pos] << 8 | data[pos + 1]

def u32le(data, pos):
    return int.from_bytes(data[pos:pos + 4], 'little') if pos + 4 <= len(data) else _short()

def _short():
    raise IndexError('field runs past the end of the message')
