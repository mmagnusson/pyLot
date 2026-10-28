"""
Decode industrial protocols far enough to say what each conversation does and what devices say about
themselves. Every request a client sends becomes an operation (Modbus Write Single Register, S7 PLC Stop,
DNP3 Direct Operate...) with a kind that says what sort of thing it does to the server: read, write,
control, program, diagnostic, data, session, error or other. Operations are listed from the conversation's
client to its server, including the errors and data the server sends back. Identity replies (Modbus Read Device
Identification, EtherNet/IP List Identity, S7 module identification, BACnet device properties, SNMP
system description) become properties of the host that sent them: Vendor, Model, Firmware, Serial...

Decoders only trust what they can check: a message has to parse as its protocol (including the DNP3 link
CRC) before anything is reported, so other traffic that happens to use the same port is ignored.
"""
from parser.ics import bacnet, banners, dnp3, enip, iec104, modbus, s7
from parser.ics.common import IDENTITY_CONFIDENCE, KINDS, PROTOCOL_CONFIDENCE

TCP_SERVICES = {502: modbus, 20000: dnp3, 102: s7, 44818: enip, 2404: iec104}
UDP_SERVICES = {502: modbus, 20000: dnp3, 44818: enip, 47808: bacnet}
TCP_BANNERS = {**{port: banners.http for port in banners.HTTP_PORTS}, 21: banners.ftp, 22: banners.ssh}
SEQ_MASK = 0xFFFFFFFF
MAX_BUFFER = 65536           # bytes of an unfinished message kept per TCP direction
MAX_PENDING = 10000          # requests waiting for a reply, per capture

class Output:
    """Collects what one message says. Decoders call op(), roles() and fact()."""
    __slots__ = ('src', 'dst', 'request', 'module', 'state', 'operations', 'facts')

    def __init__(self, pkt, request, module, state):
        self.src, self.dst = pkt.src_ip, pkt.dst_ip
        self.request = request   # sent to the service port; None when the port doesn't say (both ends use it)
        self.module = module
        self.state = state       # per-conversation dict a decoder may keep things in, such as requests awaiting replies
        self.operations = []
        self.facts = []

    @property
    def client(self):
        return self.src if self.request else self.dst

    @property
    def server(self):
        return self.dst if self.request else self.src

    def op(self, name, kind, src=None, dst=None):
        self.operations.append((src or self.src, dst or self.dst, self.module.NAME, name, kind))

    def fact(self, ip, name, value, confidence=PROTOCOL_CONFIDENCE):
        if value is not None and value != '':
            self.facts.append((ip, f'{self.module.NAME} decoder', name, str(value), confidence))

    def identity(self, ip, name, value):
        self.fact(ip, name, value, IDENTITY_CONFIDENCE)

    def roles(self, client_role, server_role, client=None, server=None):
        """The conversation's two ends, by default from the port direction, and the protocol they speak."""
        for ip, role in ((client or self.client, client_role), (server or self.server, server_role)):
            self.fact(ip, 'ICSProtocol', self.module.PROTOCOL)
            self.fact(ip, 'Role', role)

class _Stream:
    __slots__ = ('next_seq', 'buffer')

    def __init__(self, next_seq):
        self.next_seq = next_seq
        self.buffer = b''

class Decoder:
    """
    Decodes the protocol messages in one capture's packets. TCP streams are reassembled per direction, so a
    message split over segments, or several in one segment, decode as captured; retransmitted bytes are
    dropped, and after a gap decoding picks up at the next segment that starts a message.
    """

    def __init__(self):
        self._streams = {}       # (src, dst, src port, dst port) -> _Stream
        self._states = {}        # (client, server, client port, server port, protocol) -> decoder state
        self._pending = 0

    def decode(self, pkt):
        """(operations, facts) for one packet: operations are (src, dst, protocol, name, kind) and facts are
        (ip, source, property, value, confidence)."""
        if pkt.src_port is None or (not pkt.payload and pkt.transport != 6):
            return (), ()
        if pkt.transport == 6:
            module, request = self._service(TCP_SERVICES, pkt)
            if module is None:
                banner = TCP_BANNERS.get(pkt.src_port)
                if banner is None or not pkt.payload:
                    return (), ()
                out = Output(pkt, False, banner, None)
                banner.decode(pkt.payload, out)
                return out.operations, out.facts
            frames = self._reassemble(pkt, module)
        elif pkt.transport == 17:
            module, request = self._service(UDP_SERVICES, pkt)
            if module is None:
                if pkt.src_port == 161 or pkt.dst_port == 161:
                    out = Output(pkt, pkt.dst_port == 161, banners.snmp, None)
                    banners.snmp.decode(pkt.payload, out)
                    return out.operations, out.facts
                return (), ()
            frames = _split(pkt.payload, module)
        else:
            return (), ()
        if not frames:
            return (), ()
        state = self._state(pkt, module, request) if getattr(module, 'STATEFUL', False) else None
        out = Output(pkt, request, module, state)
        for frame in frames:
            try:
                module.decode(frame, out)
            except (IndexError, ValueError, KeyError):
                pass  # a malformed message: keep whatever it said before going wrong
        return out.operations, out.facts

    @staticmethod
    def _service(services, pkt):
        if pkt.dst_port in services:
            module = services[pkt.dst_port]
            return module, None if pkt.src_port == pkt.dst_port else True
        if pkt.src_port in services:
            return services[pkt.src_port], False
        return None, None

    def _state(self, pkt, module, request):
        if request is False:
            key = (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, module.NAME)
        else:
            key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, module.NAME)
        state = self._states.get(key)
        if state is None:
            if len(self._states) >= MAX_PENDING:
                self._states.clear()  # replies that never came; don't let them pile up
            state = self._states[key] = {}
        return state

    def _reassemble(self, pkt, module):
        if pkt.seq is None:  # no sequence number to reassemble by: the segment on its own
            return _split(pkt.payload, module)
        key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port)
        flags = pkt.tcp_flags or 0
        if flags & 0x02:  # SYN: a new connection
            self._streams[key] = _Stream((pkt.seq + 1) & SEQ_MASK)
            return []
        data = pkt.payload
        stream = self._streams.get(key)
        if stream is None:
            stream = self._streams[key] = _Stream(pkt.seq)
        offset = (stream.next_seq - pkt.seq) & SEQ_MASK
        if offset and offset < 0x80000000:  # starts with bytes already seen
            if offset >= len(data):
                return []
            data = data[offset:]
        elif offset:                         # bytes went missing: what's buffered can't be finished
            stream.buffer = b''
        if data:
            stream.next_seq = (pkt.seq + len(pkt.payload)) & SEQ_MASK
        frames, rest = _frames(stream.buffer + data, module)
        stream.buffer = rest if len(rest) <= MAX_BUFFER else b''
        if flags & 0x05:  # FIN or RST
            self._streams.pop(key, None)
        return frames

def _frames(data, module):
    """Split data into whole messages: (messages, the unfinished rest)."""
    frames = []
    while data:
        length = module.frame_length(data)
        if length < 0:
            return frames, b''               # not a message start: wait for one at the next segment
        if length == 0 or length > len(data):
            break
        frames.append(data[:length])
        data = data[length:]
    return frames, data

def _split(datagram, module):
    frames, _ = _frames(datagram, module)
    return frames
