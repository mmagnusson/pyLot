import logging
from parser.analysis import CaptureAnalyzer
from parser.fingerprint_loader import load_fingerprints
from parser.fingerprint_matcher import FingerprintEngine
from parser import zeek
from parser.packets import check_capture, read_capture

logger = logging.getLogger(__name__)

engine = FingerprintEngine(load_fingerprints())

def analyze_stream(stream, analyzer=None):
    """Feed every packet in a pcap/pcapng stream through analyzer (a new one if not given) and return it."""
    analyzer = analyzer or CaptureAnalyzer(engine)
    for pkt in read_capture(stream):
        analyzer.add(pkt)
    return analyzer

def parse_pcap(file_path):
    """
    Returns a CaptureAnalyzer holding the hosts, flows and fingerprint evidence in a capture file.
    Raises ValueError if the file isn't a readable pcap/pcapng capture, so callers can report it.
    """
    with open(file_path, 'rb') as f:
        analyzer = analyze_stream(f)
    logger.info("Analyzed %d packets from %s: %d hosts, %d flows", analyzer.packet_count, file_path,
                len(analyzer.hosts), len(analyzer.flows))
    return analyzer

def parse_zeek(file_path):
    """A CaptureAnalyzer holding the hosts and flows in a Zeek conn.log. Raises ValueError if it isn't one."""
    analyzer = CaptureAnalyzer(engine)
    for connection in zeek.read_conn_log(file_path):
        analyzer.add_connection(connection)
    logger.info("Analyzed %d connections from %s: %d hosts, %d flows", len(analyzer.flows), file_path,
                len(analyzer.hosts), len(analyzer.flows))
    return analyzer

def is_capture(path):
    with open(path, 'rb') as f:
        return f.read(4) in CAPTURE_MAGIC_NUMBERS

# First four bytes of pcap (both byte orders, micro- and nanosecond timestamps) and pcapng files
CAPTURE_MAGIC_NUMBERS = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a')

def check_file(path):
    """Raise ValueError unless path is a capture or Zeek conn.log pyLot can read."""
    if is_capture(path):
        check_capture(path)
    else:
        zeek.check_log(path)

def parse_file(path):
    """Analyze a capture or a Zeek conn.log, whichever path is."""
    return parse_pcap(path) if is_capture(path) else parse_zeek(path)
