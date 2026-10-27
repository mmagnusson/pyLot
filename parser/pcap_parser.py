import logging
from parser.analysis import CaptureAnalyzer
from parser.fingerprint_loader import load_fingerprints
from parser.fingerprint_matcher import FingerprintEngine
from parser.packets import read_capture

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
