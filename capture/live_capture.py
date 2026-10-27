import atexit
import logging
import subprocess
import time
import storage
from parser.analysis import CaptureAnalyzer
from parser.packets import read_capture
from parser.pcap_parser import engine

logger = logging.getLogger(__name__)

SAVE_INTERVAL = 2.0  # seconds between incremental saves

def start_live_capture(interface, db_path, capture_filter=None):
    """
    Capture on interface with dumpcap until it exits, analyzing packets exactly like uploads and saving
    them to a new 'live' session every few seconds. dumpcap needs capture rights (the wireshark group).
    """
    conn = storage.connect(db_path)
    session_id = storage.create_session(conn, f'Live capture on {interface}', 'live', 'capturing')
    command = ['dumpcap', '-i', interface, '-P', '-q', '-w', '-'] + (['-f', capture_filter] if capture_filter else [])
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        logger.error("Could not start dumpcap: %s", e)
        storage.update_session(conn, session_id, status='failed', error=f'Could not start dumpcap: {e}')
        return False
    atexit.register(proc.terminate)
    logger.info("Started live capture on interface %s (session %d)", interface, session_id)

    analyzer = CaptureAnalyzer(engine)
    error = None
    last_save = time.monotonic()
    try:
        for pkt in read_capture(proc.stdout):
            analyzer.add(pkt)
            if time.monotonic() - last_save >= SAVE_INTERVAL:
                storage.save_analysis(conn, session_id, analyzer, only_dirty=True)
                last_save = time.monotonic()
    except ValueError as e:
        # dumpcap wrote nothing usable, usually because it couldn't open the interface
        error = str(e)
    except Exception as e:
        logger.exception("Live capture on %s failed", interface)
        error = str(e)
    finally:
        proc.terminate()
        stderr = proc.communicate()[1].decode(errors='replace').strip()
        storage.save_analysis(conn, session_id, analyzer, only_dirty=True)
        if proc.returncode not in (0, -15) and stderr:
            error = stderr
        storage.update_session(conn, session_id, status='failed' if error else 'stopped', error=error)
        conn.close()
    if error:
        logger.error("Live capture on %s failed: %s", interface, error)
        logger.error("Make sure Wireshark's dumpcap is installed and you're in the wireshark group")
        return False
    return True
