import atexit
import logging
import re
import subprocess
import threading
import time
from contextlib import closing
import storage
from parser.analysis import CaptureAnalyzer
from parser.packets import read_capture
from parser.pcap_parser import engine

logger = logging.getLogger(__name__)

SAVE_INTERVAL = 2.0  # seconds between incremental saves

_running = {}  # session id -> dumpcap process, for captures in progress
_running_lock = threading.Lock()

def list_interfaces():
    """Interface names dumpcap can capture on. Raises RuntimeError with the reason if it can't list them."""
    try:
        result = subprocess.run(['dumpcap', '-D'], capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        raise RuntimeError("dumpcap isn't installed (it comes with Wireshark)")
    except PermissionError:
        raise RuntimeError("you aren't allowed to run dumpcap; join the wireshark group, then log out and back in")
    except OSError as e:
        raise RuntimeError(f"dumpcap couldn't be run: {e}")
    except subprocess.TimeoutExpired:
        raise RuntimeError('dumpcap took too long to list interfaces')
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f'dumpcap -D failed with exit code {result.returncode}')
    return [m.group(1) for line in result.stdout.splitlines() if (m := re.match(r'\s*\d+\.\s+(\S+)', line))]

def launch(interface, db_path, capture_filter=None):
    """Start capturing on interface in a background thread and return the new session's id."""
    with closing(storage.connect(db_path)) as conn:
        session_id = storage.create_session(conn, f'Live capture on {interface}', 'live', 'capturing')
    threading.Thread(target=start_live_capture, args=(interface, db_path, capture_filter, session_id), daemon=True).start()
    return session_id

def stop(session_id):
    """Stop a running capture. Returns False if session_id isn't capturing in this process."""
    with _running_lock:
        proc = _running.get(session_id)
    if proc is None:
        return False
    proc.terminate()
    return True

def is_running(session_id):
    with _running_lock:
        return session_id in _running

def start_live_capture(interface, db_path, capture_filter=None, session_id=None):
    """
    Capture on interface with dumpcap until it exits or is stopped, analyzing packets exactly like uploads
    and saving them to a 'live' session (a new one unless session_id is given) every few seconds.
    dumpcap needs capture rights (the wireshark group).
    """
    conn = storage.connect(db_path)
    if session_id is None:
        session_id = storage.create_session(conn, f'Live capture on {interface}', 'live', 'capturing')
    command = ['dumpcap', '-i', interface, '-P', '-q', '-w', '-'] + (['-f', capture_filter] if capture_filter else [])
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        logger.error("Could not start dumpcap: %s", e)
        storage.update_session(conn, session_id, status='failed', error=f'Could not start dumpcap: {e}')
        conn.close()
        return False
    atexit.register(proc.terminate)
    with _running_lock:
        _running[session_id] = proc
    logger.info("Started live capture on interface %s (session %d)", interface, session_id)

    analyzer = CaptureAnalyzer(engine)
    error = stream_error = None
    last_save = time.monotonic()
    try:
        for pkt in read_capture(proc.stdout):
            analyzer.add(pkt)
            if time.monotonic() - last_save >= SAVE_INTERVAL:
                storage.save_analysis(conn, session_id, analyzer, only_dirty=True)
                last_save = time.monotonic()
    except ValueError as e:
        # dumpcap wrote nothing usable: it failed to start, or was stopped before writing anything
        stream_error = str(e)
    except Exception as e:
        logger.exception("Live capture on %s failed", interface)
        error = str(e)
    finally:
        with _running_lock:
            _running.pop(session_id, None)
        proc.terminate()
        stderr = proc.communicate()[1].decode(errors='replace').strip()
        storage.save_analysis(conn, session_id, analyzer, only_dirty=True)
        # Exit codes decide failure; -15 is the SIGTERM sent when the capture is stopped
        if proc.returncode not in (0, -15):
            error = stderr or stream_error or f'dumpcap exited with code {proc.returncode}'
        storage.update_session(conn, session_id, status='failed' if error else 'stopped', error=error)
        conn.close()
    if error:
        logger.error("Live capture on %s failed: %s", interface, error)
        logger.error("Make sure Wireshark's dumpcap is installed and you're in the wireshark group")
        return False
    return True
