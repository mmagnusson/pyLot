from flask import Flask, render_template, request, redirect, url_for, jsonify, abort
from werkzeug.utils import secure_filename
from parser.pcap_parser import parse_pcap
from capture.live_capture import start_live_capture
from urllib.parse import urlsplit
import argparse
import logging
import os
import sqlite3
import uuid
from threading import Thread

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'db.sqlite3')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
LOOPBACK_HOSTS = ('127.0.0.1', 'localhost')
# First four bytes of pcap (both byte orders, micro- and nanosecond timestamps) and pcapng files
CAPTURE_MAGIC_NUMBERS = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('PYLOT_MAX_UPLOAD_MB', '500')) * 1024 * 1024
# Requests whose Host header isn't listed get a 400, which blocks DNS rebinding attacks
app.config['TRUSTED_HOSTS'] = os.environ.get('PYLOT_TRUSTED_HOSTS', ','.join(LOOPBACK_HOSTS)).split(',')

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def init_database():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Create devices table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            mac TEXT,
            vendor TEXT
        )
    ''')

    # Create connections table (add fingerprint column)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src TEXT NOT NULL,
            dst TEXT NOT NULL,
            protocol TEXT,
            fingerprint TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

# Initialize database on startup
init_database()

@app.before_request
def reject_cross_site_posts():
    """Block cross-site request forgery: browsers send Origin (or at least Referer) on cross-site POSTs."""
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return
    source = request.headers.get('Origin') or request.headers.get('Referer')
    # No header at all means a non-browser client such as curl, which CSRF can't drive
    if source is not None and urlsplit(source).netloc != request.host:
        abort(403)

def upload_error(message, status=400):
    return render_template('index.html', error=message), status

@app.errorhandler(413)
def upload_too_large(e):
    return upload_error(f"That file is larger than the {app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)} MB upload limit "
                        "(set PYLOT_MAX_UPLOAD_MB to change it).", 413)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('pcap_file')
    if file is None or not file.filename:
        return upload_error('No file selected.')
    if file.stream.read(4) not in CAPTURE_MAGIC_NUMBERS:
        return upload_error('That file is not a PCAP or PCAPNG capture.')
    file.stream.seek(0)

    # Never trust the client's filename: sanitize it and add a random prefix so uploads can't
    # escape the upload folder or overwrite each other
    filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename) or 'capture.pcap'}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        devices, connections = parse_pcap(filepath)
    except Exception as e:
        logger.exception("Failed to parse %s", filepath)
        return upload_error(f'Could not parse that capture: {e}', 500)
    try:
        store_results(devices, connections)
    except sqlite3.Error as e:
        logger.exception("Failed to store results for %s", filepath)
        return upload_error(f'Parsed the capture but could not save the results: {e}', 500)
    return redirect(url_for('network'))

@app.route('/network')
def network():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT * FROM devices")
        devices = cur.fetchall()
        cur.execute("SELECT * FROM connections")
        connections = cur.fetchall()
        conn.close()
        return render_template('network.html', devices=devices, connections=connections)
    except Exception as e:
        logger.exception("Failed to load network data")
        return f'Database error: {str(e)}', 500, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/api/graph')
def get_graph():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT src, dst, protocol, fingerprint FROM connections")
        edges = cur.fetchall()
        conn.close()
        return jsonify([{'data': {'source': src, 'target': dst, 'label': proto, 'fingerprint': fp}} for src, dst, proto, fp in edges])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def store_results(devices, connections):
    """
    Replace the stored results with a new set of devices and connections.
    Runs as one transaction: on error nothing changes and the sqlite3.Error propagates.
    """
    conn = sqlite3.connect(DB_PATH)
    try:
        with conn:
            conn.execute("DELETE FROM devices")
            conn.execute("DELETE FROM connections")
            conn.executemany("INSERT INTO devices(ip, mac, vendor) VALUES (?, ?, ?) ON CONFLICT(ip) DO NOTHING", devices)
            conn.executemany("INSERT INTO connections(src, dst, protocol, fingerprint) VALUES (?, ?, ?, ?)", connections)
    finally:
        conn.close()

def parse_args():
    parser = argparse.ArgumentParser(description='pyLot passive ICS network mapper')
    parser.add_argument('--host', default='127.0.0.1', help='address to listen on (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='port to listen on (default: 5000)')
    parser.add_argument('--capture-interface', metavar='IFACE',
                        help='also capture live traffic on this interface (off by default)')
    parser.add_argument('--debug', action='store_true',
                        help='enable the Flask debugger and auto-reload (never on a shared network)')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format='%(asctime)s %(levelname)s %(name)s: %(message)s')

    if args.host not in LOOPBACK_HOSTS:
        logger.warning("Listening on %s. pyLot has no authentication: anyone who can reach this address can use it.", args.host)
        if args.host not in ('0.0.0.0', '::') and 'PYLOT_TRUSTED_HOSTS' not in os.environ:
            app.config['TRUSTED_HOSTS'].append(args.host)

    # With --debug the reloader runs this file twice; only capture in the process that serves requests
    if args.capture_interface and (not args.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true'):
        Thread(target=start_live_capture, args=(args.capture_interface, DB_PATH), daemon=True).start()

    app.run(host=args.host, port=args.port, debug=args.debug)
