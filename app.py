from flask import Flask, render_template, request, redirect, url_for, jsonify, abort
from werkzeug.utils import secure_filename
from parser.pcap_parser import parse_pcap
from capture.live_capture import start_live_capture
from contextlib import closing
from urllib.parse import urlsplit
import argparse
import logging
import os
import sqlite3
import uuid
from threading import Thread
import storage

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('PYLOT_DB_PATH', os.path.join(BASE_DIR, 'pylot.sqlite3'))
UPLOAD_FOLDER = os.environ.get('PYLOT_UPLOAD_FOLDER', os.path.join(BASE_DIR, 'uploads'))
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

# Initialize database on startup
storage.init_db(DB_PATH)

def db():
    return closing(storage.connect(DB_PATH))

@app.before_request
def reject_cross_site_posts():
    """Block cross-site request forgery: browsers send Origin (or at least Referer) on cross-site POSTs."""
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return
    source = request.headers.get('Origin') or request.headers.get('Referer')
    # No header at all means a non-browser client such as curl, which CSRF can't drive
    if source is not None and urlsplit(source).netloc != request.host:
        abort(403)

def index_error(message, status=400):
    with db() as conn:
        sessions = storage.list_sessions(conn)
    return render_template('index.html', error=message, sessions=sessions), status

@app.errorhandler(413)
def upload_too_large(e):
    return index_error(f"That file is larger than the {app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)} MB upload limit "
                       "(set PYLOT_MAX_UPLOAD_MB to change it).", 413)

@app.route('/')
def index():
    with db() as conn:
        return render_template('index.html', sessions=storage.list_sessions(conn))

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('pcap_file')
    if file is None or not file.filename:
        return index_error('No file selected.')
    if file.stream.read(4) not in CAPTURE_MAGIC_NUMBERS:
        return index_error('That file is not a PCAP or PCAPNG capture.')
    file.stream.seek(0)

    # Never trust the client's filename: sanitize it and add a random prefix so uploads can't
    # escape the upload folder or overwrite each other
    filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename) or 'capture.pcap'}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        analyzer = parse_pcap(filepath)
    except Exception as e:
        logger.exception("Failed to parse %s", filepath)
        os.remove(filepath)
        return index_error(f'Could not parse that capture: {e}', 400 if isinstance(e, ValueError) else 500)
    with db() as conn:
        session_id = storage.create_session(conn, file.filename[:200], 'upload', 'ready', capture_file=filename)
        try:
            storage.save_analysis(conn, session_id, analyzer)
        except sqlite3.Error as e:
            logger.exception("Failed to store results for %s", filepath)
            storage.delete_session(conn, session_id)
            os.remove(filepath)
            return index_error(f'Parsed the capture but could not save the results: {e}', 500)
    return redirect(url_for('session_view', session_id=session_id))

@app.route('/sessions/<int:session_id>')
def session_view(session_id):
    with db() as conn:
        session = storage.get_session(conn, session_id)
    if session is None:
        abort(404)
    return render_template('network.html', session=session)

@app.route('/sessions/<int:session_id>/delete', methods=['POST'])
def delete_session(session_id):
    with db() as conn:
        session = storage.get_session(conn, session_id)
        if session is None:
            abort(404)
        if session['status'] == 'capturing':
            return index_error('That session is still capturing. Stop pyLot before deleting it.', 409)
        storage.delete_session(conn, session_id)
    if session['capture_file']:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(session['capture_file'])))
        except FileNotFoundError:
            pass
    return redirect(url_for('index'))

@app.route('/network')
def network():
    """Old single-result URL: show the newest session."""
    with db() as conn:
        sessions = storage.list_sessions(conn)
    return redirect(url_for('session_view', session_id=sessions[0]['id']) if sessions else url_for('index'))

@app.route('/api/sessions/<int:session_id>/graph')
def session_graph(session_id):
    with db() as conn:
        session = storage.get_session(conn, session_id)
        if session is None:
            return jsonify({'error': 'No such session'}), 404
        return jsonify({'session': session, **storage.session_graph(conn, session_id)})

def parse_args():
    parser = argparse.ArgumentParser(description='pyLot passive ICS network mapper')
    parser.add_argument('--host', default='127.0.0.1', help='address to listen on (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='port to listen on (default: 5000)')
    parser.add_argument('--capture-interface', metavar='IFACE',
                        help='also capture live traffic on this interface (off by default)')
    parser.add_argument('--capture-filter', metavar='BPF',
                        help='only capture traffic matching this capture filter, e.g. "not port 22"')
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
        Thread(target=start_live_capture, args=(args.capture_interface, DB_PATH, args.capture_filter), daemon=True).start()

    app.run(host=args.host, port=args.port, debug=args.debug)
