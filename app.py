from flask import Flask, Response, render_template, request, redirect, url_for, jsonify, abort
from werkzeug.utils import secure_filename
from parser.packets import check_capture
from parser.pcap_parser import parse_pcap
from capture import live_capture
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from urllib.parse import urlsplit
import argparse
import csv
import io
import logging
import os
import sqlite3
import uuid
import storage

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('PYLOT_DB_PATH', os.path.join(BASE_DIR, 'pylot.sqlite3'))
UPLOAD_FOLDER = os.environ.get('PYLOT_UPLOAD_FOLDER', os.path.join(BASE_DIR, 'uploads'))
LOOPBACK_HOSTS = ('127.0.0.1', 'localhost')
# First four bytes of pcap (both byte orders, micro- and nanosecond timestamps) and pcapng files
CAPTURE_MAGIC_NUMBERS = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a')
MAX_PAGE_SIZE = 1000
MAX_CAPTURE_FILTER_LENGTH = 500

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('PYLOT_MAX_UPLOAD_MB', '500')) * 1024 * 1024
# Requests whose Host header isn't listed get a 400, which blocks DNS rebinding attacks
app.config['TRUSTED_HOSTS'] = os.environ.get('PYLOT_TRUSTED_HOSTS', ','.join(LOOPBACK_HOSTS)).split(',')

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize database on startup
storage.init_db(DB_PATH)

# Uploads are analyzed one at a time in the background, so requests return immediately
analysis_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='analysis')

def submit(fn, *args):
    analysis_pool.submit(fn, *args)

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
        check_capture(filepath)
    except ValueError as e:
        os.remove(filepath)
        return index_error(f'Could not read that capture: {e}')

    with db() as conn:
        session_id = storage.create_session(conn, file.filename[:200], 'upload', 'processing', capture_file=filename)
    submit(analyze_upload, session_id, filepath)
    return redirect(url_for('session_view', session_id=session_id))

def analyze_upload(session_id, filepath):
    """Background job: analyze an uploaded capture into its session, marking it ready or failed."""
    with db() as conn:
        try:
            analyzer = parse_pcap(filepath)
            storage.save_analysis(conn, session_id, analyzer)
            storage.update_session(conn, session_id, status='ready')
        except Exception as e:
            logger.exception("Failed to analyze %s", filepath)
            storage.update_session(conn, session_id, status='failed', error=f'Could not analyze this capture: {e}',
                                   capture_file=None)
            try:
                os.remove(filepath)
            except FileNotFoundError:
                pass

@app.route('/captures', methods=['POST'])
def start_capture():
    interface = request.form.get('interface', '')
    capture_filter = request.form.get('capture_filter', '').strip()
    try:
        interfaces = live_capture.list_interfaces()
    except RuntimeError as e:
        return index_error(f'Live capture is unavailable: {e}', 503)
    if interface not in interfaces:
        return index_error('Choose one of the listed interfaces.')
    if len(capture_filter) > MAX_CAPTURE_FILTER_LENGTH:
        return index_error('That capture filter is too long.')
    session_id = live_capture.launch(interface, DB_PATH, capture_filter or None)
    return redirect(url_for('session_view', session_id=session_id))

@app.route('/sessions/<int:session_id>')
def session_view(session_id):
    with db() as conn:
        session = storage.get_session(conn, session_id)
    if session is None:
        abort(404)
    return render_template('network.html', session=session)

@app.route('/sessions/<int:session_id>/stop', methods=['POST'])
def stop_capture(session_id):
    with db() as conn:
        session = storage.get_session(conn, session_id)
        if session is None:
            abort(404)
        if not live_capture.stop(session_id) and session['status'] == 'capturing':
            # Nothing in this process is capturing for it, so the capture is already over
            storage.update_session(conn, session_id, status='stopped')
    return redirect(url_for('session_view', session_id=session_id))

@app.route('/sessions/<int:session_id>/delete', methods=['POST'])
def delete_session(session_id):
    with db() as conn:
        session = storage.get_session(conn, session_id)
        if session is None:
            abort(404)
        if session['status'] == 'capturing':
            return index_error('That session is still capturing. Stop the capture before deleting it.', 409)
        if session['status'] == 'processing':
            return index_error('That session is still being analyzed. Delete it once it has finished.', 409)
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

def _session_or_404(conn, session_id):
    session = storage.get_session(conn, session_id)
    if session is None:
        abort(404)
    return session

def _paging():
    """Query, sort, direction and page from the request, for the host and flow tables."""
    try:
        limit = min(max(int(request.args.get('limit', 100)), 1), MAX_PAGE_SIZE)
        offset = max(int(request.args.get('offset', 0)), 0)
    except ValueError:
        abort(400)
    return dict(query=request.args.get('q', ''), sort=request.args.get('sort', ''),
                descending=request.args.get('order') == 'desc', limit=limit, offset=offset)

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return e

@app.route('/api/sessions/<int:session_id>')
def session_status(session_id):
    with db() as conn:
        return jsonify({**_session_or_404(conn, session_id), 'running': live_capture.is_running(session_id)})

@app.route('/api/sessions/<int:session_id>/graph')
def session_graph(session_id):
    collapse = {'true': True, 'false': False}.get(request.args.get('collapse'))  # anything else: automatic
    with db() as conn:
        session = _session_or_404(conn, session_id)
        return jsonify({'session': session, **storage.session_graph(conn, session_id, collapse)})

@app.route('/api/sessions/<int:session_id>/hosts')
def session_hosts(session_id):
    with db() as conn:
        _session_or_404(conn, session_id)
        paging = _paging()
        hosts, total = storage.list_hosts(conn, session_id, **{**paging, 'sort': paging['sort'] or 'ip'})
    return jsonify({'hosts': hosts, 'total': total})

@app.route('/api/sessions/<int:session_id>/hosts/<path:ip>')
def session_host(session_id, ip):
    with db() as conn:
        _session_or_404(conn, session_id)
        host = storage.host_detail(conn, session_id, ip)
    if host is None:
        abort(404)
    return jsonify(host)

@app.route('/api/sessions/<int:session_id>/flows')
def session_flows(session_id):
    with db() as conn:
        _session_or_404(conn, session_id)
        paging = _paging()
        flows, total = storage.list_flows(conn, session_id, **{**paging, 'sort': paging['sort'] or 'packets'},
                                          host=request.args.get('host'), src=request.args.get('src'), dst=request.args.get('dst'))
    return jsonify({'flows': flows, 'total': total})

HOST_CSV_COLUMNS = ['ip', 'mac', 'vendor', 'via_mac', 'kind', 'category', 'role', 'packets_sent', 'packets_received',
                    'bytes_sent', 'bytes_received', 'first_seen', 'last_seen', 'fingerprints']
FLOW_CSV_COLUMNS = ['src', 'dst', 'transport', 'src_port', 'dst_port', 'protocol', 'packets', 'bytes', 'first_seen', 'last_seen']

def _csv(rows, columns, filename):
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=columns, extrasaction='ignore')
    writer.writeheader()
    for row in rows:
        writer.writerow({**row, 'fingerprints': '; '.join(row.get('fingerprints', []))} if 'fingerprints' in columns else row)
    return Response(out.getvalue(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename={filename}'})

@app.route('/sessions/<int:session_id>/hosts.csv')
def export_hosts(session_id):
    with db() as conn:
        _session_or_404(conn, session_id)
        hosts, _ = storage.list_hosts(conn, session_id)
    return _csv(hosts, HOST_CSV_COLUMNS, f'session_{session_id}_hosts.csv')

@app.route('/sessions/<int:session_id>/flows.csv')
def export_flows(session_id):
    with db() as conn:
        _session_or_404(conn, session_id)
        flows, _ = storage.list_flows(conn, session_id)
    return _csv(flows, FLOW_CSV_COLUMNS, f'session_{session_id}_flows.csv')

@app.route('/api/interfaces')
def interfaces():
    try:
        return jsonify({'interfaces': live_capture.list_interfaces()})
    except RuntimeError as e:
        return jsonify({'interfaces': [], 'error': str(e)})

def parse_args():
    parser = argparse.ArgumentParser(description='pyLot passive ICS network mapper')
    parser.add_argument('--host', default='127.0.0.1', help='address to listen on (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='port to listen on (default: 5000)')
    parser.add_argument('--capture-interface', metavar='IFACE',
                        help='also start capturing live traffic on this interface (captures can also be started from the web page)')
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
        live_capture.launch(args.capture_interface, DB_PATH, args.capture_filter)

    app.run(host=args.host, port=args.port, debug=args.debug)
