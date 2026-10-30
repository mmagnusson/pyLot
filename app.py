from flask import Flask, Response, render_template, request, redirect, url_for, jsonify, abort, g, session
from werkzeug.utils import secure_filename
from parser import zeek
from parser.pcap_parser import CAPTURE_MAGIC_NUMBERS, check_file, parse_file
from parser import switch_config
from capture import live_capture
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
import argparse
import csv
import io
import logging
import os
import socket
import sqlite3
import urllib.error
import uuid
import advisories
import alerts
import auth
import inventory
import storage

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('PYLOT_DB_PATH', os.path.join(BASE_DIR, 'pylot.sqlite3'))
UPLOAD_FOLDER = os.environ.get('PYLOT_UPLOAD_FOLDER', os.path.join(BASE_DIR, 'uploads'))
LOOPBACK_HOSTS = ('127.0.0.1', 'localhost')
MAX_PAGE_SIZE = 1000
MAX_CAPTURE_FILTER_LENGTH = 500
MAX_SWITCH_FILE_BYTES = 5 * 1024 * 1024

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('PYLOT_MAX_UPLOAD_MB', '500')) * 1024 * 1024
# Requests whose Host header isn't listed get a 400, which blocks DNS rebinding attacks
app.config['TRUSTED_HOSTS'] = os.environ.get('PYLOT_TRUSTED_HOSTS', ','.join(LOOPBACK_HOSTS)).split(',')

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize database on startup
storage.init_db(DB_PATH)

# Sign-in (see auth.py): a signed session cookie, sent to this site only, never readable by scripts
with closing(storage.connect(DB_PATH)) as _conn:
    app.secret_key = os.environ.get('PYLOT_SECRET_KEY') or auth.secret_key(_conn)
app.config.update(SESSION_COOKIE_NAME='pylot_session', SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=float(os.environ.get('PYLOT_SESSION_HOURS', '12'))),
                  # Set when listening beyond this machine: with no accounts, refuse requests rather than serve everyone
                  REQUIRE_ACCOUNTS=False)
login_throttle = auth.LoginThrottle()
PUBLIC_ENDPOINTS = {'login', 'static'}

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

def requires(role):
    """Routes need a viewer to read and an analyst to change anything; this raises the bar for one route."""
    def mark(view):
        view.required_role = role
        return view
    return mark

def _wants_json():
    return request.path.startswith('/api/') or request.path.endswith('.csv')

def _refuse(message, status):
    if _wants_json():
        return jsonify({'error': message}), status
    return render_template('message.html', title='Not allowed' if status == 403 else 'Unavailable', message=message), status

@app.before_request
def require_sign_in():
    g.user = None
    g.accounts = False
    if request.endpoint is None or request.endpoint in PUBLIC_ENDPOINTS:
        return
    with db() as conn:
        g.accounts = auth.has_users(conn)
        if not g.accounts:
            if app.config['REQUIRE_ACCOUNTS']:
                return _refuse('pyLot has no accounts yet. Add one on the server with: python auth.py add NAME', 503)
            return
        user = auth.get_user(conn, session.get('user_id'))
    if user is None or session.get('token') != auth.session_token(user):
        session.clear()
        if _wants_json() or request.method != 'GET':
            return jsonify({'error': 'Sign in first.'}), 401
        return redirect(url_for('login', next=request.full_path.rstrip('?')))
    g.user = user
    view = app.view_functions[request.endpoint]
    required = getattr(view, 'required_role', 'viewer' if request.method in ('GET', 'HEAD') else 'analyst')
    if not auth.allowed(user['role'], required):
        return _refuse(f"Your account ({user['role']}) can't do that; it needs the {required} role.", 403)

@app.after_request
def security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'same-origin')
    if g.get('user') and request.endpoint != 'static':
        response.headers.setdefault('Cache-Control', 'no-store')  # signed-in pages stay out of shared caches
    return response

@app.context_processor
def account_context():
    user = g.get('user')
    return {'current_user': user, 'accounts': g.get('accounts', False),
            'can': lambda role: user is None or auth.allowed(user['role'], role)}

def index_error(message, status=400):
    with db() as conn:
        sessions = storage.list_sessions(conn)
    return render_template('index.html', error=message, sessions=sessions, capture_user=live_capture.process_user()), status

@app.errorhandler(413)
def upload_too_large(e):
    return index_error(f"That file is larger than the {app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)} MB upload limit "
                       "(set PYLOT_MAX_UPLOAD_MB to change it).", 413)

@app.route('/')
def index():
    with db() as conn:
        return render_template('index.html', sessions=storage.list_sessions(conn), capture_user=live_capture.process_user())

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('pcap_file')
    if file is None or not file.filename:
        return index_error('No file selected.')
    head = file.stream.read(16)
    if head[:4] not in CAPTURE_MAGIC_NUMBERS and not zeek.looks_like_log(head):
        return index_error('That file is not a PCAP or PCAPNG capture or a Zeek conn.log.')
    file.stream.seek(0)

    # Never trust the client's filename: sanitize it and add a random prefix so uploads can't
    # escape the upload folder or overwrite each other
    filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename) or 'capture.pcap'}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    try:
        check_file(filepath)
    except ValueError as e:
        os.remove(filepath)
        return index_error(f'Could not read that file: {e}')

    with db() as conn:
        session_id = storage.create_session(conn, file.filename[:200], 'upload', 'processing', capture_file=filename)
    submit(analyze_upload, session_id, filepath)
    return redirect(url_for('session_view', session_id=session_id))

def analyze_upload(session_id, filepath, discard_on_failure=True):
    """
    Background job: analyze an uploaded capture into its session, marking it ready or failed. A new upload
    that can't be analyzed is deleted; a re-analysis keeps its file (discard_on_failure=False), since it
    was readable before.
    """
    with db() as conn:
        try:
            analyzer = parse_file(filepath)
            storage.save_analysis(conn, session_id, analyzer)
            storage.update_session(conn, session_id, status='ready')
            try:
                inventory.sync(conn, [session_id])
            except Exception:
                # The session is fine without it; the inventory tries again when it is next opened
                logger.exception("Couldn't add session %s to the inventory", session_id)
        except Exception as e:
            logger.exception("Failed to analyze %s", filepath)
            if not discard_on_failure:
                storage.update_session(conn, session_id, status='failed', error=f'Could not analyze this capture: {e}')
                return
            storage.update_session(conn, session_id, status='failed', error=f'Could not analyze this capture: {e}',
                                   capture_file=None)
            try:
                os.remove(filepath)
            except FileNotFoundError:
                pass

def _upload_path(session):
    return os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(session['capture_file']))

def _reanalyze(conn, session):
    """Queue a session's upload for analysis again. False if it can't be (no file, or busy)."""
    path = _upload_path(session) if session['capture_file'] else None
    if path is None or not os.path.exists(path) or not storage.reset_analysis(conn, session['id']):
        return False
    submit(analyze_upload, session['id'], path, False)
    return True

@app.route('/sessions/<int:session_id>/reanalyze', methods=['POST'])
def reanalyze_session(session_id):
    with db() as conn:
        session = _session_or_404(conn, session_id)
        if not _reanalyze(conn, session):
            if session['source'] != 'upload':
                return index_error('Live captures are not saved to a file, so they cannot be analyzed again.', 409)
            if session['status'] in ('processing', 'capturing'):
                return index_error('That session is still being analyzed.', 409)
            return index_error('The file for that session is no longer available, so it cannot be analyzed again.', 409)
    return redirect(url_for('session_view', session_id=session_id))

@app.route('/sessions/reanalyze', methods=['POST'])
def reanalyze_all():
    with db() as conn:
        for session_id in storage.reanalyzable_sessions(conn):
            _reanalyze(conn, storage.get_session(conn, session_id))
    return redirect(url_for('index'))

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
        others = [s for s in storage.list_sessions(conn) if s['id'] != session_id]
    if session is None:
        abort(404)
    return render_template('network.html', session=session, others=others)

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
            os.remove(_upload_path(session))
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
    baseline_id = request.args.get('baseline', type=int)
    with db() as conn:
        session = _session_or_404(conn, session_id)
        if baseline_id is not None and storage.get_session(conn, baseline_id) is None:
            return jsonify({'error': 'That baseline session does not exist.'}), 400
        return jsonify({'session': session, **storage.session_graph(conn, session_id, collapse, baseline_id)})

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
        if host is not None:
            host['vulnerabilities'] = advisories.match_hosts(conn, [host])
            host['asset'] = inventory.asset_for(conn, session_id, ip=ip, mac=host['mac'])
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

@app.route('/api/sessions/<int:session_id>/operations')
def session_operations(session_id):
    with db() as conn:
        _session_or_404(conn, session_id)
        paging = _paging()
        operations, total = storage.list_operations(conn, session_id, **{**paging, 'sort': paging['sort'] or 'kind'},
                                                    host=request.args.get('host'), kind=request.args.get('kind') or None)
        kinds = storage.operation_kinds(conn, session_id)
    return jsonify({'operations': operations, 'total': total, 'kinds': kinds})

@app.route('/api/sessions/<int:session_id>/alerts')
def session_alerts(session_id):
    with db() as conn:
        _session_or_404(conn, session_id)
        found = alerts.session_alerts(conn, session_id)
    counts = {severity: sum(1 for a in found if a['severity'] == severity) for severity in alerts.SEVERITIES}
    return jsonify({'alerts': found, 'counts': counts})

@app.route('/api/sessions/<int:session_id>/vulnerabilities')
def session_vulnerabilities(session_id):
    with db() as conn:
        _session_or_404(conn, session_id)
        found = advisories.session_vulnerabilities(conn, session_id)
        imported = advisories.advisory_summary(conn)['advisories']
    counts = {status: sum(1 for v in found if v['status'] == status) for status in advisories.STATUS_ORDER}
    counts['devices'] = len({(v['ip'], v['module']) for v in found if v['status'] == 'affected'})
    return jsonify({'vulnerabilities': found, 'counts': counts, 'advisories': imported})

@app.route('/api/sessions/<int:session_id>/devices')
def session_devices(session_id):
    with db() as conn:
        _session_or_404(conn, session_id)
        paging = _paging()
        devices, total = storage.list_devices(conn, session_id, **{**paging, 'sort': paging['sort'] or 'mac'})
    return jsonify({'devices': devices, 'total': total})

@app.route('/api/sessions/<int:session_id>/devices/<mac>')
def session_device(session_id, mac):
    with db() as conn:
        _session_or_404(conn, session_id)
        device = storage.device_detail(conn, session_id, mac.lower())
        if device is not None:
            device['asset'] = inventory.asset_for(conn, session_id, mac=device['mac'])
    if device is None:
        abort(404)
    return jsonify(device)

@app.route('/api/sessions/<int:session_id>/physical')
def session_physical(session_id):
    with db() as conn:
        _session_or_404(conn, session_id)
        return jsonify(storage.physical_graph(conn, session_id))

@app.route('/api/sessions/<int:session_id>/switches', methods=['POST'])
def import_switch(session_id):
    """Import Cisco show running-config / mac address-table / cdp or lldp neighbors output, uploaded or pasted."""
    with db() as conn:
        session = _session_or_404(conn, session_id)
        file = request.files.get('config_file')
        if file and file.filename:
            raw = file.stream.read(MAX_SWITCH_FILE_BYTES + 1)
            filename = secure_filename(file.filename)[:200] or 'switch.txt'
        else:
            raw = request.form.get('config_text', '').encode()
            filename = None
        if len(raw) > MAX_SWITCH_FILE_BYTES:
            return jsonify({'error': f'Switch files can be at most {MAX_SWITCH_FILE_BYTES // (1024 * 1024)} MB.'}), 400
        if b'\x00' in raw:
            return jsonify({'error': 'That is not a text file of switch command output.'}), 400
        data = switch_config.parse(raw.decode('utf-8', 'replace'))
        if data.is_empty():
            return jsonify({'error': 'No interfaces, MAC address table or CDP/LLDP neighbors found. pyLot reads the output of '
                                     'show running-config, show mac address-table and show cdp/lldp neighbors detail.'}), 400
        name = request.form.get('name', '').strip() or None
        switch_id = storage.save_switch(conn, session['id'], data, filename=filename, name=name)
        switch = next(s for s in storage.list_switches(conn, session_id) if s['id'] == switch_id)
    return jsonify(switch), 201

@app.route('/api/sessions/<int:session_id>/switches/<int:switch_id>', methods=['DELETE'])
def remove_switch(session_id, switch_id):
    with db() as conn:
        _session_or_404(conn, session_id)
        if not storage.delete_switch(conn, session_id, switch_id):
            abort(404)
    return '', 204

@app.route('/sessions/<int:session_id>/compare')
def compare_view(session_id):
    with db() as conn:
        session = _session_or_404(conn, session_id)
        sessions = [s for s in storage.list_sessions(conn) if s['id'] != session_id]
    return render_template('compare.html', session=session, sessions=sessions,
                           baseline_id=request.args.get('baseline', type=int))

@app.route('/api/sessions/<int:session_id>/compare')
def compare_sessions(session_id):
    baseline_id = request.args.get('baseline', type=int)
    with db() as conn:
        session = _session_or_404(conn, session_id)
        baseline = storage.get_session(conn, baseline_id) if baseline_id else None
        if baseline is None:
            return jsonify({'error': 'Choose a baseline session to compare with.'}), 400
        diff = storage.compare_sessions(conn, session_id, baseline_id)
        known = {(v['ip'], v['module'], v['advisory']) for v in advisories.session_vulnerabilities(conn, baseline_id)}
        new = [v for v in advisories.session_vulnerabilities(conn, session_id) if (v['ip'], v['module'], v['advisory']) not in known]
    diff['new_vulnerabilities'] = {'items': new[:500], 'total': len(new)}
    return jsonify({'session': session, 'baseline': baseline, **diff})

# --- security advisories

def advisories_page(message=None, error=None, status=200):
    with db() as conn:
        summary = advisories.advisory_summary(conn)
    return render_template('advisories.html', summary=summary, message=message, error=error,
                           archive=advisories.CISA_ARCHIVE), status

def _import_message(counts):
    message = f"Imported {counts['added']} new and {counts['updated']} updated advisories"
    if counts['unchanged']:
        message += f", {counts['unchanged']} already up to date"
    if counts['skipped']:
        message += f"; {counts['skipped']} files weren't CSAF advisories"
    return message + '.'

@app.route('/advisories')
def advisories_view():
    return advisories_page()

@app.route('/advisories/import', methods=['POST'])
@requires('admin')
def advisories_import():
    files = [f for f in request.files.getlist('advisory_file') if f and f.filename]
    if not files:
        return advisories_page(error='Choose a CSAF file, or a .zip or .tar.gz of them.', status=400)

    def documents():
        for file in files:
            yield from advisories.read_documents(file.filename, file.stream.read())
    with db() as conn:
        counts = advisories.import_advisories(conn, documents())
    if not (counts['added'] or counts['updated'] or counts['unchanged']):
        return advisories_page(error='No CSAF advisories found in that upload.', status=400)
    return advisories_page(message=_import_message(counts))

@app.route('/advisories/fetch', methods=['POST'])
@requires('admin')
def advisories_fetch():
    with db() as conn:
        try:
            counts = advisories.fetch_cisa(conn)
        except (urllib.error.URLError, OSError, ValueError) as e:
            logger.warning("Could not download CISA's advisories: %s", e)
            return advisories_page(error=f"Could not download CISA's advisories: {e}. On a network without Internet access, "
                                         "download the archive elsewhere and import it here.", status=502)
    if not (counts['added'] or counts['updated'] or counts['unchanged']):
        return advisories_page(error="The download from CISA held no advisories.", status=502)
    return advisories_page(message=_import_message(counts))

@app.route('/advisories/delete', methods=['POST'])
@requires('admin')
def advisories_delete():
    with db() as conn:
        advisories.delete_advisories(conn)
    return advisories_page(message='Removed every imported advisory.')

# --- named networks and settings

def _safe_next(target):
    """Only paths on this site, so a sign-in link can't send someone elsewhere afterwards."""
    if target and target.startswith('/') and not target.startswith('//') and '\\' not in target:
        return target
    return url_for('index')

def _sign_in(user):
    session.clear()
    session.permanent = True
    session['user_id'] = user['id']
    session['token'] = auth.session_token(user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    with db() as conn:
        accounts = auth.has_users(conn)
    next_page = _safe_next(request.values.get('next'))
    if not accounts:
        return redirect(url_for('users_view'))
    if request.method == 'GET':
        return render_template('login.html', next=next_page)
    address = request.remote_addr or ''
    wait = login_throttle.blocked(address)
    if wait:
        return render_template('login.html', next=next_page,
                               error=f'Too many failed sign-ins. Try again in {(wait + 59) // 60} minutes.'), 429
    username = request.form.get('username', '').strip()
    with db() as conn:
        user = auth.verify(conn, username, request.form.get('password', ''))
        if user:
            auth.record_login(conn, user['id'])
    if user is None:
        login_throttle.failed(address)
        logger.warning('Failed sign-in for %r from %s', username, address)
        return render_template('login.html', next=next_page, username=username, error='Wrong user name or password.'), 401
    login_throttle.succeeded(address)
    logger.info('%s signed in from %s', user['username'], address)
    _sign_in(user)
    return redirect(next_page)

@app.route('/logout', methods=['POST'])
@requires('viewer')
def logout():
    session.clear()
    return redirect(url_for('login'))

def account_page(message=None, error=None, status=200):
    return render_template('account.html', message=message, error=error, min_length=auth.MIN_PASSWORD_LENGTH), status

@app.route('/account')
def account_view():
    if g.user is None:
        return redirect(url_for('users_view'))
    return account_page()

@app.route('/account/password', methods=['POST'])
@requires('viewer')
def account_password():
    if g.user is None:
        return redirect(url_for('users_view'))
    form = request.form
    with db() as conn:
        if not auth.verify(conn, g.user['username'], form.get('current', '')):
            return account_page(error='Your current password is wrong.', status=400)
        if form.get('password') != form.get('confirm'):
            return account_page(error="The new passwords don't match.", status=400)
        try:
            auth.set_password(conn, g.user['id'], form.get('password'))
        except auth.AccountError as e:
            return account_page(error=f'{str(e).capitalize()}.', status=400)
        _sign_in(auth.get_user(conn, g.user['id']))  # this browser stays signed in; others are signed out
    return account_page(message='Password changed. Browsers signed in with the old one have been signed out.')

def users_page(message=None, error=None, status=200):
    with db() as conn:
        users = auth.list_users(conn)
    return render_template('users.html', users=users, roles=auth.ROLES, message=message, error=error,
                           min_length=auth.MIN_PASSWORD_LENGTH), status

@app.route('/users')
@requires('admin')
def users_view():
    return users_page()

@app.route('/users', methods=['POST'])
@requires('admin')
def users_add():
    form = request.form
    if form.get('password') != form.get('confirm'):
        return users_page(error="The passwords don't match.", status=400)
    with db() as conn:
        first = not auth.has_users(conn)
        role = 'admin' if first else form.get('role')
        try:
            user = auth.add_user(conn, form.get('username', '').strip(), form.get('password'), role)
        except auth.AccountError as e:
            return users_page(error=f'{str(e).capitalize()}.', status=400)
        if first:
            # Whoever made the first account is now asked to sign in like everyone else, so sign them in as it
            _sign_in(auth.get_user(conn, user['id']))
            auth.record_login(conn, user['id'])
            g.user, g.accounts = auth.get_user(conn, user['id']), True
    logger.info('Account %s (%s) added by %s', user['username'], user['role'], g.user['username'])
    return users_page(message=f"Added {user['username']} ({user['role']})."
                              + (' pyLot now asks everyone to sign in, and you are signed in as this account.' if first else ''))

def _other_account(conn, user_id, action):
    user = auth.get_user(conn, user_id)
    if user is None:
        abort(404)
    if user['id'] == g.user['id']:
        raise auth.AccountError(f"you can't {action} your own account here")
    return user

@app.route('/users/<int:user_id>/role', methods=['POST'])
@requires('admin')
def users_role(user_id):
    with db() as conn:
        try:
            user = _other_account(conn, user_id, 'change the role of')
            auth.set_role(conn, user_id, request.form.get('role'))
        except auth.AccountError as e:
            return users_page(error=f'{str(e).capitalize()}.', status=400)
    return users_page(message=f"{user['username']} is now {request.form.get('role')}.")

@app.route('/users/<int:user_id>/password', methods=['POST'])
@requires('admin')
def users_password(user_id):
    with db() as conn:
        try:
            user = _other_account(conn, user_id, 'reset the password of')
            auth.set_password(conn, user_id, request.form.get('password'))
        except auth.AccountError as e:
            return users_page(error=f'{str(e).capitalize()}.', status=400)
    return users_page(message=f"Set a new password for {user['username']}; they have been signed out.")

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@requires('admin')
def users_delete(user_id):
    with db() as conn:
        try:
            user = _other_account(conn, user_id, 'remove')
            auth.remove_user(conn, user_id)
        except auth.AccountError as e:
            return users_page(error=f'{str(e).capitalize()}.', status=400)
    return users_page(message=f"Removed {user['username']}.")

@app.template_filter('when')
def format_time(timestamp):
    if timestamp is None:
        return ''
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

@app.route('/inventory')
def inventory_view():
    return render_template('inventory.html')

@app.route('/api/inventory')
def inventory_list():
    with db() as conn:
        assets = inventory.list_assets(conn)
        sessions = conn.execute("SELECT COUNT(*) FROM inventory_sessions").fetchone()[0]
    return jsonify({'assets': assets, 'sessions': sessions})

def asset_page(asset_id, message=None, error=None, status=200):
    with db() as conn:
        asset = inventory.get_asset(conn, asset_id)
        if asset is None:
            abort(404)
        others = [{'id': a['id'], 'label': a['label']} for a in inventory.list_assets(conn) if a['id'] != asset_id]
        existing = {row['id'] for row in conn.execute("SELECT id FROM sessions")}
    return render_template('asset.html', asset=asset, others=others, existing_sessions=existing,
                           message=message, error=error), status

@app.route('/inventory/<int:asset_id>')
def asset_view(asset_id):
    return asset_page(asset_id)

@app.route('/inventory/<int:asset_id>', methods=['POST'])
def asset_update(asset_id):
    with db() as conn:
        try:
            inventory.update_asset(conn, asset_id, request.form.get('name'), request.form.get('notes'))
        except KeyError:
            abort(404)
        except ValueError as e:
            return asset_page(asset_id, error=f'{str(e).capitalize()}.', status=400)
    return asset_page(asset_id, message='Saved.')

@app.route('/inventory/<int:asset_id>/merge', methods=['POST'])
def asset_merge(asset_id):
    try:
        other = int(request.form.get('other', ''))
    except ValueError:
        return asset_page(asset_id, error='Choose the asset to merge into this one.', status=400)
    with db() as conn:
        try:
            inventory.merge_assets(conn, asset_id, other)
        except KeyError:
            abort(404)
        except ValueError as e:
            return asset_page(asset_id, error=f'{str(e).capitalize()}.', status=400)
    return asset_page(asset_id, message=f'Merged asset {other} into this one.')

@app.route('/inventory/<int:asset_id>/delete', methods=['POST'])
def asset_delete(asset_id):
    with db() as conn:
        if not inventory.delete_asset(conn, asset_id):
            abort(404)
    return redirect(url_for('inventory_view'))

@app.route('/networks')
def networks_view():
    return render_template('networks.html')

def _json_body():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        abort(400)
    return body

@app.route('/api/networks')
def networks_list():
    with db() as conn:
        return jsonify({'networks': storage.list_networks(conn), 'settings': storage.get_settings(conn)})

@app.route('/api/networks', methods=['POST'])
def networks_add():
    body = _json_body()
    with db() as conn:
        try:
            network = storage.add_network(conn, body.get('cidr', ''), body.get('name'))
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
    return jsonify(network), 201

@app.route('/api/networks/<int:network_id>', methods=['PUT'])
def networks_update(network_id):
    body = _json_body()
    with db() as conn:
        try:
            network = storage.update_network(conn, network_id, cidr=body.get('cidr'), name=body.get('name'))
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
    if network is None:
        abort(404)
    return jsonify(network)

@app.route('/api/networks/<int:network_id>', methods=['DELETE'])
def networks_delete(network_id):
    with db() as conn:
        if not storage.delete_network(conn, network_id):
            abort(404)
    return '', 204

@app.route('/api/settings', methods=['PUT'])
def settings_update():
    body = _json_body()
    with db() as conn:
        try:
            return jsonify(storage.update_settings(conn, **body))
        except (ValueError, TypeError) as e:
            return jsonify({'error': str(e)}), 400

HOST_CSV_COLUMNS = ['ip', 'mac', 'vendor', 'via_mac', 'kind', 'category', 'role', 'device_vendor', 'model', 'firmware', 'serial',
                    'packets_sent', 'packets_received', 'bytes_sent', 'bytes_received', 'first_seen', 'last_seen', 'fingerprints']
FLOW_CSV_COLUMNS = ['src', 'dst', 'transport', 'src_port', 'dst_port', 'protocol', 'packets', 'bytes', 'first_seen', 'last_seen']

def _cell(value):
    # Names and banners come from captured traffic: don't let a spreadsheet run one as a formula
    if isinstance(value, str) and value[:1] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    return value

def _csv(rows, columns, filename):
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=columns, extrasaction='ignore')
    writer.writeheader()
    for row in rows:
        row = {**row, 'fingerprints': '; '.join(row.get('fingerprints', []))} if 'fingerprints' in columns else row
        writer.writerow({key: _cell(value) for key, value in row.items()})
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

ALERT_CSV_COLUMNS = ['severity', 'title', 'src', 'dst', 'protocols', 'operations', 'count', 'first_seen', 'last_seen',
                     'first_frame', 'rule']

@app.route('/sessions/<int:session_id>/alerts.csv')
def export_alerts(session_id):
    with db() as conn:
        _session_or_404(conn, session_id)
        found = alerts.session_alerts(conn, session_id)
    rows = [{**a, 'src': a['src'] or '; '.join(a.get('clients', [])), 'dst': a['dst'] or 'many',
             'protocols': '; '.join(a['protocols']), 'operations': '; '.join(a['operations'])} for a in found]
    return _csv(rows, ALERT_CSV_COLUMNS, f'session_{session_id}_alerts.csv')

OPERATION_CSV_COLUMNS = ['src', 'dst', 'protocol', 'operation', 'kind', 'count', 'first_seen', 'last_seen', 'first_frame']

@app.route('/sessions/<int:session_id>/operations.csv')
def export_operations(session_id):
    with db() as conn:
        _session_or_404(conn, session_id)
        operations, _ = storage.list_operations(conn, session_id)
    return _csv(operations, OPERATION_CSV_COLUMNS, f'session_{session_id}_operations.csv')

VULNERABILITY_CSV_COLUMNS = ['status', 'severity', 'score', 'ip', 'module', 'vendor', 'model', 'firmware', 'advisory', 'title',
                             'cves', 'product', 'versions', 'match', 'reason', 'fix', 'url']

@app.route('/sessions/<int:session_id>/vulnerabilities.csv')
def export_vulnerabilities(session_id):
    with db() as conn:
        _session_or_404(conn, session_id)
        found = advisories.session_vulnerabilities(conn, session_id)
    rows = [{**v, 'cves': '; '.join(v['cves'])} for v in found]
    return _csv(rows, VULNERABILITY_CSV_COLUMNS, f'session_{session_id}_vulnerabilities.csv')

DEVICE_CSV_COLUMNS = ['mac', 'vendor', 'name', 'ips', 'vlans', 'category', 'role', 'model', 'firmware', 'serial', 'layer2',
                      'switch', 'port', 'seen', 'packets', 'bytes', 'first_seen', 'last_seen']

INVENTORY_CSV_COLUMNS = ['id', 'given_name', 'name', 'ips', 'all_ips', 'mac', 'mac_vendor', 'device_vendor', 'model', 'firmware',
                         'serial', 'category', 'role', 'first_seen', 'last_seen', 'sessions', 'changes', 'vulnerabilities',
                         'possible_vulnerabilities', 'notes']

@app.route('/inventory.csv')
def export_inventory():
    with db() as conn:
        assets = inventory.list_assets(conn)
    for asset in assets:
        asset['ips'], asset['all_ips'] = ' '.join(asset['ips']), ' '.join(asset['all_ips'])
    return _csv(assets, INVENTORY_CSV_COLUMNS, 'inventory.csv')

@app.route('/sessions/<int:session_id>/devices.csv')
def export_devices(session_id):
    with db() as conn:
        _session_or_404(conn, session_id)
        devices, _ = storage.list_devices(conn, session_id)
    rows = [{**d, 'ips': '; '.join(d['ips']), 'vlans': '; '.join(map(str, d['vlans'])), 'layer2': '; '.join(d['layer2'])}
            for d in devices]
    return _csv(rows, DEVICE_CSV_COLUMNS, f'session_{session_id}_devices.csv')

@app.route('/api/interfaces')
@requires('analyst')
def interfaces():
    try:
        return jsonify({'interfaces': live_capture.list_interfaces()})
    except RuntimeError as e:
        return jsonify({'interfaces': [], 'error': str(e)})

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='pyLot passive ICS network mapper')
    parser.add_argument('--host', default='127.0.0.1', help='address to listen on (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='port to listen on (default: 5000)')
    parser.add_argument('--capture-interface', metavar='IFACE',
                        help='also start capturing live traffic on this interface (captures can also be started from the web page)')
    parser.add_argument('--capture-filter', metavar='BPF',
                        help='only capture traffic matching this capture filter, e.g. "not port 22"')
    tls = parser.add_argument_group('HTTPS (needed to listen on anything but this machine)')
    tls.add_argument('--cert', metavar='FILE', help='serve HTTPS with this PEM certificate (and chain)')
    tls.add_argument('--key', metavar='FILE', help="the certificate's PEM private key")
    tls.add_argument('--self-signed', action='store_true',
                     help=f'serve HTTPS with a self-signed certificate, made in {os.path.join(BASE_DIR, "tls")} on first use')
    tls.add_argument('--behind-proxy', action='store_true',
                     help='a reverse proxy on this machine serves HTTPS and forwards to pyLot; trust its X-Forwarded headers')
    parser.add_argument('--debug', action='store_true',
                        help='enable the Flask debugger and auto-reload (this machine only)')
    args = parser.parse_args(argv)
    if bool(args.cert) != bool(args.key):
        parser.error('--cert and --key go together')
    if sum(map(bool, (args.cert, args.self_signed, args.behind_proxy))) > 1:
        parser.error('choose one of --cert/--key, --self-signed and --behind-proxy')
    return args

def configure_serving(args):
    """
    Check that it's safe to serve as asked and set up for it. Returns the ssl_context for app.run.
    Raises SystemExit with the reason when it isn't safe.
    """
    networked = args.host not in LOOPBACK_HOSTS or args.behind_proxy
    if networked:
        if args.debug:
            raise SystemExit("--debug runs code typed into its error pages, so it only works on this machine (127.0.0.1)")
        with db() as conn:
            if not auth.has_users(conn):
                raise SystemExit("Add an account before pyLot listens beyond this machine: python auth.py add NAME")
        if not (args.cert or args.self_signed or args.behind_proxy):
            raise SystemExit("pyLot needs HTTPS to listen beyond this machine, so passwords aren't sent in the clear: "
                             "give --cert and --key, or --self-signed, or --behind-proxy for a reverse proxy that serves HTTPS")
        app.config['REQUIRE_ACCOUNTS'] = True
        if args.host not in ('0.0.0.0', '::') and args.host not in LOOPBACK_HOSTS and 'PYLOT_TRUSTED_HOSTS' not in os.environ:
            app.config['TRUSTED_HOSTS'].append(args.host)

    ssl_context = None
    if args.cert:
        ssl_context = (args.cert, args.key)
    elif args.self_signed:
        names = [socket.gethostname(), socket.getfqdn(), *app.config['TRUSTED_HOSTS']]
        if args.host not in ('0.0.0.0', '::'):
            names.append(args.host)
        try:
            cert, key, created = auth.self_signed_certificate(os.path.join(BASE_DIR, 'tls'), names)
        except RuntimeError as e:
            raise SystemExit(str(e))
        logger.info("%s self-signed certificate %s. Browsers will warn about it; check that it shows this "
                    "SHA-256 fingerprint before accepting it: %s", 'Made' if created else 'Using', cert,
                    auth.certificate_fingerprint(cert))
        ssl_context = (cert, key)
    elif args.behind_proxy:
        from werkzeug.middleware.proxy_fix import ProxyFix
        # The proxy's headers give the browser's address (for sign-in limits), the scheme and the host it asked for
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    if ssl_context or args.behind_proxy:
        app.config['SESSION_COOKIE_SECURE'] = True
    return ssl_context

if __name__ == '__main__':
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    ssl_context = configure_serving(args)
    with db() as conn:
        if not auth.has_users(conn):
            logger.info("No accounts, so pyLot doesn't ask anyone to sign in. Add one on the Accounts page or with: python auth.py add NAME")

    # With --debug the reloader runs this file twice; only capture in the process that serves requests
    if args.capture_interface and (not args.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true'):
        live_capture.launch(args.capture_interface, DB_PATH, args.capture_filter)

    app.run(host=args.host, port=args.port, debug=args.debug, ssl_context=ssl_context)
