import io
import os
import shutil

import pytest

import app as app_module
import auth
import storage
from test_app import client, upload  # noqa: F401 (client is a fixture)

PASSWORD = 'correct horse battery'

@pytest.fixture(autouse=True)
def fresh_throttle(monkeypatch):
    monkeypatch.setattr(app_module, 'login_throttle', auth.LoginThrottle())

@pytest.fixture
def conn(tmp_path):
    db_path = str(tmp_path / 'auth.sqlite3')
    storage.init_db(db_path)
    connection = storage.connect(db_path)
    yield connection
    connection.close()

def accounts(**roles):
    """Add accounts to the app's database: accounts(alice='admin', bob='viewer')."""
    with app_module.db() as c:
        return {name: auth.add_user(c, name, PASSWORD, role) for name, role in roles.items()}

def sign_in(client, username, password=PASSWORD, **kwargs):
    return client.post('/login', data={'username': username, 'password': password, **kwargs})

# --- accounts

def test_accounts_check_names_passwords_and_roles(conn):
    assert not auth.has_users(conn)
    user = auth.add_user(conn, 'alice', PASSWORD, 'admin')
    assert auth.has_users(conn) and user['role'] == 'admin' and 'password_hash' not in user
    for username, password, role in [('bad name', PASSWORD, 'viewer'), ('bob', 'short', 'viewer'), ('bob', PASSWORD, 'root'),
                                     ('ALICE', PASSWORD, 'viewer'), ('', PASSWORD, 'viewer')]:
        with pytest.raises(auth.AccountError):
            auth.add_user(conn, username, password, role)
    assert auth.verify(conn, 'alice', PASSWORD)['id'] == user['id']
    assert auth.verify(conn, 'Alice', PASSWORD)  # names are case-insensitive
    assert auth.verify(conn, 'alice', PASSWORD + 'x') is None
    assert auth.verify(conn, 'nobody', PASSWORD) is None
    assert auth.verify(conn, None, None) is None

def test_password_changes_change_the_session_token(conn):
    user = auth.add_user(conn, 'alice', PASSWORD, 'admin')
    before = auth.session_token(auth.get_user(conn, user['id']))
    auth.set_password(conn, user['id'], 'another long password')
    assert auth.session_token(auth.get_user(conn, user['id'])) != before
    assert auth.verify(conn, 'alice', 'another long password')
    with pytest.raises(auth.AccountError):
        auth.set_password(conn, user['id'], 'short')

def test_there_is_always_an_admin_while_there_are_accounts(conn):
    admin = auth.add_user(conn, 'alice', PASSWORD, 'admin')
    viewer = auth.add_user(conn, 'bob', PASSWORD, 'viewer')
    with pytest.raises(auth.AccountError):
        auth.set_role(conn, admin['id'], 'analyst')
    with pytest.raises(auth.AccountError):
        auth.remove_user(conn, admin['id'])
    auth.set_role(conn, viewer['id'], 'admin')
    auth.set_role(conn, admin['id'], 'viewer')
    auth.remove_user(conn, admin['id'])
    auth.remove_user(conn, viewer['id'])  # the last account can go, which turns sign-in off
    assert not auth.has_users(conn)

def test_roles_include_the_ones_below():
    assert auth.allowed('admin', 'viewer') and auth.allowed('analyst', 'analyst')
    assert not auth.allowed('viewer', 'analyst') and not auth.allowed('analyst', 'admin')

def test_the_secret_key_is_kept(conn):
    key = auth.secret_key(conn)
    assert len(key) == 64 and auth.secret_key(conn) == key

def test_the_throttle_blocks_after_too_many_failures(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(auth.time, 'monotonic', lambda: now[0])
    throttle = auth.LoginThrottle(limit=3, window=60)
    for _ in range(3):
        assert not throttle.blocked('10.0.0.1')
        throttle.failed('10.0.0.1')
    assert throttle.blocked('10.0.0.1') == 61
    assert not throttle.blocked('10.0.0.2')
    now[0] += 61
    assert not throttle.blocked('10.0.0.1')
    throttle.failed('10.0.0.1')
    throttle.succeeded('10.0.0.1')
    assert not throttle.failures

# --- signing in

def test_without_accounts_nobody_signs_in(client):
    assert client.get('/').status_code == 200
    assert client.get('/api/networks').status_code == 200
    assert client.get('/login').headers['Location'].endswith('/users')
    assert b'Add the first account' in client.get('/users').data

def test_the_first_account_is_an_admin_and_signs_in(client):
    response = client.post('/users', data={'username': 'alice', 'role': 'viewer', 'password': PASSWORD, 'confirm': PASSWORD})
    assert response.status_code == 200 and b'Added alice (admin)' in response.data
    assert client.get('/').status_code == 200  # still signed in, as alice
    assert b'alice' in client.get('/').data
    other = app_module.app.test_client()
    assert other.get('/').status_code == 302

def test_pages_need_a_signed_in_user(client):
    accounts(alice='admin')
    response = client.get('/sessions/1?tab=x')
    assert response.status_code == 302 and '/login?next=/sessions/1?tab%3Dx' in response.headers['Location']
    assert client.get('/api/sessions/1').status_code == 401
    assert client.get('/sessions/1/hosts.csv').status_code == 401
    assert client.post('/networks', data={}).status_code in (401, 405)
    assert upload(client).status_code == 401
    assert client.get('/static/style.css').status_code == 200
    assert client.get('/login').status_code == 200

def test_signing_in_and_out(client):
    accounts(alice='admin')
    response = sign_in(client, 'alice', 'wrong password!')
    assert response.status_code == 401 and b'Wrong user name or password' in response.data
    response = sign_in(client, 'alice', next='/networks')
    assert response.status_code == 302 and response.headers['Location'] == '/networks'
    cookie = response.headers['Set-Cookie']
    assert 'HttpOnly' in cookie and 'SameSite=Lax' in cookie
    page = client.get('/')
    assert page.status_code == 200 and page.headers['Cache-Control'] == 'no-store'
    assert page.headers['X-Frame-Options'] == 'DENY'
    with app_module.db() as c:
        assert auth.find_user(c, 'alice')['last_login']
    client.post('/logout')
    assert client.get('/').status_code == 302

@pytest.mark.parametrize('target', ['//evil.example/', 'https://evil.example/', '/\\evil.example', 'networks'])
def test_signing_in_only_returns_to_this_site(client, target):
    accounts(alice='admin')
    assert sign_in(client, 'alice', next=target).headers['Location'] == '/'

def test_too_many_failed_sign_ins_are_refused(client, monkeypatch):
    monkeypatch.setattr(app_module, 'login_throttle', auth.LoginThrottle(limit=2))
    accounts(alice='admin')
    sign_in(client, 'alice', 'wrong password!')
    sign_in(client, 'nobody', 'wrong password!')
    response = sign_in(client, 'alice')
    assert response.status_code == 429 and b'Too many failed sign-ins' in response.data

def test_viewers_only_look(client):
    accounts(alice='admin', vera='viewer')
    sign_in(client, 'alice')
    upload(client)
    sign_in(client, 'vera')
    page = client.get('/')
    assert page.status_code == 200 and b'Upload a Capture' not in page.data and b'Delete' not in page.data
    assert client.get('/sessions/1').status_code == 200
    assert client.get('/api/sessions/1/hosts').status_code == 200
    assert client.get('/sessions/1/hosts.csv').status_code == 200
    assert upload(client).status_code == 403
    assert client.post('/api/networks', json={'cidr': '10.0.0.0/24', 'name': 'x'}).status_code == 403
    assert client.post('/sessions/1/delete').status_code == 403
    assert client.get('/api/interfaces').status_code == 403
    assert client.get('/users').status_code == 403
    assert b'An admin can download' in client.get('/advisories').data

def test_analysts_change_sessions_but_not_accounts_or_advisories(client):
    accounts(alice='admin', ann='analyst')
    sign_in(client, 'ann')
    assert upload(client).status_code == 302
    assert client.post('/api/networks', json={'cidr': '10.0.0.0/24', 'name': 'Line 1'}).status_code == 201
    assert client.post('/advisories/fetch').status_code == 403
    assert client.post('/advisories/import', data={'advisory_file': (io.BytesIO(b'{}'), 'a.json')}).status_code == 403
    assert client.get('/users').status_code == 403
    assert client.post('/users', data={'username': 'eve', 'password': PASSWORD, 'confirm': PASSWORD, 'role': 'admin'}).status_code == 403
    assert client.post('/logout').status_code == 302

def test_admins_manage_accounts(client):
    users = accounts(alice='admin', bob='viewer')
    sign_in(client, 'alice')
    response = client.post('/users', data={'username': 'carol', 'password': PASSWORD, 'confirm': PASSWORD, 'role': 'analyst'})
    assert b'Added carol (analyst)' in response.data
    assert b"don&#39;t match" in client.post('/users', data={'username': 'dave', 'password': PASSWORD, 'confirm': 'x'}).data
    bob = app_module.app.test_client()
    sign_in(bob, 'bob')
    assert bob.get('/').status_code == 200

    assert b'bob is now analyst' in client.post(f"/users/{users['bob']['id']}/role", data={'role': 'analyst'}).data
    assert bob.post('/api/networks', json={'cidr': '10.9.0.0/16', 'name': 'x'}).status_code == 201  # roles apply at once
    client.post(f"/users/{users['bob']['id']}/password", data={'password': 'a new long password'})
    assert bob.get('/').status_code == 302  # signed out by the new password
    assert sign_in(bob, 'bob', 'a new long password').status_code == 302
    client.post(f"/users/{users['bob']['id']}/delete")
    assert bob.get('/').status_code == 302

    for action, data in [('role', {'role': 'viewer'}), ('password', {'password': PASSWORD}), ('delete', {})]:
        response = client.post(f"/users/{users['alice']['id']}/{action}", data=data)
        assert response.status_code == 400 and b'your own account' in response.data
    assert client.post('/users/999/delete').status_code == 404

def test_changing_your_password(client):
    accounts(alice='admin')
    sign_in(client, 'alice')
    other = app_module.app.test_client()
    sign_in(other, 'alice')
    assert b'current password is wrong' in client.post('/account/password', data={
        'current': 'nope', 'password': 'a new long password', 'confirm': 'a new long password'}).data
    response = client.post('/account/password', data={'current': PASSWORD, 'password': 'a new long password',
                                                      'confirm': 'a new long password'})
    assert b'Password changed' in response.data
    assert client.get('/').status_code == 200  # this browser stays signed in
    assert other.get('/').status_code == 302

def test_a_networked_pylot_without_accounts_refuses_requests(client, monkeypatch):
    monkeypatch.setitem(app_module.app.config, 'REQUIRE_ACCOUNTS', True)
    response = client.get('/')
    assert response.status_code == 503 and b'python auth.py add' in response.data
    assert client.get('/api/networks').status_code == 503
    assert client.post('/users', data={'username': 'eve', 'password': PASSWORD, 'confirm': PASSWORD}).status_code == 503

# --- serving

@pytest.fixture
def serving(client, monkeypatch, tmp_path):
    """Undo what configure_serving changes."""
    config = app_module.app.config
    for key in ('REQUIRE_ACCOUNTS', 'SESSION_COOKIE_SECURE'):
        monkeypatch.setitem(config, key, config[key])
    monkeypatch.setitem(config, 'TRUSTED_HOSTS', list(config['TRUSTED_HOSTS']))
    monkeypatch.setattr(app_module.app, 'wsgi_app', app_module.app.wsgi_app)
    monkeypatch.setattr(app_module, 'BASE_DIR', str(tmp_path))
    monkeypatch.delenv('PYLOT_TRUSTED_HOSTS', raising=False)
    return lambda *argv: app_module.configure_serving(app_module.parse_args(list(argv)))

def test_localhost_serves_plain_http_without_accounts(serving):
    assert serving() is None
    assert not app_module.app.config['REQUIRE_ACCOUNTS']

def test_listening_beyond_this_machine_needs_accounts_and_https(serving, tmp_path):
    with pytest.raises(SystemExit, match='Add an account'):
        serving('--host', '10.1.1.5', '--cert', 'c.pem', '--key', 'k.pem')
    accounts(alice='admin')
    with pytest.raises(SystemExit, match='needs HTTPS'):
        serving('--host', '10.1.1.5')
    with pytest.raises(SystemExit, match='--debug'):
        serving('--host', '10.1.1.5', '--debug', '--behind-proxy')
    assert serving('--host', '10.1.1.5', '--cert', 'c.pem', '--key', 'k.pem') == ('c.pem', 'k.pem')
    config = app_module.app.config
    assert config['REQUIRE_ACCOUNTS'] and config['SESSION_COOKIE_SECURE'] and '10.1.1.5' in config['TRUSTED_HOSTS']

def test_behind_a_proxy(serving, client):
    accounts(alice='admin')
    assert serving('--behind-proxy') is None
    assert app_module.app.config['REQUIRE_ACCOUNTS'] and app_module.app.config['SESSION_COOKIE_SECURE']
    response = sign_in(client, 'alice', headers={'X-Forwarded-Proto': 'https'})
    assert 'Secure' in response.headers['Set-Cookie']

def test_tls_options_are_checked():
    for argv in (['--cert', 'c.pem'], ['--key', 'k.pem'], ['--self-signed', '--behind-proxy']):
        with pytest.raises(SystemExit):
            app_module.parse_args(argv)

@pytest.mark.skipif(not shutil.which('openssl'), reason='needs the openssl command')
def test_self_signed_certificates_are_made_once(serving, tmp_path):
    cert, key = serving('--self-signed')
    assert os.path.dirname(cert) == str(tmp_path / 'tls')
    assert os.stat(key).st_mode & 0o077 == 0
    fingerprint = auth.certificate_fingerprint(cert)
    assert len(fingerprint.split(':')) == 32
    assert auth.self_signed_certificate(str(tmp_path / 'tls'), [])[2] is False
    assert auth.certificate_fingerprint(cert) == fingerprint
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)  # a usable pair

def test_subject_names_are_addresses_or_host_names():
    assert auth._subject_names(['127.0.0.1', 'pylot.plant.local', '::1', 'bad name', '127.0.0.1']) == \
        ['IP:127.0.0.1', 'DNS:pylot.plant.local', 'IP:::1']

# --- command line

def test_the_command_line_manages_accounts(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('PYLOT_DB_PATH', str(tmp_path / 'cli.sqlite3'))
    monkeypatch.setattr(auth.getpass, 'getpass', lambda prompt: PASSWORD)
    with pytest.raises(SystemExit, match='first account must be an admin'):
        auth.main(['add', 'alice', '--role', 'viewer'])
    auth.main(['add', 'alice'])
    assert 'Added alice (admin)' in capsys.readouterr().out
    auth.main(['add', 'bob'])
    auth.main(['role', 'bob', 'viewer'])
    auth.main(['passwd', 'bob'])
    auth.main(['list'])
    out = capsys.readouterr().out
    assert 'bob is now viewer' in out and 'bob' in out and 'never' in out
    with pytest.raises(SystemExit, match='at least one admin'):
        auth.main(['remove', 'alice'])
    with pytest.raises(SystemExit, match='no account'):
        auth.main(['remove', 'carol'])
    auth.main(['remove', 'bob'])
    auth.main(['remove', 'alice'])
    assert 'no longer asks anyone to sign in' in capsys.readouterr().out
