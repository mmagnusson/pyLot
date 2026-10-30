"""
Accounts and HTTPS for pyLot.

While no accounts exist pyLot asks no one to sign in, which suits a single analyst on their own machine
(it only listens on 127.0.0.1 unless told otherwise). Once the first account is added, every page needs
a signed-in user, with one of three roles:
    viewer    looks at sessions and downloads exports
    analyst   also uploads captures, runs live captures, re-analyzes and deletes sessions, names networks
    admin     also manages accounts and imports security advisories

Passwords are stored as salted scrypt hashes (werkzeug's default). A signed-in browser holds a signed
cookie naming the account and a token derived from its password hash, so changing a password or
removing the account signs out its other browsers.

Usage, with the same database as the web app (PYLOT_DB_PATH):
    python auth.py add NAME [--role admin|analyst|viewer]    add an account (asks for its password)
    python auth.py passwd NAME                                set a new password
    python auth.py role NAME ROLE                             change an account's role
    python auth.py remove NAME                                remove an account
    python auth.py list                                       list accounts
"""
import argparse
import getpass
import hashlib
import ipaddress
import os
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque

from werkzeug.security import check_password_hash, generate_password_hash

import storage

ROLES = ('viewer', 'analyst', 'admin')  # each can do everything the ones before it can
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024
USERNAME = re.compile(r'[A-Za-z0-9._@-]{1,64}')
# Checked when an account doesn't exist, so a wrong name takes as long as a wrong password
DUMMY_HASH = generate_password_hash(secrets.token_hex(16))

# --- accounts

class AccountError(ValueError):
    pass

def _public(row):
    return None if row is None else {key: row[key] for key in ('id', 'username', 'role', 'created_at', 'last_login')}

def has_users(conn):
    return conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None

def list_users(conn):
    return [_public(row) for row in conn.execute("SELECT * FROM users ORDER BY username")]

def get_user(conn, user_id):
    """The account with its password hash, or None."""
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone() if isinstance(user_id, int) else None
    return dict(row) if row else None

def find_user(conn, username):
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return dict(row) if row else None

def _check_role(role):
    if role not in ROLES:
        raise AccountError(f"role must be one of {', '.join(ROLES)}")

def _check_password(password):
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise AccountError(f'passwords need at least {MIN_PASSWORD_LENGTH} characters')
    if len(password) > MAX_PASSWORD_LENGTH:
        raise AccountError(f'passwords can have at most {MAX_PASSWORD_LENGTH} characters')

def add_user(conn, username, password, role='analyst'):
    if not isinstance(username, str) or not USERNAME.fullmatch(username):
        raise AccountError('user names are 1 to 64 letters, digits and . _ @ -')
    _check_role(role)
    _check_password(password)
    if find_user(conn, username):
        raise AccountError(f'{username} already has an account')
    with conn:
        cur = conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                           (username, generate_password_hash(password), role))
    return _public(conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone())

def set_password(conn, user_id, password):
    _check_password(password)
    with conn:
        changed = conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                               (generate_password_hash(password), user_id)).rowcount
    if not changed:
        raise AccountError('no such account')

def _other_admins(conn, user_id):
    return conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != ?", (user_id,)).fetchone()[0]

def set_role(conn, user_id, role):
    _check_role(role)
    user = get_user(conn, user_id)
    if user is None:
        raise AccountError('no such account')
    if user['role'] == 'admin' and role != 'admin' and not _other_admins(conn, user_id):
        raise AccountError('pyLot needs at least one admin account')
    with conn:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))

def remove_user(conn, user_id):
    """Removing the last account turns sign-in off, so the last admin can only go along with everyone else."""
    user = get_user(conn, user_id)
    if user is None:
        raise AccountError('no such account')
    others = conn.execute("SELECT COUNT(*) FROM users WHERE id != ?", (user_id,)).fetchone()[0]
    if user['role'] == 'admin' and others and not _other_admins(conn, user_id):
        raise AccountError('pyLot needs at least one admin account while there are others')
    with conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

def verify(conn, username, password):
    """The account if the password is right, else None."""
    user = find_user(conn, username) if isinstance(username, str) else None
    ok = check_password_hash(user['password_hash'] if user else DUMMY_HASH, password if isinstance(password, str) else '')
    return user if user and ok else None

def record_login(conn, user_id):
    with conn:
        conn.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))

def session_token(user):
    """Changes whenever the password does, so the session cookies of the old password stop working."""
    return hashlib.sha256(user['password_hash'].encode()).hexdigest()[:32]

def allowed(role, required):
    return ROLES.index(role) >= ROLES.index(required)

def secret_key(conn):
    """The key that signs session cookies, made on first use and kept in the database so sign-ins survive restarts."""
    row = conn.execute("SELECT value FROM settings WHERE key = 'secret_key'").fetchone()
    if row:
        return row['value']
    key = secrets.token_hex(32)
    with conn:
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('secret_key', ?)", (key,))
    return conn.execute("SELECT value FROM settings WHERE key = 'secret_key'").fetchone()['value']

class LoginThrottle:
    """Refuses sign-in attempts from an address after too many recent failures."""

    def __init__(self, limit=10, window=15 * 60):
        self.limit = limit
        self.window = window
        self.failures = defaultdict(deque)
        self.lock = threading.Lock()

    def _recent(self, key, now):
        failures = self.failures[key]
        while failures and failures[0] <= now - self.window:
            failures.popleft()
        return failures

    def blocked(self, key):
        """Seconds until the address may try again, or 0."""
        now = time.monotonic()
        with self.lock:
            failures = self._recent(key, now)
            if len(failures) < self.limit:
                if not failures:
                    del self.failures[key]
                return 0
            return int(failures[0] + self.window - now) + 1

    def failed(self, key):
        with self.lock:
            self._recent(key, time.monotonic()).append(time.monotonic())

    def succeeded(self, key):
        with self.lock:
            self.failures.pop(key, None)

# --- HTTPS

def _subject_names(hosts):
    names = []
    for host in dict.fromkeys(hosts):
        try:
            names.append(f'IP:{ipaddress.ip_address(host)}')
        except ValueError:
            if re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host):
                names.append(f'DNS:{host}')
    return names

def self_signed_certificate(directory, hosts):
    """
    A certificate and key for these host names and addresses, made with openssl the first time and reused
    after that (delete the directory to make a new one). Returns (certificate path, key path, created).
    """
    cert, key = os.path.join(directory, 'cert.pem'), os.path.join(directory, 'key.pem')
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key, False
    os.makedirs(directory, mode=0o700, exist_ok=True)
    names = _subject_names(['localhost', '127.0.0.1', '::1', *hosts])
    old_umask = os.umask(0o077)  # the key is readable by its owner only
    try:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
                        '-keyout', key, '-out', cert, '-days', '825', '-subj', '/CN=pyLot',
                        '-addext', f"subjectAltName={','.join(names)}"],
                       check=True, capture_output=True, timeout=60)
    except FileNotFoundError:
        raise RuntimeError('making a self-signed certificate needs the openssl command; install it or give --cert and --key')
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"openssl couldn't make a certificate: {e.stderr.decode(errors='replace').strip()}")
    finally:
        os.umask(old_umask)
    return cert, key, True

def certificate_fingerprint(cert):
    """The SHA-256 fingerprint browsers show, so a self-signed certificate can be checked before trusting it."""
    with open(cert) as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())
    return ':'.join(f'{b:02X}' for b in hashlib.sha256(der).digest())

# --- command line

def _ask_password():
    while True:
        password = getpass.getpass('Password: ')
        if getpass.getpass('Again: ') != password:
            print("The passwords don't match.")
            continue
        try:
            _check_password(password)
            return password
        except AccountError as e:
            print(f'{str(e).capitalize()}.')

def _user_or_exit(conn, username):
    user = find_user(conn, username)
    if user is None:
        sys.exit(f'{username} has no account')
    return user

def main(argv=None):
    parser = argparse.ArgumentParser(description="Manage pyLot's accounts. While there are none, pyLot asks no one to sign in.")
    commands = parser.add_subparsers(dest='command', required=True)
    add = commands.add_parser('add', help='add an account (asks for its password)')
    add.add_argument('username')
    add.add_argument('--role', choices=ROLES, help='admin for the first account, analyst after that')
    commands.add_parser('passwd', help='set a new password').add_argument('username')
    role = commands.add_parser('role', help="change an account's role")
    role.add_argument('username')
    role.add_argument('role', choices=ROLES)
    commands.add_parser('remove', help='remove an account').add_argument('username')
    commands.add_parser('list', help='list accounts')
    args = parser.parse_args(argv)
    db_path = os.environ.get('PYLOT_DB_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pylot.sqlite3'))
    storage.init_db(db_path)
    conn = storage.connect(db_path)
    try:
        if args.command == 'add':
            first = not has_users(conn)
            role = args.role or ('admin' if first else 'analyst')
            if first and role != 'admin':
                sys.exit('The first account must be an admin, so someone can manage the others')
            if find_user(conn, args.username):
                sys.exit(f'{args.username} already has an account')
            user = add_user(conn, args.username, _ask_password(), role)
            print(f"Added {user['username']} ({user['role']}).")
            if first:
                print('pyLot now asks everyone to sign in.')
        elif args.command == 'passwd':
            user = _user_or_exit(conn, args.username)
            set_password(conn, user['id'], _ask_password())
            print(f"Changed {user['username']}'s password; browsers signed in with the old one are signed out.")
        elif args.command == 'role':
            user = _user_or_exit(conn, args.username)
            set_role(conn, user['id'], args.role)
            print(f"{user['username']} is now {args.role}.")
        elif args.command == 'remove':
            user = _user_or_exit(conn, args.username)
            remove_user(conn, user['id'])
            print(f"Removed {user['username']}.")
            if not has_users(conn):
                print('No accounts are left, so pyLot no longer asks anyone to sign in.')
        else:
            users = list_users(conn)
            for user in users:
                print(f"{user['username']:<24} {user['role']:<8} last signed in {user['last_login'] or 'never'}")
            if not users:
                print('No accounts, so pyLot asks no one to sign in.')
    except AccountError as e:
        sys.exit(f'{str(e).capitalize()}.')
    finally:
        conn.close()

if __name__ == '__main__':
    sys.exit(main())
