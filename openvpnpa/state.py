"""Local account mappings; authoritative permission arrives from the node API."""
import json
import threading
import time

from .meter import Meter


class State(Meter):
    def __init__(self, path, tag, lease=120):
        super().__init__(path)
        self.tag, self.lease = tag, lease
        self.started = False  # fail closed until a fresh panel Start
        self.last_request = 0.0
        self.last_start_config = None
        self.revoke = lambda _uid: None
        self.db.execute('CREATE TABLE IF NOT EXISTS accounts (uid TEXT PRIMARY KEY, username TEXT NOT NULL, payload TEXT NOT NULL, checked REAL NOT NULL, enrolled INTEGER NOT NULL DEFAULT 0)')
        self.db.execute('CREATE TABLE IF NOT EXISTS permissions (uid TEXT PRIMARY KEY, allowed INTEGER NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS local_settings (name TEXT PRIMARY KEY, payload TEXT NOT NULL)')

    def setting(self, name, default=None):
        with self.lock:
            row = self.db.execute('SELECT payload FROM local_settings WHERE name=?',(name,)).fetchone()
            return json.loads(row[0]) if row else default

    def save_setting(self, name, value):
        with self.transaction():
            self.db.execute('INSERT INTO local_settings VALUES (?,?) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload',
                (name,json.dumps(value)))

    def touch(self):
        with self.lock:
            self.last_request = time.monotonic()

    def synced(self, users, *, full=False):
        rows = []
        for user in users:
            if not user.email.isascii() or not user.email.isdecimal() or int(user.email) < 1:
                raise ValueError('numeric panel UID required')
            rows.append((str(int(user.email)), int(self.tag in user.inbounds)))
        with self.transaction():
            previous = {uid for uid, in self.db.execute('SELECT uid FROM permissions WHERE allowed=1')}
            if full:
                self.db.execute('DELETE FROM permissions')
            self.db.executemany('INSERT INTO permissions VALUES (?,?) ON CONFLICT(uid) DO UPDATE SET allowed=excluded.allowed', rows)
            current = {uid for uid, in self.db.execute('SELECT uid FROM permissions WHERE allowed=1')}
        for uid in previous-current:
            self.revoke(uid)

    def enroll(self, user):
        self.cache_user(user, enroll=True)

    def cache_user(self, user, *, enroll=False):
        uid = str(int(user['id']))
        if int(uid) < 1 or not user.get('username'):
            raise ValueError('invalid panel user response')
        # Keep only fields needed by this service, not proxy passwords.
        selected = {key:user.get(key) for key in ('id','username','status','expire','data_limit','used_traffic')}
        with self.transaction():
            self.db.execute('INSERT INTO accounts VALUES (?,?,?,?,?) ON CONFLICT(uid) DO UPDATE SET '
                'username=excluded.username,payload=excluded.payload,checked=excluded.checked,enrolled=MAX(accounts.enrolled,excluded.enrolled)',
                (uid,user['username'],json.dumps(selected),time.time(),int(enroll)))
        return uid

    def users(self):
        with self.lock:
            return [json.loads(payload) for payload, in self.db.execute('SELECT payload FROM accounts WHERE enrolled=1 ORDER BY CAST(uid AS INTEGER)')]

    def authorized(self, uid):
        from .panel import active
        with self.lock:
            if not self.started or time.monotonic()-self.last_request > self.lease:
                return False
            row = self.db.execute('SELECT a.payload,a.checked,a.enrolled,p.allowed FROM accounts a JOIN permissions p ON a.uid=p.uid WHERE a.uid=?', (uid,)).fetchone()
            if not row:
                return False
            payload, checked, enrolled, allowed = row
            try:
                return bool(enrolled and allowed and time.time()-checked < 45 and active(json.loads(payload)))
            except (ValueError, TypeError):
                return False

    def stop(self):
        with self.lock:
            self.started = False
        for user in self.users():
            self.revoke(str(user['id']))
