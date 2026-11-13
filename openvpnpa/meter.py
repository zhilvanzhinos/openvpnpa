"""Experimental local ledger. This does NOT make panel delivery exactly-once.

Samples are cumulative per OpenVPN process epoch + client session. Only samples
already committed here survive a crash. Never invent final counters on a crash.
"""

import json
import sqlite3
import threading
from contextlib import contextmanager


class Meter:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                epoch TEXT NOT NULL, session TEXT NOT NULL, uid TEXT NOT NULL,
                up INTEGER NOT NULL, down INTEGER NOT NULL,
                closed INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (epoch, session)
            );
            CREATE TABLE IF NOT EXISTS pending (
                uid TEXT PRIMARY KEY, up INTEGER NOT NULL, down INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS outbound_pending (
                id INTEGER PRIMARY KEY CHECK(id=1), up INTEGER NOT NULL, down INTEGER NOT NULL
            );
        """)

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
            else:
                self.db.execute("COMMIT")

    def sample(self, epoch, session, uid, up, down, *, final=False):
        """Commit a cumulative sample once. Reject regressions and ID reuse.

        epoch must change for every OpenVPN process start, NOT bridge restart.
        session must never be reused in an epoch. Retain closed-session tombstones.
        """
        if not epoch or not session or not isinstance(uid, str) or not uid.isascii() or not uid.isdecimal() or int(uid) < 1:
            raise ValueError("epoch, session and a positive numeric panel UID required")
        if any(type(v) is not int or v < 0 or v > 2**63 - 1 for v in (up, down)):
            raise ValueError("counters must be nonnegative int64 values")
        with self.transaction():
            row = self.db.execute(
                "SELECT uid,up,down,closed FROM sessions WHERE epoch=? AND session=?",
                (epoch, session),
            ).fetchone()
            old_up = old_down = 0
            if row:
                old_uid, old_up, old_down, closed = row
                if old_uid != uid:
                    raise ValueError("session cannot change owner")
                if up < old_up or down < old_down:
                    raise ValueError("stale/regressing sample; a new process needs a new epoch")
                if closed:
                    if (up, down) == (old_up, old_down):
                        return
                    raise ValueError("closed session cannot receive additional traffic")
            self.db.execute(
                "INSERT INTO pending VALUES (?,?,?) ON CONFLICT(uid) DO UPDATE SET "
                "up=up+excluded.up, down=down+excluded.down",
                (uid, up-old_up, down-old_down),
            )
            self.db.execute('INSERT INTO outbound_pending VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET '
                'up=up+excluded.up,down=down+excluded.down', (up-old_up,down-old_down))
            self.db.execute(
                "INSERT INTO sessions VALUES (?,?,?,?,?,?) ON CONFLICT(epoch,session) "
                "DO UPDATE SET up=excluded.up,down=excluded.down,closed=excluded.closed",
                (epoch, session, uid, up, down, int(final)),
            )

    def stats(self, *, reset=False, uid=None):
        """Model the official destructive read; retain an audit copy locally.

        A returned report has NOT been acknowledged by the panel. Its local ID
        is absent from the official response schema. Do not auto-replay it.
        """
        with self.transaction():
            rows = self.db.execute("SELECT uid,up,down FROM pending WHERE (? IS NULL OR uid=?) ORDER BY uid", (uid,uid))
            stats = [dict(name=user_id, type="user", link=link, value=value)
                     for user_id, up, down in rows
                     for link, value in (("uplink", up), ("downlink", down)) if value]
            if reset and stats:
                self.db.execute("INSERT INTO reports(payload) VALUES (?)", (json.dumps(stats),))
                self.db.execute("DELETE FROM pending WHERE (? IS NULL OR uid=?)", (uid,uid))
            return stats

    def outbound_stats(self, reset=False):
        with self.transaction():
            row = self.db.execute('SELECT up,down FROM outbound_pending WHERE id=1').fetchone()
            stats = [] if row is None else [dict(name='openvpn-egress',type='outbound',link=link,value=value)
                for link,value in zip(('uplink','downlink'),row) if value]
            if reset:
                self.db.execute('DELETE FROM outbound_pending')
            return stats

    def audit(self):
        with self.lock:
            return [(rid, json.loads(payload)) for rid, payload in self.db.execute("SELECT id,payload FROM reports ORDER BY id")]

    def close(self):
        with self.lock:
            self.db.close()
