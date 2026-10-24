"""Armazenamento SQLite: consultas, aparelhos, sessões, configurações e auditoria."""
from __future__ import annotations

import sqlite3
import threading
import time
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS queries (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    ip      TEXT NOT NULL,
    domain  TEXT NOT NULL,
    qtype   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts);
CREATE INDEX IF NOT EXISTS idx_queries_ip_ts ON queries(ip, ts);
CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain);

CREATE TABLE IF NOT EXISTS devices (
    ip         TEXT PRIMARY KEY,
    name       TEXT NOT NULL DEFAULT '',
    host       TEXT NOT NULL DEFAULT '',
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    created    REAL NOT NULL,
    expires    REAL NOT NULL,
    ip         TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires);

CREATE TABLE IF NOT EXISTS audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    ip         TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit(action, ts);
"""


def start_of_today() -> float:
    now = datetime.now()
    return datetime(now.year, now.month, now.day).timestamp()


class Store:
    """Acesso thread-safe ao banco (uma conexão + lock)."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, timeout=15.0)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.commit()

    # ------------------------------------------------------------------ escrita

    def add_query(self, ip: str, domain: str, qtype: str = "", ts: float | None = None) -> int:
        ts = time.time() if ts is None else ts
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO queries (ts, ip, domain, qtype) VALUES (?, ?, ?, ?)",
                (ts, ip, domain, qtype),
            )
            self._conn.execute(
                "INSERT INTO devices (ip, first_seen, last_seen) VALUES (?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen",
                (ip, ts, ts),
            )
            self._conn.commit()
            return int(cur.lastrowid or 0)

    def set_device_name(self, ip: str, name: str) -> None:
        name = (name or "").strip()[:60]
        with self._lock:
            self._conn.execute(
                "INSERT INTO devices (ip, name, first_seen, last_seen) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET name = excluded.name",
                (ip, name, time.time(), time.time()),
            )
            self._conn.commit()

    def set_device_host(self, ip: str, host: str) -> None:
        host = (host or "").strip()[:80]
        with self._lock:
            self._conn.execute("UPDATE devices SET host = ? WHERE ip = ?", (host, ip))
            self._conn.commit()

    def cleanup(self, retention_days: int) -> int:
        cutoff = time.time() - retention_days * 86400
        with self._lock:
            cur = self._conn.execute("DELETE FROM queries WHERE ts < ?", (cutoff,))
            self._conn.execute("DELETE FROM audit WHERE ts < ?", (cutoff,))
            self._conn.execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
            self._conn.commit()
            return cur.rowcount or 0

    def reset(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM queries")
            self._conn.execute("DELETE FROM devices")
            self._conn.commit()

    # ------------------------------------------------------------------ configurações

    def get_setting(self, key: str, default: str = "") -> str:
        with self._lock:
            row = self._conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._conn.commit()

    def has_password(self) -> bool:
        return bool(self.get_setting("password_hash"))

    # ------------------------------------------------------------------ sessões

    def create_session(self, token_hash: str, hours: float, ip: str, ua: str) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO sessions (token_hash, created, expires, ip, user_agent) "
                "VALUES (?, ?, ?, ?, ?)",
                (token_hash, now, now + hours * 3600, ip, ua[:160]),
            )
            self._conn.execute("DELETE FROM sessions WHERE expires < ?", (now,))
            self._conn.commit()

    def session_valid(self, token_hash: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT created, expires, ip, user_agent FROM sessions WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
        if not row:
            return None
        if row["expires"] < time.time():
            self.delete_session(token_hash)
            return None
        return dict(row)

    def delete_session(self, token_hash: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            self._conn.commit()

    def delete_all_sessions(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions")
            self._conn.commit()

    def delete_other_sessions(self, keep_hash: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE token_hash <> ?", (keep_hash,))
            self._conn.commit()

    # ------------------------------------------------------------------ auditoria

    def audit(self, ip: str, action: str, detail: str = "", ua: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit (ts, ip, action, detail, user_agent) VALUES (?, ?, ?, ?, ?)",
                (time.time(), ip[:64], action[:40], detail[:200], ua[:160]),
            )
            self._conn.commit()

    def audit_list(self, limit: int = 120, action: str = "") -> list[dict]:
        limit = max(1, min(int(limit), 500))
        sql = "SELECT id, ts, ip, action, detail, user_agent FROM audit"
        params: list[object] = []
        if action:
            sql += " WHERE action = ?"
            params.append(action)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = [dict(r) for r in self._conn.execute(sql, params)]
        return rows

    def audit_actions(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT action, COUNT(*) AS total FROM audit GROUP BY action ORDER BY total DESC"
            )
            return [dict(r) for r in rows]

    def recent_failures(self, ip: str, window_seconds: int) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM audit WHERE action = 'login_fail' AND ip = ? AND ts >= ?",
                (ip, time.time() - window_seconds),
            ).fetchone()
        return int(row[0])

    def last_action_ts(self, ip: str, action: str) -> float:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(ts) FROM audit WHERE ip = ? AND action = ?",
                (ip, action),
            ).fetchone()
        return float(row[0] or 0.0)

    def audit_rows(self):
        with self._lock:
            cur = self._conn.execute(
                "SELECT ts, ip, action, detail, user_agent FROM audit ORDER BY id ASC"
            )
            for r in cur:
                yield dict(r)

    # ------------------------------------------------------------------ consultas

    def recent(self, after_id: int = 0, limit: int = 200, search: str = "", ip: str = "") -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        where = ["q.id > ?"]
        params: list[object] = [int(after_id)]
        if ip:
            where.append("q.ip = ?")
            params.append(ip)
        if search:
            where.append("(q.domain LIKE ? OR d.name LIKE ? OR d.host LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])
        params.append(limit)

        sql = f"""
            SELECT q.id, q.ts, q.ip, q.domain, q.qtype,
                   COALESCE(d.name, '') AS name,
                   COALESCE(d.host, '') AS host
            FROM queries q
            LEFT JOIN devices d ON d.ip = q.ip
            WHERE {' AND '.join(where)}
            ORDER BY q.id DESC
            LIMIT ?
        """
        with self._lock:
            rows = [dict(r) for r in self._conn.execute(sql, params)]
        rows.reverse()
        return rows

    def export_rows(self):
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT q.ts, q.ip, COALESCE(d.name, '') AS name,
                       COALESCE(d.host, '') AS host, q.domain, q.qtype
                FROM queries q LEFT JOIN devices d ON d.ip = q.ip
                ORDER BY q.id ASC
                """
            )
            for r in cur:
                yield dict(r)

    def stats(self) -> dict:
        since = start_of_today()
        with self._lock:
            total = self._conn.execute(
                "SELECT COUNT(*) FROM queries WHERE ts >= ?", (since,)
            ).fetchone()[0]
            unique = self._conn.execute(
                "SELECT COUNT(DISTINCT domain) FROM queries WHERE ts >= ?", (since,)
            ).fetchone()[0]
            active = self._conn.execute(
                "SELECT COUNT(DISTINCT ip) FROM queries WHERE ts >= ?", (since,)
            ).fetchone()[0]

            top = [
                dict(r)
                for r in self._conn.execute(
                    """
                    SELECT domain, COUNT(*) AS hits
                    FROM queries
                    WHERE ts >= ?
                    GROUP BY domain
                    ORDER BY hits DESC, domain ASC
                    LIMIT 10
                    """,
                    (since,),
                )
            ]

            devices = [
                dict(r)
                for r in self._conn.execute(
                    """
                    SELECT d.ip, d.name, d.host, d.last_seen,
                           (SELECT COUNT(*) FROM queries q WHERE q.ip = d.ip AND q.ts >= ?) AS hits
                    FROM devices d
                    ORDER BY hits DESC, d.last_seen DESC
                    """,
                    (since,),
                )
            ]

            last_id = self._conn.execute("SELECT COALESCE(MAX(id), 0) FROM queries").fetchone()[0]
            last_ts = self._conn.execute("SELECT COALESCE(MAX(ts), 0) FROM queries").fetchone()[0]

        return {
            "today_total": total,
            "today_unique": unique,
            "today_devices": active,
            "top_domains": top,
            "devices": devices,
            "max_id": last_id,
            "last_query_ts": last_ts,
        }
