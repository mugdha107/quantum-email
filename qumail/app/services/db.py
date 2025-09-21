import sqlite3
import json
import os
import threading
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional


SCHEMA = [
    # Accounts (for future multi-account support)
    """
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        smtp_host TEXT, smtp_port INTEGER, smtp_starttls INTEGER,
        imap_host TEXT, imap_port INTEGER, imap_ssl INTEGER,
        username TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );
    """,
    # Messages catalog for dashboard/filtering
    """
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        external_id TEXT,
        account_id INTEGER,
        subject TEXT,
        from_addr TEXT,
        to_addrs_json TEXT,
        level INTEGER,
        direction TEXT, -- outgoing/incoming
        sent_at TEXT,
        received_at TEXT
    );
    """,
    # Audits of key usage
    """
    CREATE TABLE IF NOT EXISTS audits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT DEFAULT (datetime('now')),
        op TEXT, -- requested/consumed/cached/encrypt/decrypt
        key_id TEXT,
        client_id TEXT,
        peer_id TEXT,
        level INTEGER,
        message_id INTEGER,
        account_id INTEGER,
        tampered INTEGER DEFAULT 0,
        notes TEXT
    );
    """,
    # Key metadata (expiry / uses)
    """
    CREATE TABLE IF NOT EXISTS keys_cache (
        key_id TEXT PRIMARY KEY,
        cached_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT,
        max_uses INTEGER,
        uses INTEGER DEFAULT 0
    );
    """,
]


@dataclass
class DBConfig:
    path: str


class Database:
    def __init__(self, cfg: DBConfig):
        self.path = cfg.path
        os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    def _init_schema(self):
        with self._conn:
            for stmt in SCHEMA:
                self._conn.execute(stmt)

    def exec(self, sql: str, params: Iterable[Any] | None = None):
        with self._lock, self._conn:
            return self._conn.execute(sql, params or [])

    def log_audit(
        self,
        op: str,
        key_id: Optional[str],
        level: Optional[int],
        client_id: Optional[str] = None,
        peer_id: Optional[str] = None,
        message_id: Optional[int] = None,
        account_id: Optional[int] = None,
        tampered: bool = False,
        notes: str | None = None,
    ):
        self.exec(
            "INSERT INTO audits (op, key_id, level, client_id, peer_id, message_id, account_id, tampered, notes)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            [op, key_id, level, client_id, peer_id, message_id, account_id, 1 if tampered else 0, notes],
        )

    def upsert_message(
        self,
        external_id: str | None,
        account_id: Optional[int],
        subject: str | None,
        from_addr: str | None,
        to_addrs: list[str] | None,
        level: Optional[int],
        direction: str,
        when: str | None,
    ):
        to_json = json.dumps(to_addrs or [])
        # Simple insert; in a full app you might enforce uniqueness on external_id
        self.exec(
            "INSERT INTO messages (external_id, account_id, subject, from_addr, to_addrs_json, level, direction, sent_at, received_at)"
            " VALUES (?,?,?,?,?,?,?, CASE WHEN ?='outgoing' THEN datetime('now') END, CASE WHEN ?='incoming' THEN datetime('now') END)",
            [external_id, account_id, subject, from_addr, to_json, level, direction, direction, direction],
        )

    def update_key_meta(self, key_id: str, expires_at: Optional[str], max_uses: Optional[int], uses: Optional[int]):
        # Upsert semantics using INSERT OR REPLACE
        self.exec(
            "INSERT INTO keys_cache(key_id, expires_at, max_uses, uses) VALUES(?,?,?,?)"
            " ON CONFLICT(key_id) DO UPDATE SET expires_at=excluded.expires_at, max_uses=excluded.max_uses, uses=excluded.uses",
            [key_id, expires_at, max_uses, uses],
        )

    def increment_key_uses(self, key_id: str, inc: int = 1):
        self.exec("UPDATE keys_cache SET uses = COALESCE(uses,0) + ? WHERE key_id = ?", [inc, key_id])
