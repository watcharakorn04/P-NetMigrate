"""SQLite persistence (proposal §2.3.2 item 2: a single SQLite file that survives restarts).

Built on the stdlib `sqlite3` module. Tables are created automatically on first use.

Security: nothing stored here may contain a credential.
  * conversions.input_text is the source AFTER `strip_secrets` (stripped lines are replaced by
    a fixed-text advisory, so line numbers still line up for the before/after view);
  * conversions.output_text / lines_json are the converted lines, which never hold secrets;
  * devices has no username/password columns at all;
  * deployments stores the filtered command list and the log, never the SSH credentials.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS conversions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at            TEXT    NOT NULL,
    kind                  TEXT    NOT NULL DEFAULT 'single',   -- single | batch
    batch_id              TEXT,
    filename              TEXT,
    hostname              TEXT,
    direction             TEXT    NOT NULL,                    -- c2h | h2c
    source_vendor         TEXT    NOT NULL,
    target_vendor         TEXT    NOT NULL,
    requested_mode        TEXT    NOT NULL,
    effective_mode        TEXT    NOT NULL,
    coverage_percent      REAL    NOT NULL DEFAULT 0,
    total_lines           INTEGER NOT NULL DEFAULT 0,
    unsupported_lines     INTEGER NOT NULL DEFAULT 0,
    count_rule            INTEGER NOT NULL DEFAULT 0,
    count_ai              INTEGER NOT NULL DEFAULT 0,
    count_system          INTEGER NOT NULL DEFAULT 0,
    count_unconverted     INTEGER NOT NULL DEFAULT 0,
    count_not_needed      INTEGER NOT NULL DEFAULT 0,
    review_count          INTEGER NOT NULL DEFAULT 0,
    secret_stripped_count INTEGER NOT NULL DEFAULT 0,
    warnings_count        INTEGER NOT NULL DEFAULT 0,
    input_text            TEXT    NOT NULL,
    output_text           TEXT    NOT NULL,
    lines_json            TEXT    NOT NULL,
    warnings_json         TEXT    NOT NULL DEFAULT '[]',
    notices_json          TEXT    NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS ix_conversions_created ON conversions(created_at);
CREATE INDEX IF NOT EXISTS ix_conversions_batch ON conversions(batch_id);

CREATE TABLE IF NOT EXISTS batch_skipped (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    filename   TEXT NOT NULL,
    reason     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_batch_skipped_batch ON batch_skipped(batch_id);

CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    vendor      TEXT    NOT NULL,                -- cisco_ios_xe | huawei_vrp
    os_version  TEXT    NOT NULL DEFAULT '',
    model       TEXT    NOT NULL DEFAULT '',     -- key of app.core.hardware.CATALOG ('' = unknown)
    ssh_port    INTEGER NOT NULL DEFAULT 22,
    location    TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'active',
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS deployments (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     TEXT    NOT NULL,
    finished_at    TEXT,
    device_id      INTEGER,
    device_name    TEXT    NOT NULL DEFAULT '',
    host           TEXT    NOT NULL DEFAULT '',
    vendor         TEXT    NOT NULL,
    mode           TEXT    NOT NULL,             -- simulation | live
    status         TEXT    NOT NULL,             -- running | success | failed
    conversion_id  INTEGER,
    commands_json  TEXT    NOT NULL,
    removed_json   TEXT    NOT NULL,
    log_json       TEXT    NOT NULL DEFAULT '[]'
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def path_from_url(url: str) -> Path:
    """'sqlite:///./netmigrate.db' -> Path('./netmigrate.db')."""
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        raise ValueError("DATABASE_URL must look like sqlite:///path/to/file.db")
    return Path(url[len(prefix):])


class Database:
    """Thin wrapper: one short-lived connection per unit of work, schema auto-created."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            with self._lock:
                yield conn
                conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


_instances: dict[str, Database] = {}
_instances_lock = threading.Lock()


def database_for(url: str) -> Database:
    """Process-wide Database for a DATABASE_URL (created and initialised on first use)."""
    with _instances_lock:
        db = _instances.get(url)
        if db is None:
            db = _instances[url] = Database(path_from_url(url))
        return db
