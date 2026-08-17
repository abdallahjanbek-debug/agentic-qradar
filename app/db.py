"""SQLite connection handling and schema migrations.

Connections are per-thread: the poller, each engine worker, and each Flask request
thread get their own. WAL mode means readers never block writers.
"""

import os
import sqlite3
import threading

from qpylib import qpylib

_local = threading.local()

MIGRATIONS = [
    # 1
    """
    CREATE TABLE offense (
      offense_id            INTEGER PRIMARY KEY,
      first_persisted_time  INTEGER NOT NULL,
      start_time            INTEGER,
      last_updated_time     INTEGER,
      status                TEXT,
      magnitude             INTEGER,
      severity              INTEGER,
      credibility           INTEGER,
      relevance             INTEGER,
      description           TEXT,
      offense_type          INTEGER,
      offense_source        TEXT,
      event_count           INTEGER,
      flow_count            INTEGER,
      device_count          INTEGER,
      source_count          INTEGER,
      username_count        INTEGER,
      domain_id             INTEGER,
      inactive              INTEGER,
      protected             INTEGER,
      raw_json              TEXT NOT NULL,
      ingested_at           INTEGER NOT NULL
    );
    CREATE INDEX idx_offense_created ON offense(first_persisted_time);

    CREATE TABLE offense_rule (
      offense_id  INTEGER NOT NULL REFERENCES offense(offense_id) ON DELETE CASCADE,
      rule_id     INTEGER NOT NULL,
      rule_type   TEXT,
      PRIMARY KEY (offense_id, rule_id)
    );

    CREATE TABLE queue_item (
      offense_id        INTEGER PRIMARY KEY REFERENCES offense(offense_id) ON DELETE CASCADE,
      state             TEXT NOT NULL,
      enqueued_at       INTEGER NOT NULL,
      claimed_at        INTEGER,
      lease_expires_at  INTEGER,
      worker_id         TEXT,
      attempts          INTEGER NOT NULL DEFAULT 0,
      last_error        TEXT,
      updated_at        INTEGER NOT NULL
    );
    CREATE INDEX idx_queue_state ON queue_item(state, enqueued_at);
    CREATE INDEX idx_queue_lease ON queue_item(state, lease_expires_at);

    CREATE TABLE investigation (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      offense_id        INTEGER NOT NULL REFERENCES offense(offense_id) ON DELETE CASCADE,
      started_at        INTEGER NOT NULL,
      completed_at      INTEGER,
      verdict           TEXT,
      confidence        REAL,
      summary           TEXT,
      narrative         TEXT,
      result_json       TEXT,
      gate_decision     TEXT,
      model             TEXT,
      effort            TEXT,
      input_tokens      INTEGER,
      output_tokens     INTEGER,
      cache_read_tokens INTEGER,
      cost_usd_micros   INTEGER,
      stop_reason       TEXT,
      served_by_model   TEXT
    );
    CREATE INDEX idx_inv_offense ON investigation(offense_id);

    CREATE TABLE transcript (
      investigation_id  INTEGER PRIMARY KEY REFERENCES investigation(id) ON DELETE CASCADE,
      request_json      TEXT,
      response_json     TEXT,
      created_at        INTEGER NOT NULL
    );

    CREATE TABLE app_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE setting   (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);
    """,
]


def db_path() -> str:
    directory = qpylib.get_store_path("db")
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, "socai.db")


def connection() -> sqlite3.Connection:
    """Thread-local connection with pragmas applied."""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        return conn

    conn = sqlite3.connect(db_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
    _local.conn = conn
    return conn


def init_schema() -> None:
    """Apply pending migrations. Idempotent — safe to call on every start."""
    conn = connection()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"
    )
    row = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
    current = row["v"] or 0

    for index, script in enumerate(MIGRATIONS, start=1):
        if index <= current:
            continue
        qpylib.log("socai: applying schema migration {}".format(index))
        conn.executescript(script)
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (index,))
        conn.commit()


def reclaim_space() -> None:
    """Return freed pages to the filesystem after a retention purge.

    Incremental rather than a full VACUUM, which would take a long exclusive lock.
    """
    connection().execute("PRAGMA incremental_vacuum(1000)")
