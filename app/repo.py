"""Repository layer.

All SQL lives here. Swapping SQLite for PostgreSQL later means reimplementing this
module, not rewriting the services.
"""

import json
import time

from . import config
from .db import connection

OFFENSE_COLUMNS = [
    "offense_id", "first_persisted_time", "start_time", "last_updated_time",
    "status", "magnitude", "severity", "credibility", "relevance", "description",
    "offense_type", "offense_source", "event_count", "flow_count", "device_count",
    "source_count", "username_count", "domain_id", "inactive", "protected",
]


def now_ms() -> int:
    return int(time.time() * 1000)


# ── settings & state ────────────────────────────────────────────────────────

def get_setting(key: str) -> str:
    row = connection().execute(
        "SELECT value FROM setting WHERE key = ?", (key,)
    ).fetchone()
    if row is not None:
        return row["value"]
    return config.DEFAULTS.get(key, "")


def get_int(key: str) -> int:
    try:
        return int(get_setting(key))
    except (TypeError, ValueError):
        return int(config.DEFAULTS.get(key, 0))


def get_bool(key: str) -> bool:
    return get_setting(key).strip().lower() in ("1", "true", "yes", "on")


def all_settings() -> dict:
    values = dict(config.DEFAULTS)
    for row in connection().execute("SELECT key, value FROM setting"):
        values[row["key"]] = row["value"]
    return values


def set_settings(values: dict) -> None:
    conn = connection()
    stamp = now_ms()
    for key, value in values.items():
        conn.execute(
            "INSERT INTO setting (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, str(value), stamp),
        )
    conn.commit()


def get_state(key: str, default=None):
    row = connection().execute(
        "SELECT value FROM app_state WHERE key = ?", (key,)
    ).fetchone()
    return row["value"] if row else default


def set_state(key: str, value) -> None:
    conn = connection()
    conn.execute(
        "INSERT INTO app_state (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )
    conn.commit()


# ── ingest ──────────────────────────────────────────────────────────────────

def upsert_offense(offense: dict) -> bool:
    """Insert an offense and enqueue it. Returns True if newly inserted.

    Idempotent: the poll window deliberately overlaps, so re-seeing an offense is
    normal and must be a no-op.
    """
    conn = connection()
    stamp = now_ms()
    values = [offense.get(column) for column in OFFENSE_COLUMNS]

    cursor = conn.execute(
        "INSERT OR IGNORE INTO offense ({}, raw_json, ingested_at) VALUES ({})".format(
            ", ".join(OFFENSE_COLUMNS),
            ", ".join(["?"] * (len(OFFENSE_COLUMNS) + 2)),
        ),
        values + [json.dumps(offense), stamp],
    )
    inserted = cursor.rowcount > 0

    if inserted:
        offense_id = offense["offense_id"]
        for rule in offense.get("rules") or []:
            conn.execute(
                "INSERT OR IGNORE INTO offense_rule (offense_id, rule_id, rule_type) "
                "VALUES (?, ?, ?)",
                (offense_id, rule.get("id"), rule.get("type")),
            )
        conn.execute(
            "INSERT OR IGNORE INTO queue_item "
            "(offense_id, state, enqueued_at, attempts, updated_at) VALUES (?, ?, ?, 0, ?)",
            (offense_id, config.PENDING, stamp, stamp),
        )

    conn.commit()
    return inserted


# ── queue ───────────────────────────────────────────────────────────────────

def claim_next(worker_id: str):
    """Claim the oldest PENDING item by offense creation time (FIFO).

    Two statements rather than UPDATE..RETURNING, which needs SQLite >= 3.35 and
    is not guaranteed on the base image. The guarded UPDATE makes the race safe:
    a loser sees rowcount 0 and retries.
    """
    conn = connection()
    row = conn.execute(
        "SELECT q.offense_id FROM queue_item q "
        "JOIN offense o ON o.offense_id = q.offense_id "
        "WHERE q.state = ? ORDER BY o.first_persisted_time ASC LIMIT 1",
        (config.PENDING,),
    ).fetchone()
    if row is None:
        return None

    offense_id = row["offense_id"]
    stamp = now_ms()
    cursor = conn.execute(
        "UPDATE queue_item SET state = ?, claimed_at = ?, lease_expires_at = ?, "
        "worker_id = ?, attempts = attempts + 1, updated_at = ? "
        "WHERE offense_id = ? AND state = ?",
        (config.IN_PROGRESS, stamp, stamp + config.LEASE_MS, worker_id, stamp,
         offense_id, config.PENDING),
    )
    conn.commit()
    return offense_id if cursor.rowcount else None


def heartbeat(offense_id: int) -> None:
    conn = connection()
    stamp = now_ms()
    conn.execute(
        "UPDATE queue_item SET lease_expires_at = ?, updated_at = ? "
        "WHERE offense_id = ? AND state = ?",
        (stamp + config.LEASE_MS, stamp, offense_id, config.IN_PROGRESS),
    )
    conn.commit()


def finish(offense_id: int, state: str, error: str = None) -> None:
    conn = connection()
    conn.execute(
        "UPDATE queue_item SET state = ?, last_error = ?, worker_id = NULL, "
        "lease_expires_at = NULL, updated_at = ? WHERE offense_id = ?",
        (state, error, now_ms(), offense_id),
    )
    conn.commit()


def fail(offense_id: int, error: str) -> str:
    """Mark a failed attempt. Returns the resulting state."""
    conn = connection()
    row = conn.execute(
        "SELECT attempts FROM queue_item WHERE offense_id = ?", (offense_id,)
    ).fetchone()
    attempts = row["attempts"] if row else config.MAX_ATTEMPTS
    state = config.DEAD_LETTER if attempts >= config.MAX_ATTEMPTS else config.PENDING
    finish(offense_id, state, error[:2000] if error else None)
    return state


def reap_expired_leases() -> int:
    """Return items whose worker died back to PENDING."""
    conn = connection()
    stamp = now_ms()
    cursor = conn.execute(
        "UPDATE queue_item SET state = ?, worker_id = NULL, lease_expires_at = NULL, "
        "last_error = 'lease expired', updated_at = ? "
        "WHERE state = ? AND lease_expires_at IS NOT NULL AND lease_expires_at < ?",
        (config.PENDING, stamp, config.IN_PROGRESS, stamp),
    )
    conn.commit()
    return cursor.rowcount


def requeue(offense_id: int) -> None:
    conn = connection()
    stamp = now_ms()
    conn.execute(
        "UPDATE queue_item SET state = ?, attempts = 0, last_error = NULL, "
        "worker_id = NULL, lease_expires_at = NULL, updated_at = ? WHERE offense_id = ?",
        (config.PENDING, stamp, offense_id),
    )
    conn.commit()


# ── reads for the UI ────────────────────────────────────────────────────────

def state_counts() -> dict:
    rows = connection().execute(
        "SELECT state, COUNT(*) AS n FROM queue_item GROUP BY state"
    ).fetchall()
    counts = {row["state"]: row["n"] for row in rows}
    for state in (config.PENDING, config.IN_PROGRESS, config.DONE,
                  config.FAILED, config.DEAD_LETTER, config.SKIPPED):
        counts.setdefault(state, 0)
    return counts


def health() -> dict:
    conn = connection()
    oldest = conn.execute(
        "SELECT MIN(enqueued_at) AS t FROM queue_item WHERE state = ?",
        (config.PENDING,),
    ).fetchone()["t"]
    return {
        "counts": state_counts(),
        "oldest_pending_ms": oldest,
        "oldest_pending_age_seconds": int((now_ms() - oldest) / 1000) if oldest else 0,
        "watermark": get_state("watermark"),
        "last_poll_at": get_state("last_poll_at"),
        "last_poll_error": get_state("last_poll_error"),
        "connection_status": get_state("connection_status"),
        "connection_checked_at": get_state("connection_checked_at"),
        "budget_paused": get_state("budget_paused", "0"),
    }


def list_queue(state: str = None, limit: int = 100, offset: int = 0) -> list:
    sql = (
        "SELECT o.offense_id, o.description, o.magnitude, o.severity, "
        "       o.first_persisted_time, o.event_count, "
        "       q.state, q.attempts, q.last_error, q.updated_at, "
        "       i.verdict, i.confidence, i.summary "
        "  FROM queue_item q "
        "  JOIN offense o ON o.offense_id = q.offense_id "
        "  LEFT JOIN investigation i ON i.id = ("
        "        SELECT MAX(id) FROM investigation WHERE offense_id = o.offense_id) "
    )
    params = []
    if state:
        sql += " WHERE q.state = ? "
        params.append(state)
    sql += " ORDER BY o.first_persisted_time ASC LIMIT ? OFFSET ?"
    params += [limit, offset]
    return [dict(row) for row in connection().execute(sql, params)]


def get_offense(offense_id: int):
    row = connection().execute(
        "SELECT * FROM offense WHERE offense_id = ?", (offense_id,)
    ).fetchone()
    return dict(row) if row else None


def get_offense_rules(offense_id: int) -> list:
    return [dict(row) for row in connection().execute(
        "SELECT rule_id, rule_type FROM offense_rule WHERE offense_id = ?",
        (offense_id,),
    )]


def latest_investigation(offense_id: int):
    row = connection().execute(
        "SELECT * FROM investigation WHERE offense_id = ? ORDER BY id DESC LIMIT 1",
        (offense_id,),
    ).fetchone()
    return dict(row) if row else None


# ── investigations ──────────────────────────────────────────────────────────

def start_investigation(offense_id: int) -> int:
    conn = connection()
    cursor = conn.execute(
        "INSERT INTO investigation (offense_id, started_at) VALUES (?, ?)",
        (offense_id, now_ms()),
    )
    conn.commit()
    return cursor.lastrowid


def complete_investigation(investigation_id: int, result: dict, usage: dict) -> None:
    conn = connection()
    conn.execute(
        "UPDATE investigation SET completed_at = ?, verdict = ?, confidence = ?, "
        "summary = ?, narrative = ?, result_json = ?, gate_decision = ?, model = ?, "
        "effort = ?, input_tokens = ?, output_tokens = ?, cache_read_tokens = ?, "
        "cost_usd_micros = ?, stop_reason = ?, served_by_model = ? WHERE id = ?",
        (
            now_ms(),
            result.get("verdict"),
            result.get("confidence"),
            result.get("summary"),
            result.get("narrative"),
            json.dumps(result),
            usage.get("gate_decision"),
            usage.get("model"),
            usage.get("effort"),
            usage.get("input_tokens"),
            usage.get("output_tokens"),
            usage.get("cache_read_tokens"),
            usage.get("cost_usd_micros"),
            usage.get("stop_reason"),
            usage.get("served_by_model"),
            investigation_id,
        ),
    )
    conn.commit()


def save_transcript(investigation_id: int, request_json: str, response_json: str) -> None:
    conn = connection()
    conn.execute(
        "INSERT OR REPLACE INTO transcript "
        "(investigation_id, request_json, response_json, created_at) VALUES (?, ?, ?, ?)",
        (investigation_id, request_json, response_json, now_ms()),
    )
    conn.commit()


def tokens_used_today() -> int:
    cutoff = now_ms() - 24 * 60 * 60 * 1000
    row = connection().execute(
        "SELECT COALESCE(SUM(input_tokens), 0) + COALESCE(SUM(output_tokens), 0) AS n "
        "FROM investigation WHERE started_at >= ?",
        (cutoff,),
    ).fetchone()
    return row["n"] or 0


# ── retention ───────────────────────────────────────────────────────────────

def purge(investigation_days: int, transcript_days: int) -> dict:
    conn = connection()
    stamp = now_ms()

    transcript_cutoff = stamp - transcript_days * 86400000
    transcripts = conn.execute(
        "DELETE FROM transcript WHERE created_at < ?", (transcript_cutoff,)
    ).rowcount

    offense_cutoff = stamp - investigation_days * 86400000
    offenses = conn.execute(
        "DELETE FROM offense WHERE first_persisted_time < ?", (offense_cutoff,)
    ).rowcount

    conn.commit()
    return {"transcripts": transcripts, "offenses": offenses}
