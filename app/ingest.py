"""Offense poller — the `socai-ingest` named service.

Watermark-based incremental poll on first_persisted_time. Also owns the lease
reaper and the daily retention purge.
"""

import time

from qpylib import qpylib

from . import config, db, qradar, repo

PURGE_INTERVAL_SECONDS = 24 * 60 * 60


def _initial_watermark() -> int:
    backfill_days = repo.get_int("backfill_days")
    return repo.now_ms() - backfill_days * 86400000


def _map_offense(raw: dict) -> dict:
    """QRadar's offense object into our column names."""
    return {
        "offense_id": raw.get("id"),
        "first_persisted_time": raw.get("first_persisted_time"),
        "start_time": raw.get("start_time"),
        "last_updated_time": raw.get("last_updated_time"),
        "status": raw.get("status"),
        "magnitude": raw.get("magnitude"),
        "severity": raw.get("severity"),
        "credibility": raw.get("credibility"),
        "relevance": raw.get("relevance"),
        "description": (raw.get("description") or "").strip(),
        "offense_type": raw.get("offense_type"),
        "offense_source": raw.get("offense_source"),
        "event_count": raw.get("event_count"),
        "flow_count": raw.get("flow_count"),
        "device_count": raw.get("device_count"),
        "source_count": raw.get("source_count"),
        "username_count": raw.get("username_count"),
        "domain_id": raw.get("domain_id"),
        "inactive": 1 if raw.get("inactive") else 0,
        "protected": 1 if raw.get("protected") else 0,
        "rules": raw.get("rules") or [],
        "source_address_ids": raw.get("source_address_ids") or [],
        "local_destination_address_ids": raw.get("local_destination_address_ids") or [],
        "log_sources": raw.get("log_sources") or [],
    }


def poll_once() -> int:
    watermark = repo.get_state("watermark")
    watermark = int(watermark) if watermark else _initial_watermark()

    offenses = qradar.fetch_offenses_since(watermark)
    if not offenses:
        repo.set_state("last_poll_at", repo.now_ms())
        repo.set_state("last_poll_error", "")
        return 0

    ingested = 0
    highest = watermark
    for raw in offenses:
        mapped = _map_offense(raw)
        if mapped["offense_id"] is None or mapped["first_persisted_time"] is None:
            continue
        if repo.upsert_offense(mapped):
            ingested += 1
        highest = max(highest, mapped["first_persisted_time"])

    # Roll back slightly so equal-timestamp rows straddling a page boundary are
    # re-fetched next pass. The re-fetch is a no-op thanks to INSERT OR IGNORE.
    repo.set_state("watermark", max(highest - config.WATERMARK_OVERLAP_MS, watermark))
    repo.set_state("last_poll_at", repo.now_ms())
    repo.set_state("last_poll_error", "")
    return ingested


def main() -> None:
    qpylib.create_log()
    db.init_schema()
    qpylib.log("socai-ingest: starting")

    last_purge = 0.0
    backoff = 0

    while True:
        try:
            ingested = poll_once()
            if ingested:
                qpylib.log("socai-ingest: ingested {} offense(s)".format(ingested))
            backoff = 0
        except Exception as error:
            backoff = min(backoff * 2 + 30, 600)
            repo.set_state("last_poll_error", str(error)[:500])
            qpylib.log("socai-ingest: poll failed: {}".format(error), level="ERROR")

        try:
            reaped = repo.reap_expired_leases()
            if reaped:
                qpylib.log("socai-ingest: reaped {} expired lease(s)".format(reaped))
        except Exception as error:
            qpylib.log("socai-ingest: reaper failed: {}".format(error), level="ERROR")

        if time.time() - last_purge > PURGE_INTERVAL_SECONDS:
            try:
                removed = repo.purge(
                    repo.get_int("retention_investigation_days"),
                    repo.get_int("retention_transcript_days"),
                )
                db.reclaim_space()
                qpylib.log("socai-ingest: purge removed {}".format(removed))
            except Exception as error:
                qpylib.log("socai-ingest: purge failed: {}".format(error), level="ERROR")
            last_purge = time.time()

        time.sleep(backoff or repo.get_int("poll_interval_seconds"))


if __name__ == "__main__":
    main()
