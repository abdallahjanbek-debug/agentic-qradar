# Step 1 — Offense Ingestion & Queue

Status: **approved, not yet implemented**
Last updated: 2026-08-17

---

## 1. Goal

Pull offenses out of QRadar into a durable queue inside the app, and give operators
visibility into that queue: what is pending, what is being investigated, what is done.

This step covers ingestion, queue mechanics, storage, and the queue tab data model.
It does **not** cover the investigation logic itself (step 3) or the LLM prompt
contract (step 3a).

---

## 2. Decisions

| Decision | Value | Notes |
|---|---|---|
| Deployment | Everything inside the QRadar app container | App Framework v2, Python 3, Flask, supervisord |
| Memory allocation | `"resources": 1024` (MB) in `manifest.json` | Up from the 200 MB default |
| Datastore | SQLite (WAL mode) in `/opt/app-root/store/db/` | See §5 for rationale |
| Expected volume | ~1,000 offenses/day | ~365k rows/year |
| Ingest filter | **All offenses.** No filtering. | Rule-based filtering explicitly out of scope |
| Investigation trigger | **Offense creation only.** No re-investigation on update. | See §9 — known limitation |
| Poll watermark | `first_persisted_time` | Monotonic per offense; see §4 |
| Backfill on first run | 1 day | Configurable |
| Queue ordering | **FIFO by offense creation time** (`first_persisted_time ASC`) | No priority, no starvation guard |
| Worker concurrency | 4 (configurable) | See §8 — throughput is tight |
| Investigation retention | 365 days (configurable) | Deletes the whole record |
| Transcript retention | 30 days (configurable) | Deletes raw LLM payloads only |

---

## 3. Architecture

```
        QRadar Console
              │
              │  GET /api/siem/offenses      (service token, Version header)
              ▼
      ┌───────────────────┐
      │  ingest service   │   named service, supervisord
      │  (poller thread)  │   watermark-based incremental poll
      └─────────┬─────────┘
                │ upsert
                ▼
      ┌───────────────────────────────────────┐
      │   SQLite  /opt/app-root/store/db/      │
      │   offense · offense_rule · queue_item  │
      │   investigation · transcript           │
      │   app_state · setting                  │
      └─────┬───────────────────────────┬─────┘
            │ claim (lease)             │ read
            ▼                           ▼
      ┌───────────────────┐     ┌───────────────────┐
      │  engine service   │     │   Flask app       │
      │  N worker threads │     │   REST + Queue tab │
      └───────────────────┘     └───────────────────┘
```

Two named services declared in `manifest.json` (`services[]`), each run by supervisord:

- **`socai-ingest`** — the offense poller. Single thread, single writer for new rows.
- **`socai-engine`** — the investigation worker pool. N threads claiming queue items.

Flask serves the Queue tab (`areas[]`) and the admin settings page
(`configuration_pages[]`). Keeping ingest and engine as separate supervisord
programs means one can crash and restart without taking the other down.

---

## 4. Polling design

### Endpoint

```
GET /api/siem/offenses
  ?filter=first_persisted_time > <watermark>
  &sort=+first_persisted_time
  &fields=<explicit field list>
Headers:
  SEC: <service token>          (injected via qpylib)
  Version: <api version>        (required — apps must pin the API version)
  Range: items=0-499            (paging is a HEADER, not a query param)
```

`first_persisted_time` and `last_persisted_time` are both filterable and sortable.
Because we investigate on creation only, **`first_persisted_time` is the watermark** —
it is set once when the offense is created and never moves. This is materially
simpler than watermarking on `last_persisted_time`, which mutates continuously on
active offenses.

### Loop

1. Read `watermark` from `app_state` (on first run: `now - backfill_days`).
2. Page through results with `Range: items=N-N+499` until a short page is returned.
3. For each offense: `INSERT OR IGNORE` into `offense`, insert `offense_rule` rows,
   `INSERT OR IGNORE` into `queue_item` with state `PENDING`.
4. Advance `watermark` to the highest `first_persisted_time` seen, **minus a small
   overlap** (default 5s), and commit it in the same transaction as the rows.
5. Sleep `poll_interval` (default 60s).

### Correctness notes

- **Overlap + idempotent upsert.** Offenses sharing an identical
  `first_persisted_time` can straddle a page boundary. The overlap re-fetches a few
  records; `INSERT OR IGNORE` on the `offense_id` primary key makes that a no-op.
- **Watermark commits atomically with the rows.** If the container dies mid-page,
  the watermark has not advanced past uncommitted rows, so the next run re-fetches
  them. At-least-once delivery, deduplicated by primary key.
- **`fields=` is explicit.** Requesting the full offense object on every poll is
  wasteful; we name the fields we store.
- **Rate limiting.** If QRadar returns 429 or 5xx, back off exponentially and do not
  advance the watermark.

---

## 5. Why SQLite

Everything runs inside the app container, and the app container has a hard memory
ceiling: 1024 MB requested here, against a console-wide cap of *10% of total console
memory across all installed apps*.

PostgreSQL as a sidecar service would consume 100 MB+ RSS before storing a row —
a significant fraction of our budget spent on a database engine we do not need at
this scale. SQLite is a library, not a server: no extra process, negligible memory
overhead, and it handles a few hundred thousand rows comfortably.

Write pressure is low. 1,000 offenses/day averages **one insert per 86 seconds**.
Even at 50× burst this is nothing for SQLite.

Configuration:

- `journal_mode = WAL` — readers (the UI) never block writers (poller, workers).
- `busy_timeout = 5000` — concurrent writers retry instead of raising
  `SQLITE_BUSY`.
- `synchronous = NORMAL` — safe under WAL, much faster than `FULL`.
- `foreign_keys = ON`.
- `auto_vacuum = INCREMENTAL` — see §7.

All DB access goes behind a thin repository layer so PostgreSQL is a swap rather
than a rewrite if the deployment ever outgrows this.

---

## 6. Schema

Timestamps are **milliseconds since epoch** throughout, matching QRadar's convention.

```sql
-- ── offense: the QRadar-side facts, as fetched ──────────────────────────────
CREATE TABLE offense (
  offense_id            INTEGER PRIMARY KEY,   -- QRadar offense id
  first_persisted_time  INTEGER NOT NULL,      -- creation; the poll watermark field
  start_time            INTEGER,
  last_updated_time     INTEGER,
  status                TEXT,                  -- OPEN | HIDDEN | CLOSED at ingest
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
  inactive              INTEGER,               -- 0/1
  protected             INTEGER,               -- 0/1
  raw_json              TEXT NOT NULL,         -- full API payload, verbatim
  ingested_at           INTEGER NOT NULL
);
CREATE INDEX idx_offense_created ON offense(first_persisted_time);

-- ── contributing rules: evidence for the investigation, not a filter ────────
CREATE TABLE offense_rule (
  offense_id  INTEGER NOT NULL REFERENCES offense(offense_id) ON DELETE CASCADE,
  rule_id     INTEGER NOT NULL,
  rule_type   TEXT,                            -- CRE_RULE | ADE_RULE | BUILDING_BLOCK_RULE
  PRIMARY KEY (offense_id, rule_id)
);

-- ── queue_item: the state machine ───────────────────────────────────────────
CREATE TABLE queue_item (
  offense_id        INTEGER PRIMARY KEY REFERENCES offense(offense_id) ON DELETE CASCADE,
  state             TEXT NOT NULL,             -- see §7
  enqueued_at       INTEGER NOT NULL,
  claimed_at        INTEGER,
  lease_expires_at  INTEGER,
  worker_id         TEXT,
  attempts          INTEGER NOT NULL DEFAULT 0,
  last_error        TEXT,
  updated_at        INTEGER NOT NULL
);
CREATE INDEX idx_queue_state    ON queue_item(state, enqueued_at);
CREATE INDEX idx_queue_lease    ON queue_item(state, lease_expires_at);

-- ── investigation: the verdict and narrative (survives transcript purge) ────
CREATE TABLE investigation (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  offense_id        INTEGER NOT NULL REFERENCES offense(offense_id) ON DELETE CASCADE,
  started_at        INTEGER NOT NULL,
  completed_at      INTEGER,
  verdict           TEXT,                      -- TRUE_POSITIVE | FALSE_POSITIVE | ESCALATE | INCONCLUSIVE
  confidence        REAL,
  narrative         TEXT,
  evidence_json     TEXT,
  gate_decision     TEXT,                      -- CLOSED_BY_GATE | ESCALATED_TO_DEEP
  model             TEXT,
  effort            TEXT,
  input_tokens      INTEGER,
  output_tokens     INTEGER,
  cache_read_tokens INTEGER,
  cost_usd_micros   INTEGER,
  stop_reason       TEXT,                      -- incl. "refusal"
  served_by_model   TEXT                       -- differs from `model` when a fallback served
);
CREATE INDEX idx_inv_offense ON investigation(offense_id);

-- ── transcript: heavy, short-lived, purged independently ────────────────────
CREATE TABLE transcript (
  investigation_id  INTEGER PRIMARY KEY REFERENCES investigation(id) ON DELETE CASCADE,
  request_json      TEXT,
  response_json     TEXT,
  created_at        INTEGER NOT NULL
);

-- ── app_state / setting ─────────────────────────────────────────────────────
CREATE TABLE app_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE setting   (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);
```

### Migrations

Schema migrations must be **idempotent at startup** — `/opt/app-root/store` persists
across app stop/start and upgrade, and the app has no separate migration step.
A `schema_version` row in `app_state` plus ordered, forward-only migration scripts
run on boot before either named service starts accepting work.

---

## 7. Queue mechanics

### State machine

```
   PENDING ──claim──▶ IN_PROGRESS ──▶ DONE
      ▲                    │
      │                    ├──▶ FAILED ──retry──▶ PENDING
      └──lease expiry──────┘         └──attempts > max──▶ DEAD_LETTER
```

`SKIPPED` exists in the enum but is unused while the ingest filter accepts
everything. It is retained so a future filter can record deliberate exclusions
visibly rather than dropping them silently.

### Claiming (lease-based)

A worker claims the oldest `PENDING` item and stamps a lease. If the worker dies,
the lease expires and a reaper returns the item to `PENDING`. Without this, a
container restart mid-investigation strands offenses in `IN_PROGRESS` permanently.

Portable claim (no reliance on `RETURNING`, which needs SQLite ≥ 3.35):

```sql
-- 1. select candidate
SELECT q.offense_id
  FROM queue_item q
  JOIN offense o USING (offense_id)
 WHERE q.state = 'PENDING'
 ORDER BY o.first_persisted_time ASC
 LIMIT 1;

-- 2. claim it, guarded on state (loser of a race gets rowcount 0 and retries)
UPDATE queue_item
   SET state = 'IN_PROGRESS',
       claimed_at = :now,
       lease_expires_at = :now + :lease_ms,
       worker_id = :worker_id,
       attempts = attempts + 1,
       updated_at = :now
 WHERE offense_id = :offense_id
   AND state = 'PENDING';
```

- **Lease duration**: 10 minutes, extended by a heartbeat every 60s while working.
- **Reaper**: runs every 60s, resets items where
  `state='IN_PROGRESS' AND lease_expires_at < now`.
- **Max attempts**: 3, then `DEAD_LETTER`.

### Ordering

FIFO on `offense.first_persisted_time ASC`. Offenses are investigated in the order
QRadar created them. No priority, no promotion.

---

## 8. Throughput

1,000 offenses/day is **one offense every 86 seconds**, sustained.

A single investigation — several AQL enrichment queries plus an LLM call — is
expected to take 60–120 seconds. **One worker cannot keep up**: at 90s/investigation
a single worker maxes out near 960/day with zero margin, and the queue would grow
monotonically.

Default worker concurrency is **4**, giving roughly 4× headroom for bursts and for
investigations that run long. This is a settings-page value so it can be tuned
against observed console behaviour.

The Queue tab must surface **queue depth and oldest-pending age** prominently —
those two numbers are the early warning that concurrency is set too low.

---

## 9. Known limitation: creation-only investigation

**Decided: investigate on creation only.** An offense is investigated once, shortly
after QRadar creates it, and never revisited.

QRadar offenses are living objects — the same `offense_id` keeps absorbing events,
and magnitude, event count, source addresses, and contributing rules all grow over
time. An offense investigated at creation is judged on the evidence available in its
first minutes.

Consequence: an offense that is genuinely benign at 4 events and genuinely malicious
at 2,400 events will be recorded with the verdict from the first evaluation. Slow-burn
activity will be under-called.

This is accepted for the current scope. Re-investigation on material change
(magnitude/severity increase, event-count multiple, new contributing rules, new
source addresses) is an **additive** change: it needs a `generation` column on
`investigation` and a re-enqueue predicate in the poller, and does not require
reworking the schema or state machine. It is deferred, not designed out.

---

## 10. Retention

Two independent retention windows, because the heavy data and the valuable data
have different useful lifetimes.

| Setting | Default | Deletes |
|---|---|---|
| `retention_investigation_days` | 365 | `offense` row and everything cascading from it |
| `retention_transcript_days` | 30 | `transcript` rows only; verdict and narrative survive |

Storage projection at 1,000/day:

```
offense metadata + evidence     ~2–5 KB each  × 365k  ≈ 1.5 GB   (kept 1 year)
raw LLM transcripts            ~50–200 KB each × 30k  ≈ 1.5–6 GB (kept 30 days)
```

Retaining transcripts for a full year would reach 18–70 GB and is the reason for
the split window.

**Vacuuming matters.** Deleting rows in SQLite does not shrink the file. With
`auto_vacuum = INCREMENTAL`, the purge job runs `PRAGMA incremental_vacuum(N)` after
each pass to reclaim pages gradually, avoiding the long exclusive lock a full
`VACUUM` would take.

The purge job runs once daily inside the ingest service.

---

## 11. Queue tab (`areas[]`)

Data the tab needs — no `required_capabilities`, so all analysts can view it:

- **Summary counts** by state: pending / in progress / done / failed / dead-letter.
- **Health**: queue depth, oldest pending age, last successful poll, watermark.
- **List** with filters (state, date range, magnitude, verdict) and FIFO ordering.
- **Detail**: offense fields, contributing rules, investigation narrative, verdict,
  confidence, token/cost counters, attempt history.
- **Actions**: requeue a `FAILED`/`DEAD_LETTER` item, force-requeue a `DONE` item.

REST endpoints are declared in `rest_methods[]`. CSRF protection applies
(`use_qradar_csrf` or app-level) to every state-changing route.

---

## 12. Manifest additions (sketch)

```jsonc
{
  "resources": 1024,
  "authentication": {
    "oauth2": {
      "authorisation_flow": "CLIENT_CREDENTIALS",
      "requested_capabilities": ["SEM"]
    }
  },
  "services": [
    { "name": "socai-ingest", "command": "python3 -m socai.ingest", "directory": "/opt/app-root/app/", "version": "1" },
    { "name": "socai-engine", "command": "python3 -m socai.engine", "directory": "/opt/app-root/app/", "version": "1" }
  ],
  "areas": [
    { "id": "socai_queue", "text": "SOC AI", "description": "Automated offense triage", "url": "/queue", "required_capabilities": [] }
  ]
}
```

The app's QRadar API visibility equals the permissions of the service account an
admin selects at install time via the Application Assistant. Domain and tenant
scoping follow from that account.

---

## 13. Open / deferred

| Item | Status |
|---|---|
| Re-investigation on material offense change | Deferred (§9) |
| Rule-based / rule-group ingest filtering | Out of scope |
| Writeback to QRadar (notes, close reason, assignment) | Not yet designed |
| Multi-tenancy (`multitenancy_safe`) | Not addressed |
| PostgreSQL migration path | Repository layer only; not exercised |

---

## 14. Next

Step 2 (LLM integration) is documented in `02-llm-integration.md`.
Step 3a — the offense context contract and expected LLM output schema — is the
next design task.
