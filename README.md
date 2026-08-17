# QRadar SOC AI

A QRadar app that does the job of a SOC Level 1 analyst: it pulls offenses from
QRadar, investigates them with Claude, stores the investigations, and presents
them in a custom QRadar tab.

Everything runs inside the QRadar app container. Design decisions and rationale
live in [`docs/plans/`](docs/plans/).

---

## Status: first testable build — not yet installed

An install against the test console (192.168.8.202, QRadar 7.5.0 UP14) was
attempted and **failed at package upload**: the console accepts the bytes then
rejects the archive with error 33101. Size, transfer integrity, and local archive
validity have all been ruled out. See
[`docs/plans/04-deployment-log.md`](docs/plans/04-deployment-log.md) for the full
findings, the console facts that forced three manifest/config corrections, and the
untested next steps.

This is a working skeleton meant for a **test QRadar environment**. What works
end to end:

- Offense polling into a durable SQLite queue (FIFO by offense creation time)
- Lease-based claiming with a reaper, retries, and a dead-letter state
- Fixed context bundle: offense metadata, contributing rules, resolved source and
  destination IPs, log sources, and the first 50 events via AQL
- One Claude call per offense with a schema-enforced verdict
- Queue tab with counts, health, list, and a per-offense detail view
- Admin settings page with encrypted key storage and connection diagnostics
- Retention purge with incremental vacuum

**Deliberately stubbed:** the triage gate (`app/engine.py::triage_gate`) is a
pass-through. It exists as a pipeline stage so adding it later does not mean
reworking the state machine, but it currently escalates everything to the deep
model. Turning it on is the main cost lever — see
[`docs/plans/02-llm-integration.md`](docs/plans/02-llm-integration.md) §9.

**Not built:** writeback to QRadar (notes, close reason, assignment),
re-investigation on offense update, multi-tenancy.

---

## Layout

```
manifest.json              app declaration: areas, config pages, services, resources
app/
  __init__.py              Flask factory
  config.py                settings keys, defaults, constants
  db.py                    SQLite connection, pragmas, migrations
  repo.py                  all SQL — the seam for a future Postgres swap
  appsecrets.py            encdec-backed API key storage
  qradar.py                QRadar REST + Ariel/AQL
  ingest.py                socai-ingest service: poller, reaper, purge
  engine.py                socai-engine service: worker pool
  llm/
    anthropic_client.py    per-model request building, refusal handling, cost
    prompt.py              cache-safe prompt assembly
    schema.py              the investigation output contract
  views/
    queue.py               queue tab + REST
    admin.py               settings page + REST
container/run/             startup scripts (store directory creation)
docs/plans/                design docs
```

---

## Build and deploy

Requires the [QRadar App SDK v2](https://ibmsecuritydocs.github.io/qradar_appfw_v2/)
(`qapp`).

### 1. Vendor dependencies

QRadar apps must bundle their dependencies — fetching from the internet at install
time is not permitted.

```bash
pip download -r requirements.txt -d container/pip/ --only-binary=:all:
```

### 2. Run locally

```bash
qapp run
```

To let a locally-run app call the QRadar API, see
[Configuring apps running through the SDK to make API calls](https://ibmsecuritydocs.github.io/qradar_appfw_v2/docs/tutorials/allowing_apps_running_through_the_sdk_to_make_api_calls.html).

### 3. Package and deploy

```bash
qapp package -p socai.zip
qapp deploy -q <console-ip> -u <admin-user> -p socai.zip
```

### 4. Authorize

On install, QRadar prompts an admin to pick a service account via the Application
Assistant. That account needs the **SEM** capability. **The app's visibility into
offenses is exactly that account's visibility** — domain and tenant scoping follow
from it. Deploy changes afterwards to activate the authorized service token.

### 5. Configure

Admin tab → **SOC AI Settings**:

1. Paste the Anthropic API key and save. It is encrypted with `qpylib.encdec` and
   never returned to the browser.
2. Click **Test connection**. Three outcomes are distinguished on purpose:
   `valid`, `key_rejected`, and `unreachable` (egress/proxy problem).
3. Adjust models, retention, and worker concurrency as needed.

Then open the **SOC AI** tab. Offenses created in the last day are backfilled on
first poll.

---

## Operating notes

**Throughput.** 1,000 offenses/day is one every 86 seconds; an investigation takes
60–120s. Worker concurrency defaults to 4 for that reason. Watch *oldest pending
age* on the queue tab — if it climbs steadily, concurrency is too low. Concurrency
is read at service start, so restart the app after changing it.

**Cost.** Every investigation records its own token counts and cost. Set a
**daily token budget** to bound spend: when it is hit the engine stops claiming
work and the tab shows a paused banner. Ingestion keeps running, so nothing is
lost.

**Prompt caching.** The system prompt is the stable cached prefix. Adding anything
offense-specific to `prompt.SYSTEM_PROMPT` silently disables caching and roughly
triples input cost. `cache_read_tokens` is recorded per investigation, and the
engine logs a warning when a large prompt gets no cache read.

**Storage.** Two retention windows: investigations (365d) and raw LLM transcripts
(30d). Transcripts are the bulk of the data — retaining them for a year would
reach tens of GB. Purge runs daily and reclaims pages incrementally.

**Refusals.** Claude's safety classifiers can decline security-flavored prompts;
this returns HTTP 200 with `stop_reason: "refusal"`, not an error. Server-side
fallback is enabled by default so declined investigations are re-served rather
than failing. Refusal rate is visible via `investigation.stop_reason`.

---

## Scope

This build targets a **test / research environment**. Offense metadata and raw log
payloads — including usernames, internal IPs, and hostnames — are sent to the
Anthropic API unmodified. Redaction, an admin acknowledgement gate, and a
"what gets sent" preview are deferred, not descoped; see
[`docs/plans/02-llm-integration.md`](docs/plans/02-llm-integration.md) §11 before
pointing this at production data.
