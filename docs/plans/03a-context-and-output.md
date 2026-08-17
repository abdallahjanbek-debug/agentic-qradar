# Step 3a — Offense Context Bundle & LLM Output Contract

Status: **approved, implemented in the skeleton**
Last updated: 2026-08-17

---

## 1. Goal

Define exactly what evidence is sent to the model for each offense, and exactly
what shape the model's answer must take.

---

## 2. Decisions

| Decision | Value |
|---|---|
| Evidence strategy | **(a) Fixed context bundle.** No agentic tool loop. |
| Event sample | **50 events**, `ORDER BY starttime ASC` — the *first* 50 |
| Aggregate profile query | **Not included** |
| Payload handling | Truncated to 1000 chars/event (configurable) |
| Output enforcement | **Structured outputs** (`output_config.format`, JSON schema) |

Strategy (a) means every investigation costs a predictable, bounded number of
QRadar queries and exactly one LLM call. The trade-off is that a brute-force
offense and a data-exfiltration offense receive the same evidence shape. Accepted
for now; the `reasoning_gaps` output field (§5) is how we find out what the bundle
is missing.

---

## 3. Context bundle

Assembled by the engine worker before the LLM call. Six blocks:

| Block | Source | Extra API calls |
|---|---|---|
| Offense metadata | `offense` table (from ingest) | none |
| Contributing rules | `offense_rule` + `/analytics/rules/{id}` | one per rule |
| Source addresses | `/siem/source_addresses` | one |
| Local destination addresses | `/siem/local_destination_addresses` | one |
| Log sources | offense payload (`log_sources[]`) | none |
| Events | Ariel/AQL | one async search |

### Address resolution is not optional

The offense object returns `source_address_ids` and
`local_destination_address_ids` — **numeric IDs, not IP addresses**. Without
resolving them the model sees an offense containing no addresses at all. Same for
rules: `rules[]` carries `{id, type}` and the human-readable rule *name* requires
`/analytics/rules/{id}`.

Rule names are cached in-process — a small set of rules generates most offenses,
so this collapses to near-zero calls in steady state.

### Event query

```sql
SELECT
    starttime,
    QIDNAME(qid)               AS event_name,
    LOGSOURCENAME(logsourceid) AS log_source,
    CATEGORYNAME(category)     AS category,
    sourceip, sourceport,
    destinationip, destinationport,
    username,
    magnitude, severity, credibility, relevance,
    eventcount,
    UTF8(payload)              AS payload
FROM events
WHERE INOFFENSE(:offense_id)
ORDER BY starttime ASC
LIMIT 50
START :offense_start_ms STOP :offense_end_ms
```

Notes:

- **`ORDER BY starttime ASC`** returns the *earliest* 50 events — how the offense
  began, which is the most diagnostic slice for triage. Switching to `DESC` gives
  the 50 most recent instead.
- **The time window is always explicit.** AQL's default range is short and an
  offense can span days, so a missing `START`/`STOP` silently returns nothing.
  Bounds come from the offense's own `start_time` and `last_updated_time`, which
  we already store; AQL accepts epoch milliseconds directly.
- **No `SELECT *`.** Named fields only. `QIDNAME` / `LOGSOURCENAME` /
  `CATEGORYNAME` resolve numeric IDs into names the model can reason about.
- **Payload is truncated** to 1000 chars per event. Windows events run 2–4 KB
  each; 50 untruncated could reach ~37k tokens — more than the rest of the prompt
  combined.
- **`INOFFENSE()` is expensive** on very large offenses. The Ariel search runs with
  a hard timeout so a slow query cannot hold a queue lease open indefinitely.

Ariel is asynchronous. `ArielSearch.search_sync(query, timeout, sleep_interval)`
blocks until the search completes — appropriate inside a worker thread, which has
nothing else to do while waiting.

---

## 4. Prompt layout (cache-critical)

The bundle is rendered in this order so the cacheable prefix is as large as
possible:

```
  system  ── role, triage doctrine, verdict definitions, output rules   ← STABLE
            └─ cache_control: ephemeral  ◀── breakpoint
  user    ── offense metadata
             contributing rules
             addresses
             log sources
             events                                                     ← VOLATILE
```

Nothing offense-specific — no IDs, timestamps, or counts — may appear above the
breakpoint. `usage.cache_read_input_tokens` is recorded per investigation so a
regression here is visible rather than hypothetical.

---

## 5. Output contract

Enforced with `output_config.format` (JSON schema) rather than asking for JSON in
the prompt and parsing hopefully.

```jsonc
{
  "verdict":            "TRUE_POSITIVE | FALSE_POSITIVE | ESCALATE | INCONCLUSIVE",
  "confidence":         0.0,
  "summary":            "one-line analyst-readable conclusion",
  "narrative":          "what happened and why this verdict",
  "key_findings":       ["..."],
  "evidence": [
    { "observation": "...", "supporting_events": [0, 3, 7] }
  ],
  "indicators": {
    "source_ips":      ["..."],
    "destination_ips": ["..."],
    "usernames":       ["..."],
    "hostnames":       ["..."]
  },
  "recommended_action": "CLOSE_AS_FALSE_POSITIVE | ESCALATE_TO_L2 | MONITOR | NEEDS_HUMAN_REVIEW",
  "mitre_techniques":   ["T1110.001"],
  "reasoning_gaps":     ["..."]
}
```

### Why these fields

**`evidence[].supporting_events`** holds indices into the 50-event sample. Forcing
the model to cite which events support each claim is the strongest available
defense against confident fabrication, and it makes the queue tab reviewable — an
analyst clicks a finding and sees the events behind it.

**`reasoning_gaps`** is deliberate. With a fixed bundle the model will regularly
lack something it needs. "I could not determine whether 10.4.2.9 is a domain
controller" is far more useful than a guess, and accumulated gaps become the
evidence for what to add to the bundle in a later iteration.

**`verdict` and `recommended_action` are separate.** "This is a true positive" and
"a human should look at this" are different statements. An obvious low-severity TP
can be auto-closed; an INCONCLUSIVE one cannot.

### Schema constraints

Structured outputs require `additionalProperties: false` and an explicit
`required` array on every object, and do **not** support numeric range or string
length constraints. `confidence` is therefore declared as a plain number and
range-checked (0–1) on our side after parsing.

The first request per schema pays a one-time compile cost; the schema is then
cached for 24 hours. Structured outputs are incompatible with citations — not used
here.

---

## 6. Failure handling

| Case | Handling |
|---|---|
| `stop_reason == "refusal"` | Recorded on the investigation; item → `FAILED`, retried. Server-side fallback (`fallbacks: "default"`) usually prevents this. |
| `stop_reason == "max_tokens"` | Output truncated → invalid JSON. Item → `FAILED`; raise `max_tokens` if it recurs. |
| Ariel timeout | Investigation proceeds with an empty event list and a recorded gap, rather than failing outright. |
| Schema validation failure | Item → `FAILED`, raw response kept in `transcript` for diagnosis. |

An offense with no events is still worth a verdict — the metadata and rules alone
are often enough to call an obvious false positive.

---

## 7. Deferred

- Agentic follow-up tools (strategy (c)) — revisit once `reasoning_gaps` shows
  what the fixed bundle actually misses.
- Asset/network context, reference-set lookups, threat intel enrichment.
- MITRE mapping is requested from the model but not validated against a technique
  list.
