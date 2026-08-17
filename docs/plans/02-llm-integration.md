# Step 2 — LLM Integration & Admin Settings

Status: **approved, not yet implemented**
Last updated: 2026-08-17

---

## 1. Goal

Give the app a configured, validated connection to Claude, administered from a
settings page in the QRadar **Admin tab**, with the API key stored encrypted and
never exposed back to the UI.

This step covers the settings page, secret storage, egress, connectivity
diagnostics, model/cost configuration, and the client wrapper. It does **not**
cover the prompt contract — what context is sent with an offense and what shape
the response takes is step 3a.

---

## 2. Decisions

| Decision | Value | Notes |
|---|---|---|
| Provider | Anthropic (Claude) only | Thin seam for a second provider; no plugin system |
| Key scope | **App-wide**, one key | encdec `user` = fixed synthetic `socai_app` |
| Settings location | `configuration_pages[]` → icon in QRadar Admin tab | `required_capabilities: ["ADMIN"]` |
| Egress | Console has outbound internet | Proxy env vars honoured automatically |
| Connectivity diagnostics | **Build regardless** | Three-state Test Connection |
| Redaction | **None.** Full offense + log payloads sent as-is. | Test/research environment |
| Deep model | `claude-opus-5` | $5 / $25 per MTok |
| Triage gate model | `claude-haiku-4-5` | $1 / $5 per MTok |
| Effort | `high` (deep model only) | See §6 — not valid on Haiku |
| Prompt caching | Designed in from day one | See §7 |
| Refusal handling | Server-side fallback enabled | See §8 |

---

## 3. Settings page

QRadar's `configuration_pages[]` manifest object renders an icon in the **Admin
tab**; the page itself is served by a route in our Flask app.

```jsonc
"configuration_pages": [
  {
    "id": "socai_settings",
    "text": "SOC AI Settings",
    "description": "Configure the Claude connection, models, and retention",
    "url": "/admin/settings",
    "required_capabilities": ["ADMIN"]
  }
]
```

Two rules from IBM's guidance:

1. `required_capabilities: ["ADMIN"]` goes on **the configuration page only**.
   Applying it to other components (areas, REST methods) locks non-admin analysts
   out of the app entirely — the Queue tab must stay unrestricted.
2. CSRF protection is mandatory. A form that accepts a secret is the last place to
   skip it — either `use_qradar_csrf: true` or app-level protection on every
   state-changing route.

### Fields

| Field | Storage | Default |
|---|---|---|
| Anthropic API key | encdec-encrypted | — |
| Deep model | `setting` | `claude-opus-5` |
| Triage gate model | `setting` | `claude-haiku-4-5` |
| Triage gate enabled | `setting` | `true` |
| Effort | `setting` | `high` |
| Max tokens / investigation | `setting` | 8000 |
| Daily token budget | `setting` | — (engine pauses when exceeded) |
| Worker concurrency | `setting` | 4 |
| Poll interval (s) | `setting` | 60 |
| Backfill days (first run) | `setting` | 1 |
| Investigation retention (days) | `setting` | 365 |
| Transcript retention (days) | `setting` | 30 |
| Connection status | derived | — |

Non-secret settings live in the `setting` table alongside the queue — transactional,
and they survive app upgrade with the rest of `/opt/app-root/store`.

The model dropdowns are populated from `client.models.list()` rather than a
hardcoded list, so they stay current as models are released.

---

## 4. Secret storage

```
Admin submits key  (HTTPS, inside the QRadar console)
        │
        ▼
Flask route  — ADMIN-gated, CSRF-protected
        │
        ▼
Encryption({'name': 'anthropic_api_key', 'user': 'socai_app'}).encrypt(key)
        │
        ▼
Encrypted file under /opt/app-root/store   — persists across restart and upgrade
        │
        ▼
Decrypted in-process at call time.  Never logged.  Never returned to the UI.
```

`qpylib.encdec` uses Fernet (engine v4) and transparently re-encrypts secrets
written by older engine versions when they are decrypted, so engine migration is
free.

### Why the `user` is a fixed synthetic value

`encdec` keys the stored file by its `user` property so an app can hold different
secrets for different users. That is the wrong model here:

- Passing the **logged-in admin's** username means a *different* admin cannot
  decrypt the key later.
- The background services (`socai-ingest`, `socai-engine`) have **no logged-in
  user at all** and could never decrypt it.

The key is app-scoped, not admin-scoped, so it is stored under the constant
`socai_app`. This is easy to get wrong and surfaces as a baffling
"works in the UI, fails in the worker" bug.

### UI contract

The key is **write-only from the UI**. The settings page displays:

- configured: yes / no
- last 4 characters
- last-validated timestamp and result
- a **Replace key** action

There is no "show key" affordance and no endpoint that returns the plaintext.

---

## 5. Egress and connectivity diagnostics

QRadar injects `https_proxy`, `http_proxy`, and `no_proxy` into the app container
automatically (governed by `APP_PROXY_ENABLED` in `nva.conf`), and additionally
exposes `QRADAR_HTTPS_PROXY` / `QRADAR_HTTP_PROXY` / `QRADAR_NO_PROXY`. Python's
`httpx` — which the Anthropic SDK uses — honours the standard variables by default,
so **no manual proxy configuration is required**.

The console for this deployment has outbound internet. Diagnostics are built anyway,
because "it doesn't work" on a locked-down console is otherwise undiagnosable.

### Test Connection — three distinct outcomes

| Outcome | Detection | Message |
|---|---|---|
| Network / proxy unreachable | connection error, timeout, DNS failure | Shows the resolved proxy env vars and the target host |
| Key rejected | `401` / `403` | Key invalid or lacks access |
| Valid | `models.list()` returns | Shows resolved models and validation time |

`GET /v1/models` (`client.models.list()`) is the validation call: it authenticates
the key without spending tokens, and its result populates the model dropdowns.

The result is persisted so the Queue tab can display a degraded-connection banner
rather than silently accumulating failed investigations.

---

## 6. Claude client

### Auth and headers

```
x-api-key: sk-ant-...
anthropic-version: 2023-06-01
```

Both are set by the SDK; the key is injected per-call from encdec, never from an
environment variable.

### Models

| Role | Model | $/MTok in | $/MTok out | Context | Max output |
|---|---|---|---|---|---|
| Deep investigation | `claude-opus-5` | $5 | $25 | 1M | 128K |
| Triage gate | `claude-haiku-4-5` | $1 | $5 | 200K | 64K |

### Per-model parameter differences — important

The two models do **not** take the same parameters:

| Parameter | `claude-opus-5` | `claude-haiku-4-5` |
|---|---|---|
| `output_config.effort` | Supported (`low`–`max`) | **Errors — do not send** |
| Thinking | On by default (adaptive). `{"type":"disabled"}` only valid at effort ≤ `high` | Uses the older `{"type":"enabled","budget_tokens":N}` form, or omit |
| `thinking.display` | Defaults to `"omitted"` (empty text) — set `"summarized"` to capture reasoning | — |
| Server-side `fallbacks` | Supported | Not used |

Sending `effort` to the triage gate is a 400. The client wrapper builds request
parameters per model rather than sharing one parameter block.

### Output sizing

`max_tokens` above roughly 16,000 must use the streaming path or the request risks
an SDK HTTP timeout. Default investigation budget is 8,000, so the non-streaming
path is fine; if the deep investigation budget is raised past ~16K, switch that call
to `.stream()` + `.get_final_message()`.

---

## 7. Prompt caching — design constraint, not an optimisation

Every investigation shares the same prefix: system prompt, playbooks, and tool
definitions. Only the offense payload varies. Cached tokens bill at roughly **0.1×**,
and `claude-opus-5` has a **512-token minimum cacheable prefix**, so even a modest
playbook set qualifies.

Caching is a **prefix match** — a single byte change anywhere in the prefix
invalidates everything after it. Render order is `tools` → `system` → `messages`.

Rules the prompt builder must follow from day one:

- **No timestamps, offense IDs, UUIDs, or per-request values anywhere in the system
  prompt.** Those go at the end, after the cache breakpoint.
- Tool definitions serialised deterministically (sorted by name).
- No conditional system-prompt sections — every flag combination is a distinct
  prefix and caches separately.
- `cache_control: {"type": "ephemeral"}` on the last stable block.

Verification: `usage.cache_read_input_tokens` must be non-zero on the second and
subsequent investigations. If it is zero across repeated runs, a silent invalidator
has crept into the prefix. This value is persisted per investigation
(`investigation.cache_read_tokens`) so the regression is visible rather than
hypothetical.

---

## 8. Refusals and fallback

`claude-opus-5` ships elevated cybersecurity safeguards, and its classifiers may
decline a request. A declined request returns **HTTP 200** with
`stop_reason: "refusal"` and a `stop_details` category — not an exception.

This matters more here than in a typical application: SOC triage prompts are exactly
the shape that trips cyber-category classifiers, and a benign investigation can be
declined.

Two requirements:

1. **Check `stop_reason` before reading `response.content`.** Code that indexes
   `content[0]` unconditionally breaks on a refusal — the content array can be empty.
2. **Enable server-side fallback.** With `fallbacks: "default"` (beta header
   `server-side-fallback-2026-07-01`), a declined request is re-run on Anthropic's
   recommended fallback inside the same call, routed by refusal category — cyber
   refusals route to `claude-opus-4-8`. Without it, a refused investigation simply
   stops.

`"default"` is preferred over pinning a fallback model: the right substitute depends
on why the request was declined, and it removes the migration owed when a pinned
model is deprecated.

Both `stop_reason` and the model that actually served the response are persisted
(`investigation.stop_reason`, `investigation.served_by_model`) so refusal rate is
measurable rather than anecdotal.

---

## 9. Cost model

Ingesting all offenses at 1,000/day means 1,000 investigations/day.

Uncapped, all-deep:

```
~30k input + ~5k output per investigation
  input   30k × $5/MTok  = $0.150
  output   5k × $25/MTok = $0.125
                          ─────────
                          ~$0.275 each  →  ~$275/day  →  ~$8,250/month
```

Two levers, both designed in from the start:

**Prompt caching** — if ~20k of the input is stable prefix, that portion bills at
~0.1×, cutting roughly $0.09/investigation (~$90/day).

**Triage gate** — a `claude-haiku-4-5` pass closes obvious noise before the deep
model runs, escalating only ambiguous offenses. At a plausible 60–70% filter rate
the total lands around $60–80/day.

The gate is a **pipeline stage from day one**, even if it starts as a pass-through.
Adding a stage later means reworking the state machine and the `investigation`
schema; starting with it costs nothing.

Guard rails:

- `investigation.cost_usd_micros` recorded per investigation.
- **Daily token budget** setting — when exceeded, the engine stops claiming new work
  and the Queue tab shows a paused banner. The queue keeps filling; nothing is lost.

---

## 10. Provider abstraction

One interface, one implementation:

```
LLMProvider
  ├─ validate()          → connectivity/auth check, model list
  └─ complete(request)   → LLMResponse (text, usage, stop_reason, served_by_model)

AnthropicProvider(LLMProvider)
```

No plugin registry, no config-driven provider loading. The seam exists so a second
provider is a new class rather than a refactor — that is all the abstraction worth
paying for now.

---

## 11. Deferred, not descoped

The current posture — no redaction, no data-handling acknowledgement gate, no egress
review — is scoped to a **test / research environment**. Offense metadata and raw
log payloads, including usernames, internal IPs, and hostnames, are sent to the
Anthropic API unmodified.

Before this points at a production console with real customer data, the following
comes back as a discrete work item:

- Configurable redaction (usernames, internal IPs, hostnames) before egress.
- An admin acknowledgement toggle gating the engine.
- A "what gets sent" preview rendering a real offense as the model would see it.
- A decision on Anthropic data retention. Default is 30-day retention;
  **zero-data-retention orgs can use `claude-opus-5`** (only `claude-fable-5` hard-
  requires 30-day retention), so ZDR is available if the compliance posture needs it.

Nothing about the current build changes. This is recorded so it is not lost.

---

## 12. Next

Step 3a — the offense context contract (what is sent with each offense) and the
expected LLM output schema (verdict, confidence, evidence, narrative) — is the next
design task.
