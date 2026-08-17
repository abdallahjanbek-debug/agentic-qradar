"""Prompt assembly.

Layout is cache-critical. The system prompt is the stable prefix and carries the
cache breakpoint; everything offense-specific goes in the user turn, after it.
Nothing offense-specific -- no IDs, timestamps, or counts -- may appear in
SYSTEM_PROMPT, or the prefix changes on every request and nothing ever caches.
"""

import json

SYSTEM_PROMPT = """\
You are a SOC Level 1 analyst triaging offenses from IBM QRadar.

You will be given one offense: its metadata, the correlation rules that fired, the
source and destination addresses involved, the contributing log sources, and a
sample of the earliest events that make up the offense.

Your job is to decide what this offense is and what should happen to it.

## Verdicts

- TRUE_POSITIVE  — the activity described is real and warrants attention.
- FALSE_POSITIVE — the rule fired on benign activity.
- ESCALATE       — likely malicious and beyond Level 1 disposition.
- INCONCLUSIVE   — the evidence provided does not support any of the above.

Verdict and recommended action are separate judgements. An obvious low-severity
true positive can still be closed; an inconclusive offense cannot.

## How to work

Reason from the evidence you were given. The event sample is the earliest events
of the offense, in chronological order, and is capped -- the offense may contain
far more events than you can see, so treat counts in the metadata as authoritative
over what you can count in the sample.

Every observation you record in `evidence` must cite the indices of the events that
support it. Do not assert anything you cannot point at.

When something matters to the verdict but is not determinable from the evidence --
whether a host is a server or a workstation, whether an account is a service
account, whether a destination is expected -- record it in `reasoning_gaps` rather
than assuming. A stated gap is more useful than a confident guess.

Set `confidence` to reflect the evidence actually available, not the strength of
your prose. Sparse or ambiguous evidence means low confidence, and that is a valid
and useful answer.
"""


def _truncate(value, limit: int) -> str:
    if value is None:
        return ""
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "…[truncated]"


def build_user_content(bundle: dict, payload_limit: int) -> str:
    """Render the offense bundle. Everything here is volatile — it sits after the
    cache breakpoint by construction."""
    offense = bundle["offense"]

    lines = ["# Offense", ""]
    for label, key in [
        ("ID", "offense_id"),
        ("Description", "description"),
        ("Status", "status"),
        ("Magnitude", "magnitude"),
        ("Severity", "severity"),
        ("Credibility", "credibility"),
        ("Relevance", "relevance"),
        ("Type", "offense_type"),
        ("Source", "offense_source"),
        ("Event count", "event_count"),
        ("Flow count", "flow_count"),
        ("Device count", "device_count"),
        ("Distinct usernames", "username_count"),
        ("Domain", "domain_id"),
    ]:
        value = offense.get(key)
        if value not in (None, ""):
            lines.append("- {}: {}".format(label, value))

    lines += ["", "# Contributing rules", ""]
    rules = bundle.get("rules") or []
    if rules:
        for rule in rules:
            lines.append("- {} ({})".format(rule.get("name"), rule.get("type")))
    else:
        lines.append("- none resolved")

    lines += ["", "# Addresses", ""]
    lines.append("- Sources: {}".format(", ".join(bundle.get("source_ips") or []) or "none"))
    lines.append("- Local destinations: {}".format(
        ", ".join(bundle.get("destination_ips") or []) or "none"))

    lines += ["", "# Log sources", ""]
    log_sources = bundle.get("log_sources") or []
    if log_sources:
        for source in log_sources:
            lines.append("- {} ({})".format(
                source.get("name"), source.get("type_name") or "unknown type"))
    else:
        lines.append("- none reported")

    events = bundle.get("events") or []
    lines += ["", "# Events (earliest {}, chronological)".format(len(events)), ""]
    if not events:
        lines.append("No events were retrievable for this offense.")
    for index, event in enumerate(events):
        fields = {
            key: value for key, value in event.items()
            if key != "payload" and value not in (None, "")
        }
        lines.append("## [{}] {}".format(index, fields.pop("event_name", "event")))
        lines.append(json.dumps(fields, default=str))
        payload = _truncate(event.get("payload"), payload_limit)
        if payload:
            lines.append("payload: {}".format(payload))
        lines.append("")

    return "\n".join(lines)
