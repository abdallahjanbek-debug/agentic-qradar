"""Investigation workers — the `socai-engine` named service.

A pool of threads claims queue items FIFO by offense creation time, assembles the
fixed context bundle, and runs one LLM call per offense.

Throughput note: 1,000 offenses/day is one every 86 seconds, and an investigation
takes 60-120s. A single worker cannot keep up, which is why concurrency defaults
to 4.
"""

import json
import threading
import time

from qpylib import qpylib

from . import appsecrets, config, db, qradar, repo
from .llm import AnthropicProvider, LLMError, RefusalError
from .llm import prompt as prompt_builder

IDLE_SLEEP_SECONDS = 5


def build_bundle(offense_id: int) -> dict:
    """The fixed context bundle. Six blocks, bounded cost, one LLM call."""
    offense = repo.get_offense(offense_id)
    if offense is None:
        raise LLMError("offense {} not found".format(offense_id))

    raw = json.loads(offense["raw_json"])

    bundle = {
        "offense": offense,
        "rules": qradar.resolve_rule_names(raw.get("rules")),
        # The offense object returns address IDs, not IPs.
        "source_ips": qradar.resolve_source_addresses(raw.get("source_address_ids")),
        "destination_ips": qradar.resolve_destination_addresses(
            raw.get("local_destination_address_ids")),
        "log_sources": raw.get("log_sources") or [],
        "events": [],
    }

    start_ms = offense["start_time"] or offense["first_persisted_time"]
    stop_ms = offense["last_updated_time"] or repo.now_ms()
    try:
        bundle["events"] = qradar.fetch_offense_events(
            offense_id,
            start_ms,
            stop_ms + 1000,
            repo.get_int("event_sample_size"),
            repo.get_int("ariel_timeout_seconds"),
        )
    except qradar.QRadarError as error:
        # An offense with no events is still worth a verdict: metadata and rules
        # alone are often enough to call an obvious false positive.
        qpylib.log("socai-engine: events unavailable for offense {}: {}".format(
            offense_id, error), level="WARNING")

    return bundle


def triage_gate(bundle: dict) -> str:
    """Cheap pre-filter stage.

    Present as a pipeline stage from day one so adding it later does not mean
    reworking the state machine. Currently a pass-through -- see README.
    """
    return "ESCALATED_TO_DEEP"


def investigate(provider: AnthropicProvider, offense_id: int) -> None:
    investigation_id = repo.start_investigation(offense_id)
    bundle = build_bundle(offense_id)
    gate_decision = triage_gate(bundle)

    user_content = prompt_builder.build_user_content(
        bundle, repo.get_int("event_payload_max_chars")
    )
    result, usage, raw_text = provider.investigate(
        system_prompt=prompt_builder.SYSTEM_PROMPT,
        user_content=user_content,
        model=repo.get_setting("deep_model"),
        max_tokens=repo.get_int("max_tokens"),
        effort=repo.get_setting("effort"),
        fallbacks_enabled=repo.get_bool("fallbacks_enabled"),
    )

    usage["gate_decision"] = gate_decision
    repo.complete_investigation(investigation_id, result, usage)
    repo.save_transcript(investigation_id, user_content, raw_text)
    repo.finish(offense_id, config.DONE)

    qpylib.log("socai-engine: offense {} -> {} ({:.2f}) [{} tok, ${:.4f}]".format(
        offense_id, result.get("verdict"), result.get("confidence") or 0.0,
        (usage.get("input_tokens") or 0) + (usage.get("output_tokens") or 0),
        (usage.get("cost_usd_micros") or 0) / 1_000_000.0,
    ))


def budget_exceeded() -> bool:
    budget = repo.get_int("daily_token_budget")
    if budget <= 0:
        return False
    return repo.tokens_used_today() >= budget


def worker(index: int, stop_event: threading.Event) -> None:
    worker_id = "worker-{}".format(index)
    qpylib.log("socai-engine: {} started".format(worker_id))

    while not stop_event.is_set():
        api_key = appsecrets.get_api_key()
        if not api_key:
            time.sleep(30)
            continue

        if budget_exceeded():
            repo.set_state("budget_paused", "1")
            time.sleep(60)
            continue
        repo.set_state("budget_paused", "0")

        offense_id = repo.claim_next(worker_id)
        if offense_id is None:
            time.sleep(IDLE_SLEEP_SECONDS)
            continue

        heart = threading.Event()
        beater = threading.Thread(
            target=_heartbeat_loop, args=(offense_id, heart), daemon=True)
        beater.start()

        try:
            investigate(AnthropicProvider(api_key), offense_id)
        except RefusalError as error:
            state = repo.fail(offense_id, "refusal: {}".format(error))
            qpylib.log("socai-engine: offense {} refused -> {}".format(offense_id, state),
                       level="WARNING")
        except Exception as error:
            state = repo.fail(offense_id, str(error))
            qpylib.log("socai-engine: offense {} failed -> {}: {}".format(
                offense_id, state, error), level="ERROR")
        finally:
            heart.set()


def _heartbeat_loop(offense_id: int, stop_event: threading.Event) -> None:
    while not stop_event.wait(config.HEARTBEAT_SECONDS):
        try:
            repo.heartbeat(offense_id)
        except Exception:
            return


def main() -> None:
    qpylib.create_log()
    db.init_schema()

    concurrency = max(repo.get_int("worker_concurrency"), 1)
    qpylib.log("socai-engine: starting {} worker(s)".format(concurrency))

    stop_event = threading.Event()
    threads = [
        threading.Thread(target=worker, args=(i, stop_event), daemon=True)
        for i in range(concurrency)
    ]
    for thread in threads:
        thread.start()

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop_event.set()


if __name__ == "__main__":
    main()
