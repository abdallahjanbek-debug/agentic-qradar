"""Settings keys, defaults, and constants."""

# encdec identity. This is deliberately a fixed synthetic user, not the logged-in
# admin: the key is app-scoped, and the background services have no logged-in user
# to decrypt under.
SECRET_USER = "socai_app"
SECRET_NAME = "anthropic_api_key"

# 20.0 is DEPRECATED on QRadar 7.5.0 UP14. Highest non-deprecated is 27.0.
QRADAR_API_VERSION = "27.0"

# Settings live in the `setting` table. Values are stored as strings.
DEFAULTS = {
    "deep_model": "claude-opus-5",
    "gate_model": "claude-haiku-4-5",
    "gate_enabled": "false",
    "effort": "high",
    "max_tokens": "8000",
    "daily_token_budget": "0",          # 0 = unlimited
    # 2 for the constrained test console; 4 is the design target for 1k/day.
    "worker_concurrency": "2",
    "poll_interval_seconds": "60",
    "backfill_days": "1",
    "retention_investigation_days": "365",
    "retention_transcript_days": "30",
    "event_sample_size": "50",
    "event_payload_max_chars": "1000",
    "ariel_timeout_seconds": "120",
    "fallbacks_enabled": "true",
}

EFFORT_LEVELS = ["low", "medium", "high", "xhigh", "max"]

# Queue states
PENDING = "PENDING"
IN_PROGRESS = "IN_PROGRESS"
DONE = "DONE"
FAILED = "FAILED"
DEAD_LETTER = "DEAD_LETTER"
SKIPPED = "SKIPPED"

MAX_ATTEMPTS = 3
LEASE_MS = 10 * 60 * 1000
HEARTBEAT_SECONDS = 60
REAPER_INTERVAL_SECONDS = 60

# Poll window overlap, to survive equal-timestamp rows straddling a page boundary.
WATERMARK_OVERLAP_MS = 5000
OFFENSE_PAGE_SIZE = 500

# Model families that reject `output_config.effort` and adaptive thinking.
LEGACY_PARAM_MODELS = ("claude-haiku-4-5", "claude-sonnet-4-5", "claude-opus-4-5")

# USD per million tokens, for the cost counter shown in the UI.
PRICING = {
    "claude-opus-5": (5.00, 25.00),
    "claude-opus-4-8": (5.00, 25.00),
    "claude-sonnet-5": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
}


def uses_legacy_params(model: str) -> bool:
    """True for models that predate output_config.effort and adaptive thinking.

    Sending `effort` to one of these is a 400, so request parameters are built
    per-model rather than shared between the gate and the deep call.
    """
    return model.startswith(LEGACY_PARAM_MODELS)
