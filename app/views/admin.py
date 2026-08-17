"""Admin settings page.

Reached from the QRadar Admin tab via the configuration_pages manifest entry, which
carries required_capabilities: ["ADMIN"]. That restriction is deliberately NOT
applied to the queue area -- applying it there would lock non-admin analysts out of
the app entirely.
"""

from flask import Blueprint, jsonify, render_template, request

from .. import appsecrets, config, repo
from ..llm import AnthropicProvider

adminbp = Blueprint("admin", __name__, template_folder="../templates")

EDITABLE = set(config.DEFAULTS.keys())


@adminbp.route("/")
def index():
    return render_template("settings.html")


@adminbp.route("/api/settings", methods=["GET"])
def api_get_settings():
    return jsonify({
        "settings": repo.all_settings(),
        "key_configured": appsecrets.is_configured(),
        "key_masked": appsecrets.masked(),
        "connection_status": repo.get_state("connection_status"),
        "connection_detail": repo.get_state("connection_detail"),
        "connection_checked_at": repo.get_state("connection_checked_at"),
        "effort_levels": config.EFFORT_LEVELS,
    })


@adminbp.route("/api/settings", methods=["POST"])
def api_save_settings():
    payload = request.get_json(silent=True) or {}
    updates = {k: v for k, v in payload.items() if k in EDITABLE}
    if updates:
        repo.set_settings(updates)
    return jsonify({"ok": True, "saved": sorted(updates)})


@adminbp.route("/api/key", methods=["POST"])
def api_set_key():
    """Write-only. There is no endpoint that returns the plaintext key."""
    payload = request.get_json(silent=True) or {}
    key = (payload.get("api_key") or "").strip()
    if not key:
        return jsonify({"ok": False, "error": "empty key"}), 400
    appsecrets.set_api_key(key)
    return jsonify({"ok": True, "masked": appsecrets.masked()})


@adminbp.route("/api/test-connection", methods=["POST"])
def api_test_connection():
    """Three distinct outcomes, so a locked-down console is diagnosable."""
    key = appsecrets.get_api_key()
    if not key:
        result = {"ok": False, "status": "not_configured",
                  "detail": "No API key has been saved."}
    else:
        result = AnthropicProvider(key).validate()

    repo.set_state("connection_status", result.get("status"))
    repo.set_state("connection_detail", (result.get("detail") or "")[:500])
    repo.set_state("connection_checked_at", repo.now_ms())
    return jsonify(result)
