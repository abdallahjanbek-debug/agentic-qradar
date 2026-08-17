"""Queue tab — visible to all analysts, so no required_capabilities."""

import json

from flask import Blueprint, jsonify, render_template, request

from .. import config, repo

queuebp = Blueprint("queue", __name__, template_folder="../templates")

VALID_STATES = {
    config.PENDING, config.IN_PROGRESS, config.DONE,
    config.FAILED, config.DEAD_LETTER, config.SKIPPED,
}


@queuebp.route("/")
def index():
    return render_template("queue.html")


@queuebp.route("/api/health")
def api_health():
    return jsonify(repo.health())


@queuebp.route("/api/items")
def api_items():
    state = request.args.get("state") or None
    if state and state not in VALID_STATES:
        return jsonify({"error": "unknown state"}), 400
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))
    return jsonify(repo.list_queue(state=state, limit=limit, offset=offset))


@queuebp.route("/api/items/<int:offense_id>")
def api_item(offense_id):
    offense = repo.get_offense(offense_id)
    if offense is None:
        return jsonify({"error": "not found"}), 404

    offense.pop("raw_json", None)
    investigation = repo.latest_investigation(offense_id)
    result = None
    if investigation and investigation.get("result_json"):
        try:
            result = json.loads(investigation["result_json"])
        except ValueError:
            result = None

    return jsonify({
        "offense": offense,
        "rules": repo.get_offense_rules(offense_id),
        "investigation": investigation,
        "result": result,
    })


@queuebp.route("/api/items/<int:offense_id>/requeue", methods=["POST"])
def api_requeue(offense_id):
    if repo.get_offense(offense_id) is None:
        return jsonify({"error": "not found"}), 404
    repo.requeue(offense_id)
    return jsonify({"ok": True})
