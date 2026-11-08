"""Findings tab API: scheduled findings, shared by all admins."""

import datetime
import json

from flask import Blueprint, g, jsonify, request

from . import chatstore, findingstore, scheduler, settings
from .auth import admin_required

# pylint: disable=invalid-name
findingsbp = Blueprint('findingsbp', __name__, url_prefix='/')

CATEGORY_NAMES = {'expensive_searches': 'Expensive searches'}


def _local(ms):
    return datetime.datetime.fromtimestamp(ms / 1000).strftime('%Y-%m-%d %H:%M:%S') if ms else None


@findingsbp.route('/api/findings')
@admin_required
def list_findings():
    args = request.args
    findings = findingstore.search(category=args.get('category') or None,
                                   severity=args.get('severity') or None,
                                   status=args.get('status') or None)
    interval = settings.get_config('findings_interval_minutes')
    tasks = []
    for task, (setting, _) in scheduler.TASKS.items():
        state = findingstore.task_state(task)
        runs = findingstore.last_runs(task, 1)
        tasks.append({'task': task, 'name': CATEGORY_NAMES.get(task, task),
                      'enabled': settings.get_config(setting) == 'on',
                      'interval_minutes': interval,
                      'watching_since': state['watermark'] and _local(state['watermark']),
                      'last_run': runs[0] if runs else None,
                      'run_requested': bool(state['run_requested'] and
                                            (state['last_run'] or 0) < state['run_requested'])})
    return jsonify(findings=findings, tasks=tasks, categories=CATEGORY_NAMES,
                   statuses=list(findingstore.STATUSES))


@findingsbp.route('/api/findings/<finding_id>/status', methods=['PUT'])
@admin_required
def set_status(finding_id):
    status = (request.get_json(silent=True) or {}).get('status')
    try:
        if not findingstore.set_status(finding_id, status):
            return jsonify(error='Finding not found.'), 404
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(finding=findingstore.get(finding_id))


@findingsbp.route('/api/findings/<finding_id>/analyse', methods=['POST'])
@admin_required
def analyse(finding_id):
    if not settings.get(settings.ANTHROPIC_KEY):
        return jsonify(error='No Anthropic API key is configured.'), 409
    if not findingstore.request_analysis(finding_id):
        return jsonify(error='Finding not found.'), 404
    return jsonify(message='Analysis queued; it appears within a minute.'), 202


@findingsbp.route('/api/findings/tasks/<task>/run', methods=['POST'])
@admin_required
def run_now(task):
    if task not in scheduler.TASKS:
        return jsonify(error='Unknown task.'), 404
    findingstore.request_run(task)
    return jsonify(message='Run requested; it starts within 15 seconds.'), 202


def _context(finding):
    """The finding as attached to a chat message, so the agent can discuss it."""
    details = finding['details']
    summary = {'title': finding['title'], 'severity': finding['severity'],
               'status': finding['status'], 'occurrences': finding['occurrences'],
               'first_seen': _local(finding['first_seen']),
               'last_seen': _local(finding['last_seen']), 'details': details,
               'analysis': finding.get('analysis')}
    return '[Attached: finding "{0}"]\n{1}'.format(finding['title'][:120],
                                                  json.dumps(summary, indent=1, default=str))


@findingsbp.route('/api/findings/<finding_id>/chat', methods=['POST'])
@admin_required
def chat_about(finding_id):
    finding = findingstore.get(finding_id)
    if finding is None:
        return jsonify(error='Finding not found.'), 404
    chat = chatstore.create(g.qradar_user, title='Finding: ' + finding['title'][:60])
    chatstore.set_pending_context(chat['id'], {'text': _context(finding)})
    return jsonify(chat_id=chat['id']), 201
