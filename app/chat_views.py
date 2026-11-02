"""Agent chat API: conversations (each visible only to its owner), runs and bulk uploads."""

import io
import time

from flask import Blueprint, g, jsonify, request, send_file
from qpylib import qpylib

from . import agent, bulk, chatstore, claude, qradar
from .auth import admin_required

# pylint: disable=invalid-name
chatbp = Blueprint('chatbp', __name__, url_prefix='/')

MAX_MESSAGE_LENGTH = 20000
# Rows listed per group in the summary attached to the chat; the full lists are in the file.
MAX_ROWS_IN_CONTEXT = 300
XLSX_MIME = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'


def _own_chat(chat_id):
    chat = chatstore.get(chat_id, g.qradar_user)
    if chat is None:
        return None, (jsonify(error='Chat not found.'), 404)
    return chat, None


@chatbp.route('/api/chats')
@admin_required
def list_chats():
    return jsonify(chats=chatstore.list_for(g.qradar_user))


@chatbp.route('/api/chats', methods=['POST'])
@admin_required
def create_chat():
    model = (request.get_json(silent=True) or {}).get('model')
    if model is not None and model not in claude.MODELS:
        return jsonify(error='Unknown model.'), 400
    chat = chatstore.create(g.qradar_user, model=model)
    return jsonify(chat={k: chat[k] for k in ('id', 'title', 'created', 'updated')}), 201


@chatbp.route('/api/chats/<chat_id>')
@admin_required
def get_chat(chat_id):
    chat, error = _own_chat(chat_id)
    if error:
        return error
    run = agent.active_run(chat_id)
    pending = chat['pending_context']
    return jsonify(chat=dict({k: chat[k] for k in ('id', 'title', 'created', 'updated')},
                             model=agent.model_for(chat)),
                   items=agent.transcript(chatstore.messages(chat_id),
                                          chatstore.uploads(chat_id)),
                   active_run=run.id if run else None,
                   pending_attachment=bool(pending))


@chatbp.route('/api/chats/<chat_id>/model', methods=['PUT'])
@admin_required
def set_chat_model(chat_id):
    chat, error = _own_chat(chat_id)
    if error:
        return error
    model = (request.get_json(silent=True) or {}).get('model')
    if model not in claude.MODELS:
        return jsonify(error='Unknown model.'), 400
    chatstore.set_model(chat['id'], model)
    return jsonify(model=model)


@chatbp.route('/api/chats/<chat_id>', methods=['DELETE'])
@admin_required
def delete_chat(chat_id):
    if agent.active_run(chat_id):
        return jsonify(error='Wait for the current answer to finish, or stop it first.'), 409
    if not chatstore.delete(chat_id, g.qradar_user):
        return jsonify(error='Chat not found.'), 404
    return jsonify(deleted=True)


@chatbp.route('/api/chats/<chat_id>/messages', methods=['POST'])
@admin_required
def send_message(chat_id):
    chat, error = _own_chat(chat_id)
    if error:
        return error
    text = str((request.get_json(silent=True) or {}).get('text', '')).strip()
    if not text:
        return jsonify(error='Type a message first.'), 400
    if len(text) > MAX_MESSAGE_LENGTH:
        return jsonify(error='Messages are limited to {0} characters. For long lists, upload '
                             'an Excel file.'.format(MAX_MESSAGE_LENGTH)), 400
    try:
        run = agent.start(chat, g.qradar_user, text)
    except agent.AgentError as exc:
        return jsonify(error=str(exc)), 409
    return jsonify(run_id=run.id), 202


@chatbp.route('/api/runs/<run_id>')
@admin_required
def run_events(run_id):
    run = agent.get_run(run_id, g.qradar_user)
    if run is None:
        return jsonify(error='This answer is no longer available.'), 404
    after = request.args.get('after', '0')
    index = int(after) if after.isdigit() else 0
    events, done = run.since(index)
    return jsonify(events=events, next=index + len(events), done=done)


@chatbp.route('/api/runs/<run_id>/cancel', methods=['POST'])
@admin_required
def cancel_run(run_id):
    run = agent.get_run(run_id, g.qradar_user)
    if run is None:
        return jsonify(error='This answer is no longer available.'), 404
    run.cancelled = True
    return jsonify(cancelled=True)


def _context_text(filename, result):
    """The bulk check summary Claude sees with the next message."""
    counts = result['counts']
    lines = ['[Attached: bulk check of {0}]'.format(filename),
             'Rows checked: {targets}. Rows with a log source receiving events: {connected}. '
             'Rows with log sources not receiving: {not_connected}. Rows with no log source: '
             '{not_found}.'.format(**counts)]
    not_receiving = [r for r in result['rows'] if r['source']['state'] != 'connected']
    if not_receiving:
        lines.append('Log sources not receiving events (row, input, log source, state, '
                     'last event):')
        for r in not_receiving[:MAX_ROWS_IN_CONTEXT]:
            src = r['source']
            lines.append('- row {0}: {1} -> {2} (id {3}), {4}, last event {5}'.format(
                r['row'], r['ip'] or r['hostname'], src['name'], src['id'], src['state_label'],
                src['last_event_age'] + ' ago' if src['last_event_age'] else 'never'))
        if len(not_receiving) > MAX_ROWS_IN_CONTEXT:
            lines.append('- ... {0} more in the downloaded file'.format(
                len(not_receiving) - MAX_ROWS_IN_CONTEXT))
    if result['not_found']:
        lines.append('Rows with no log source (row, IP, hostname):')
        for t in result['not_found'][:MAX_ROWS_IN_CONTEXT]:
            lines.append('- row {0}: {1} {2}'.format(t['row'], t['ip'], t['hostname']).rstrip())
        if len(result['not_found']) > MAX_ROWS_IN_CONTEXT:
            lines.append('- ... {0} more in the downloaded file'.format(
                len(result['not_found']) - MAX_ROWS_IN_CONTEXT))
    return '\n'.join(lines)


# Bulk check: upload an .xlsx of IPs and/or hostnames. The result workbook is saved with the
# chat (so it can be downloaded again after a reload) and its summary is attached to the chat's
# next message so the agent can discuss it.
@chatbp.route('/api/chats/<chat_id>/bulk_check', methods=['POST'])
@admin_required
def bulk_check(chat_id):
    chat, error = _own_chat(chat_id)
    if error:
        return error
    upload = request.files.get('file')
    if upload is None or not upload.filename:
        return jsonify(error='Choose an Excel file to upload.'), 400
    if not upload.filename.lower().endswith('.xlsx'):
        return jsonify(error='Upload an Excel Workbook (.xlsx). Older .xls files and macro-enabled '
                             'workbooks are not accepted.'), 400
    try:
        targets = bulk.read_targets(upload.read())
        sources = qradar.log_sources()
    except bulk.BulkError as exc:
        return jsonify(error=str(exc)), 400
    except qradar.QRadarError as exc:
        return jsonify(error=str(exc)), 502
    now_ms = int(time.time() * 1000)
    result = bulk.check(targets, sources, now_ms)
    workbook = bulk.build_workbook(result, upload.filename, now_ms)
    counts = result['counts']
    summary = ('Checked {targets} rows. With a log source receiving events: {connected}. '
               'With log sources not receiving: {not_connected}. With no log source: '
               '{not_found}. The results are attached to your next message, so you can ask me '
               'about them.').format(**counts)
    upload_id = chatstore.add_upload(chat['id'], upload.filename,
                                     time.strftime('log-source-check-%Y%m%d-%H%M.xlsx'),
                                     summary, counts, workbook)
    chatstore.set_pending_context(chat['id'], {'text': _context_text(upload.filename, result)})
    qpylib.log('bulk_check rows={targets} connected={connected} not_connected={not_connected} '
               'not_found={not_found}'.format(**counts), level='INFO')
    return jsonify(upload_id=upload_id, counts=counts), 201


@chatbp.route('/api/chats/<chat_id>/uploads/<upload_id>/result')
@admin_required
def upload_result(chat_id, upload_id):
    chat, error = _own_chat(chat_id)
    if error:
        return error
    found = chatstore.upload_file(chat['id'], upload_id)
    if found is None:
        return jsonify(error='File not found.'), 404
    filename, workbook = found
    return send_file(io.BytesIO(workbook), mimetype=XLSX_MIME, as_attachment=True,
                     download_name=filename)
