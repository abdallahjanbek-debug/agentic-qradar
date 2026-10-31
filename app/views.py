import base64
import io
import time

from flask import (Blueprint, current_app, jsonify, render_template, request, send_file,
                   send_from_directory)
from qpylib import qpylib

from . import assistant, bulk, qradar
from .auth import admin_required

# pylint: disable=invalid-name
viewsbp = Blueprint('viewsbp', __name__, url_prefix='/')

MAX_QUESTION_LENGTH = 2000
XLSX_MIME = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'


@viewsbp.route('/')
@viewsbp.route('/index')
@admin_required
def index():
    return render_template('chat.html')


# Answers one chat question. POST through QRadar.fetch so use_qradar_csrf protects it.
@viewsbp.route('/api/ask', methods=['POST'])
@admin_required
def ask():
    body = request.get_json(silent=True) or {}
    question = str(body.get('question', '')).strip()[:MAX_QUESTION_LENGTH]
    if not question:
        return jsonify(error='Type a question first.'), 400
    try:
        result = assistant.answer(question)
    except qradar.QRadarError as exc:
        return jsonify(error=str(exc)), 502
    qpylib.log('ask feature={0} matches={1}'.format(result['feature'],
                                                    len(result.get('matches', []))),
               level='INFO')
    return jsonify(result)


# Bulk check: upload an .xlsx of IPs and/or hostnames, get back a result workbook. The file is
# returned base64-encoded in JSON so the chat can show the summary and offer the download.
@viewsbp.route('/api/bulk_check', methods=['POST'])
@admin_required
def bulk_check():
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
    qpylib.log('bulk_check rows={targets} connected={connected} not_connected={not_connected} '
               'not_found={not_found}'.format(**counts), level='INFO')
    answer = ('Checked {targets} rows: {connected} have a log source receiving events, '
              '{not_connected} have log sources that are not receiving, and {not_found} have no '
              'log source.').format(**counts)
    return jsonify(feature='bulk_check', answer=answer, counts=counts,
                   filename=time.strftime('log-source-check-%Y%m%d-%H%M.xlsx'),
                   file_base64=base64.b64encode(workbook).decode('ascii'))


@viewsbp.route('/api/bulk_template')
@admin_required
def bulk_template():
    return send_file(io.BytesIO(bulk.template_workbook()), mimetype=XLSX_MIME,
                     as_attachment=True, download_name='log-source-check-template.xlsx')


# The presence of this endpoint avoids a Flask error being logged when a browser
# makes a favicon.ico request.
@viewsbp.route('/favicon.ico')
def favicon():
    return send_from_directory(current_app.static_folder, 'favicon-16x16.png')
