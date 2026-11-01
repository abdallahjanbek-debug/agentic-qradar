import io

from flask import Blueprint, current_app, render_template, send_file, send_from_directory

from . import bulk
from .auth import admin_required

# pylint: disable=invalid-name
viewsbp = Blueprint('viewsbp', __name__, url_prefix='/')

XLSX_MIME = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'


@viewsbp.route('/')
@viewsbp.route('/index')
@admin_required
def index():
    return render_template('chat.html')


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
