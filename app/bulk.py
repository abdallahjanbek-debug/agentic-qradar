"""Feature: bulk log source check from an Excel file.

The upload's first two columns hold an IP address, a hostname, or one of each. Every cell is
classified by its content, so column order and an optional header row don't matter. The result
is a workbook with Summary, Connected, Not connected and Not found sheets.

No QRadar or Flask imports, so it can be tested on its own.
"""

import datetime
import io
import os

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter

from . import logsources

MAX_ROWS = 5000
MAX_CELL_LENGTH = 253  # longest valid DNS name
HEADER_WORDS = {'ip', 'ip address', 'ipaddress', 'address', 'ip_address', 'host', 'hostname',
                'host name', 'host_name', 'fqdn', 'name', 'device', 'device name', 'server'}

SOURCE_COLUMNS = ['Row', 'Input IP', 'Input hostname', 'Log source', 'Type', 'Identifier',
                  'State', 'Last event', 'Since last event', 'Avg EPS', 'Collector',
                  'Matched by', 'QRadar status message']
NOT_FOUND_COLUMNS = ['Row', 'Input IP', 'Input hostname']

_HEADER_FONT = Font(bold=True, color='FFFFFF')
_HEADER_FILL = PatternFill(fill_type='solid', start_color='0F62FE', end_color='0F62FE')
_STATE_FILLS = {
    'connected': PatternFill(fill_type='solid', start_color='DEFBE6', end_color='DEFBE6'),
    'silent': PatternFill(fill_type='solid', start_color='FFD7D9', end_color='FFD7D9'),
    'never': PatternFill(fill_type='solid', start_color='FCF4D6', end_color='FCF4D6'),
    'disabled': PatternFill(fill_type='solid', start_color='E8E8E8', end_color='E8E8E8'),
}


class BulkError(Exception):
    """The upload can't be processed; the message is safe to show to the user."""


def _cell_text(value):
    if value is None:
        return ''
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return str(value).strip()


def read_targets(data):
    """[{'row': n, 'ip': str, 'hostname': str}] from the bytes of an .xlsx file."""
    try:
        workbook = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    except Exception as exc:  # openpyxl raises many types for damaged or non-xlsx files
        raise BulkError("This isn't a readable .xlsx file. Save it as an Excel Workbook "
                        '(.xlsx) and try again.') from exc
    try:
        sheet = workbook.worksheets[0]
        targets = []
        first = True
        for row_number, row in enumerate(sheet.iter_rows(max_col=2, values_only=True), start=1):
            cells = [_cell_text(v) for v in row if _cell_text(v)]
            if not cells:
                continue
            if first:
                first = False
                if all(c.lower() in HEADER_WORDS for c in cells):
                    continue
            ip = next((c for c in cells if logsources.is_ip(c)), '')
            hostname = next((c for c in cells if c != ip), '')
            if len(hostname) > MAX_CELL_LENGTH:
                raise BulkError('Row {0}: the hostname is longer than {1} characters.'.format(
                    row_number, MAX_CELL_LENGTH))
            targets.append({'row': row_number, 'ip': ip, 'hostname': hostname})
            if len(targets) > MAX_ROWS:
                raise BulkError('The file has more than {0} rows. Split it into smaller files.'
                                .format(MAX_ROWS))
    finally:
        workbook.close()
    if not targets:
        raise BulkError('The first sheet has no IP addresses or hostnames in columns A and B.')
    return targets


def check(targets, sources, now_ms):
    """Look up every target. Returns {'rows': [...], 'not_found': [...], 'counts': {...}}."""
    rows, not_found = [], []
    counts = {'targets': len(targets), 'connected': 0, 'not_connected': 0, 'not_found': 0}
    for target in targets:
        found = logsources.match_target(target['ip'], target['hostname'], sources)
        states = set()
        for src, how in found:
            info = logsources.describe(src, now_ms)
            states.add(info['state'])
            rows.append(dict(target, source=info, matched_by=how))
        status = logsources.target_status(states)
        counts[status] += 1
        if status == 'not_found':
            not_found.append(target)
    return {'rows': rows, 'not_found': not_found, 'counts': counts}


def _local_time(ms):
    # The container's TZ is the console's time zone; Excel has no time zones, so write local.
    return datetime.datetime.fromtimestamp(ms / 1000) if ms else None


def _append(sheet, values):
    sheet.append(values)
    for cell in sheet[sheet.max_row]:
        # openpyxl stores text starting with "=" as a formula. Force plain text, so a log
        # source name or uploaded cell can never run as a formula when the file is opened.
        if isinstance(cell.value, str):
            cell.data_type = 's'
    return sheet[sheet.max_row]


def _table(sheet, columns, widths):
    _append(sheet, columns)
    for cell in sheet[1]:
        cell.font = _HEADER_FONT
        cell.fill = _HEADER_FILL
    sheet.freeze_panes = 'A2'
    for index, width in enumerate(widths, start=1):
        sheet.column_dimensions[get_column_letter(index)].width = width


def _source_sheet(sheet, rows):
    _table(sheet, SOURCE_COLUMNS, [7, 16, 28, 40, 34, 28, 22, 20, 18, 9, 28, 30, 50])
    for item in rows:
        src = item['source']
        cells = _append(sheet, [
            item['row'], item['ip'], item['hostname'], src['name'], src['type'],
            src['identifier'], src['state_label'], _local_time(src['last_event_time']),
            src['last_event_age'] or '', src['average_eps'], src['collector'], item['matched_by'],
            '; '.join(src['messages']),
        ])
        cells[6].fill = _STATE_FILLS[src['state']]
        cells[7].number_format = 'yyyy-mm-dd hh:mm:ss'
    if rows:
        sheet.auto_filter.ref = sheet.dimensions


def build_workbook(result, source_filename, now_ms):
    """The result workbook as .xlsx bytes."""
    counts = result['counts']
    workbook = Workbook()
    summary = workbook.active
    summary.title = 'Summary'
    summary.column_dimensions['A'].width = 52
    summary.column_dimensions['B'].width = 40
    for label, value in [
        ('AI Admin: bulk log source check', None),
        ('Checked', _local_time(now_ms)),
        ('Uploaded file', source_filename),
        ('Rows checked', counts['targets']),
        ('Rows with a log source receiving events', counts['connected']),
        ('Rows with log sources, none receiving events', counts['not_connected']),
        ('Rows with no log source found', counts['not_found']),
        ('"Receiving events" means', 'last event within {0} minutes'.format(
            logsources.STALE_MINUTES)),
        ('Times are in the QRadar console time zone', os.environ.get('TZ', 'local time')),
    ]:
        _append(summary, [label, value])
    summary['A1'].font = Font(bold=True, size=14)
    summary['B2'].number_format = 'yyyy-mm-dd hh:mm:ss'
    summary.append([])
    _append(summary, ['Sheets', ''])
    summary.cell(summary.max_row, 1).font = Font(bold=True)
    for name, text in [('Connected', 'log sources receiving events, per uploaded row'),
                       ('Not connected', 'log sources not receiving, never received, or disabled'),
                       ('Not found', 'uploaded rows with no matching log source')]:
        _append(summary, [name, text])

    connected = [r for r in result['rows'] if r['source']['state'] == 'connected']
    others = [r for r in result['rows'] if r['source']['state'] != 'connected']
    _source_sheet(workbook.create_sheet('Connected'), connected)
    _source_sheet(workbook.create_sheet('Not connected'), others)
    missing = workbook.create_sheet('Not found')
    _table(missing, NOT_FOUND_COLUMNS, [7, 16, 40])
    for target in result['not_found']:
        _append(missing, [target['row'], target['ip'], target['hostname']])
    if result['not_found']:
        missing.auto_filter.ref = missing.dimensions

    out = io.BytesIO()
    workbook.save(out)
    return out.getvalue()


def template_workbook():
    """A sample upload file with the expected layout."""
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = 'Targets'
    _table(sheet, ['IP', 'Hostname'], [18, 36])
    for row in [['10.1.2.3', 'fw01.example.local'], ['10.1.2.4', ''], ['', 'dc01.example.local']]:
        _append(sheet, row)
    out = io.BytesIO()
    workbook.save(out)
    return out.getvalue()
