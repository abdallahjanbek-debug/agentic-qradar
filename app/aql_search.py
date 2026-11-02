"""Feature: event searches (AQL) for the agent, under strict guardrails.

The agent never writes AQL text. It sends a structured request (filters on allowed fields and
a time range) and this module builds the query, so by construction:
- filters use only ALLOWED_FILTER_FIELDS, with at least one inclusion filter;
- the columns are QRadar's default Log Activity columns plus the payload;
- every query has LIMIT 50 and a time range of at most the configured maximum.
QRadar's own validator then checks the generated AQL before it runs, and a running search is
cancelled when it exceeds SEARCH_TIMEOUT_SECONDS or the user presses Stop. Every search is
recorded in the audit table.
"""

import datetime
import ipaddress
import threading
import time

from qpylib import qpylib

from . import chatstore, qradar, settings

RESULT_LIMIT = 50
SEARCH_TIMEOUT_SECONDS = 600
MAX_CONCURRENT_SEARCHES = 5
POLL_SECONDS = 2
MAX_VALUES_PER_FILTER = 50
MAX_RESOLVED_IDS = 200
PAYLOAD_CHARS_FOR_CLAUDE = 4000

# QRadar's default Log Activity columns, then the payload. Not user-selectable.
COLUMNS = [
    ('QIDNAME(qid)', 'Event Name'),
    ('LOGSOURCENAME(logsourceid)', 'Log Source'),
    ('eventcount', 'Event Count'),
    ("DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss')", 'Time'),
    ('CATEGORYNAME(category)', 'Low Level Category'),
    ('sourceip', 'Source IP'),
    ('sourceport', 'Source Port'),
    ('destinationip', 'Destination IP'),
    ('destinationport', 'Destination Port'),
    ('username', 'Username'),
    ('magnitude', 'Magnitude'),
    ('UTF8(payload)', 'Payload'),
]

# field -> allowed operators. The only fields a search may filter on.
ALLOWED_FILTER_FIELDS = {
    'source_ip': ('equals', 'not_equals', 'in', 'in_cidr'),
    'destination_ip': ('equals', 'not_equals', 'in', 'in_cidr'),
    'log_source': ('equals', 'not_equals', 'contains'),
    'log_source_type': ('equals', 'not_equals', 'contains'),
    'username': ('equals', 'not_equals', 'contains'),
    'event_name': ('equals', 'not_equals', 'contains'),
    'qradar_event_id': ('equals', 'not_equals', 'in'),
    'qid': ('equals', 'not_equals', 'in'),
}
INCLUDE_OPERATORS = ('equals', 'in', 'in_cidr', 'contains')
# Characters that could end a string literal or confuse the AQL parser.
FORBIDDEN_CHARACTERS = set('\'"\\\r\n\t\x00')

_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SEARCHES)


class SearchError(Exception):
    """The search request is invalid or the search failed; safe to show to the user/Claude."""


# ---- Building the AQL ------------------------------------------------------------------------

def _text(value, field):
    value = str(value).strip()
    if not value or len(value) > 200 or FORBIDDEN_CHARACTERS & set(value):
        raise SearchError('{0}: "{1}" is not allowed (1-200 characters; no quotes, '
                          'backslashes or line breaks).'.format(field, value[:50]))
    return value


def _ips(values, field, cidr):
    out = []
    for value in values:
        try:
            if cidr:
                out.append(str(ipaddress.ip_network(str(value).strip(), strict=False)))
            else:
                out.append(str(ipaddress.ip_address(str(value).strip())))
        except ValueError as exc:
            raise SearchError('{0}: "{1}" is not a valid {2}.'.format(
                field, str(value)[:50], 'CIDR range' if cidr else 'IP address')) from exc
    return out


def _ints(values, field):
    try:
        return [int(str(v).strip()) for v in values]
    except ValueError as exc:
        raise SearchError('{0}: values must be whole numbers.'.format(field)) from exc


def _match_names(names_by_id, values, operator, field):
    """IDs whose name equals (case-insensitive) or contains any value; numeric values are IDs."""
    wanted = [_text(v, field).lower() for v in values]
    ids = set()
    for value in wanted:
        if value.isdigit() and int(value) in names_by_id:
            ids.add(int(value))
            continue
        for item_id, name in names_by_id.items():
            name = (name or '').lower()
            if (operator == 'contains' and value in name) or name == value:
                ids.add(item_id)
    if not ids:
        raise SearchError('{0}: nothing matches {1}.'.format(field, ', '.join(wanted)))
    if len(ids) > MAX_RESOLVED_IDS:
        raise SearchError('{0}: {1} matches; be more specific.'.format(field, len(ids)))
    return sorted(ids)


def _event_qids(values, operator):
    """QIDs whose event name equals or contains the value, from QRadar's QID records."""
    qids = set()
    for value in values:
        value = _text(value, 'event_name')
        pattern = '%{0}%'.format(value) if operator == 'contains' else value
        resp = qradar.call('GET', 'api/data_classification/qid_records',
                           params={'filter': 'name ILIKE "{0}"'.format(pattern), 'fields': 'qid'},
                           headers={'Range': 'items=0-{0}'.format(MAX_RESOLVED_IDS)})
        qids.update(r['qid'] for r in resp.json())
    if not qids:
        raise SearchError('event_name: no QRadar event is named {0}.'.format(', '.join(values)))
    if len(qids) > MAX_RESOLVED_IDS:
        raise SearchError('event_name: more than {0} event types match; be more specific.'
                          .format(MAX_RESOLVED_IDS))
    return sorted(qids)


def _in_list(column, items, negate, quote=False):
    rendered = ', '.join("'{0}'".format(i) if quote else str(i) for i in items)
    if len(items) == 1:
        return '{0} {1} {2}'.format(column, '!=' if negate else '=', rendered)
    return '{0}{1} IN ({2})'.format('NOT ' if negate else '', column, rendered)


def _condition(spec):
    if not isinstance(spec, dict):
        raise SearchError('Each filter must be an object with field, operator and values.')
    field, operator, values = spec.get('field'), spec.get('operator'), spec.get('values')
    if field not in ALLOWED_FILTER_FIELDS:
        raise SearchError('Filtering on "{0}" is not allowed. Allowed fields: {1}.'.format(
            field, ', '.join(ALLOWED_FILTER_FIELDS)))
    if operator not in ALLOWED_FILTER_FIELDS[field]:
        raise SearchError('{0} supports these operators: {1}.'.format(
            field, ', '.join(ALLOWED_FILTER_FIELDS[field])))
    if isinstance(values, (str, int)):
        values = [values]
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_VALUES_PER_FILTER:
        raise SearchError('{0}: give 1 to {1} values.'.format(field, MAX_VALUES_PER_FILTER))
    if operator in ('equals', 'not_equals', 'contains') and len(values) > 1 and \
            field in ('source_ip', 'destination_ip', 'qradar_event_id', 'qid'):
        operator = 'in' if operator == 'equals' else operator
    negate = operator == 'not_equals'

    if field in ('source_ip', 'destination_ip'):
        column = 'sourceip' if field == 'source_ip' else 'destinationip'
        if operator == 'in_cidr':
            ranges = _ips(values, field, cidr=True)
            return '(' + ' OR '.join("INCIDR('{0}', {1})".format(r, column) for r in ranges) + ')'
        return _in_list(column, _ips(values, field, cidr=False), negate, quote=True)
    if field == 'log_source':
        names = {s['id']: s['name'] for s in qradar.log_sources()}
        return _in_list('logsourceid', _match_names(names, values, operator, field), negate)
    if field == 'log_source_type':
        ids = _match_names(qradar.log_source_types(), values, operator, field)
        return _in_list('devicetype', ids, negate)
    if field == 'username':
        texts = [_text(v, field) for v in values]
        pattern = '%{0}%' if operator == 'contains' else '{0}'
        joined = (' AND ' if negate else ' OR ').join(
            "username {0} '{1}'".format('NOT ILIKE' if negate else 'ILIKE', pattern.format(t))
            for t in texts)
        return '(' + joined + ')'
    if field == 'event_name':
        return _in_list('qid', _event_qids(values, operator), negate)
    if field == 'qradar_event_id':
        return _in_list('qideventid', [_text(v, field) for v in values], negate, quote=True)
    return _in_list('qid', _ints(values, field), negate)


def _time_clause(time_range, max_days):
    if not isinstance(time_range, dict):
        raise SearchError('time_range is required: {"last_minutes": n} or {"start": ..., '
                          '"end": ...}.')
    max_minutes = max_days * 1440
    if 'last_minutes' in time_range:
        minutes = time_range['last_minutes']
        if not isinstance(minutes, int) or isinstance(minutes, bool) or \
                not 1 <= minutes <= max_minutes:
            raise SearchError('last_minutes must be 1 to {0} ({1} days, the configured '
                              'maximum).'.format(max_minutes, max_days))
        return 'LAST {0} MINUTES'.format(minutes), minutes
    try:
        # Console-local time, which is also the container's time zone.
        start = datetime.datetime.strptime(str(time_range['start']), '%Y-%m-%d %H:%M')
        end = datetime.datetime.strptime(str(time_range['end']), '%Y-%m-%d %H:%M')
    except (KeyError, ValueError) as exc:
        raise SearchError('start and end must look like "2026-11-02 08:30" (console time).') \
            from exc
    minutes = int((end - start).total_seconds() // 60)
    if minutes < 1:
        raise SearchError('end must be after start.')
    if minutes > max_minutes:
        raise SearchError('The time range is {0:.1f} days; the maximum is {1} days.'.format(
            minutes / 1440, max_days))
    return 'START {0} STOP {1}'.format(int(start.timestamp() * 1000),
                                       int(end.timestamp() * 1000)), minutes


def build(request):
    """(aql, minutes) from the agent's structured request. Raises SearchError."""
    if not isinstance(request, dict):
        raise SearchError('The search request must be an object.')
    filters = request.get('filters')
    if not isinstance(filters, list) or not filters:
        raise SearchError('At least one filter is required.')
    if not any(isinstance(f, dict) and f.get('operator') in INCLUDE_OPERATORS for f in filters):
        raise SearchError('At least one filter must include something (equals, in, in_cidr or '
                          'contains); a search with only exclusions matches almost everything.')
    where = ' AND '.join(_condition(f) for f in filters)
    order = 'ASC' if request.get('order') == 'oldest_first' else 'DESC'
    time_clause, minutes = _time_clause(request.get('time_range'),
                                        settings.get_config('aql_max_window_days'))
    select = ', '.join('{0} AS "{1}"'.format(expr, name) for expr, name in COLUMNS)
    aql = 'SELECT {0} FROM events WHERE {1} ORDER BY starttime {2} LIMIT {3} {4}'.format(
        select, where, order, RESULT_LIMIT, time_clause)
    return aql, minutes


# ---- Running it ----------------------------------------------------------------------------

def validate(aql):
    """QRadar's own AQL validator: a list of error messages, empty when valid."""
    resp = qradar.call('POST', 'api/ariel/validators/aql', params={'query_expression': aql})
    return [m.get('message', '') for m in resp.json().get('error_messages') or []]


def _cancel(search_id):
    qradar.call('POST', 'api/ariel/searches/' + search_id, params={'status': 'CANCELED'},
                ok=(200, 202))


def _run(aql, should_stop):
    resp = qradar.call('POST', 'api/ariel/searches', params={'query_expression': aql},
                       ok=(200, 201))
    search_id = resp.json()['search_id']
    try:
        deadline = time.time() + SEARCH_TIMEOUT_SECONDS
        while True:
            status = qradar.call('GET', 'api/ariel/searches/' + search_id).json()
            if status['status'] == 'COMPLETED':
                break
            if status['status'] in ('ERROR', 'CANCELED'):
                messages = [m.get('message', '') for m in status.get('error_messages') or []]
                raise SearchError('QRadar could not run the search: {0}'.format(
                    '; '.join(messages) or status['status']))
            if should_stop():
                _cancel(search_id)
                raise SearchError('Stopped by the user; the search was cancelled.')
            if time.time() > deadline:
                _cancel(search_id)
                raise SearchError('The search took longer than {0} minutes and was cancelled. '
                                  'Narrow the filters or the time range.'
                                  .format(SEARCH_TIMEOUT_SECONDS // 60))
            time.sleep(POLL_SECONDS)
        results = qradar.call('GET', 'api/ariel/searches/{0}/results'.format(search_id),
                              headers={'Range': 'items=0-{0}'.format(RESULT_LIMIT - 1)})
        return results.json().get('events', [])
    finally:
        try:
            qradar.call('DELETE', 'api/ariel/searches/' + search_id, ok=(200, 202, 204, 404))
        except qradar.QRadarError:
            qpylib.log('Could not delete Ariel search {0}'.format(search_id), level='WARNING')


def search(request, owner, should_stop=lambda: False):
    """Build, validate and run one search. Returns a dict for Claude and the chat UI.
    should_stop() is checked while the search runs; True cancels it (the Stop button)."""
    started = time.time()
    aql = None
    status = 'rejected'
    rows = []
    try:
        aql, minutes = build(request)
        errors = validate(aql)
        if errors:
            raise SearchError('QRadar rejected the query: ' + '; '.join(errors))
        if not _slots.acquire(blocking=False):
            raise SearchError('{0} event searches are already running; try again shortly.'
                              .format(MAX_CONCURRENT_SEARCHES))
        try:
            status = 'failed'
            rows = _run(aql, should_stop)
            status = 'completed'
        finally:
            _slots.release()
    finally:
        chatstore.record_search(owner, aql, request, status, len(rows),
                                int((time.time() - started) * 1000))
    for row in rows:
        payload = row.get('Payload')
        if isinstance(payload, str) and len(payload) > PAYLOAD_CHARS_FOR_CLAUDE:
            row['Payload'] = payload[:PAYLOAD_CHARS_FOR_CLAUDE] + ' …[truncated]'
    return {'aql': aql, 'time_range_minutes': minutes, 'row_count': len(rows),
            'limited_to': RESULT_LIMIT, 'columns': [name for _, name in COLUMNS], 'rows': rows}
