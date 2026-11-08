"""Findings task: expensive searches.

QRadar's SIM Audit log source records every Ariel search twice with the same search ID:
"Search Executed" (who, from where, time range, and the filters: parsed criteria plus the AQL for
API/AQL searches, or the filter wording such as "Payload Contains is x" for Log Activity
searches built in the UI) and "Search
Completed" (status, data and index files scanned, results, search time, concurrent searches).
Each run reads both for the window since the previous run with one indexed AQL query, joins
them, applies fixed rules and records findings. Searches still running past the critical
duration are flagged before they finish. Starts are remembered between runs, so a search that
starts in one window and completes in a later one is still joined.
"""

import datetime
import hashlib
import re

from qpylib import qpylib

from . import aql_search, findingstore, qradar, settings

CATEGORY = 'expensive_searches'
TASK = 'expensive_searches'
# Marks this task's own audit query, so it never reports itself.
MARKER = 'aiadmin_findings_collector'
OVERLAP_MS = 2 * 60000            # re-read the end of the previous window for late events
MAX_WINDOW_MS = 24 * 3600000      # after a long outage, catch up at most a day
AUDIT_ROW_LIMIT = 10000

_ids = {}


# ---- Reading the audit events ----------------------------------------------------------------

def _audit_ids():
    """(SIM Audit log source type id, [Search Executed and Search Completed QIDs])."""
    if not _ids:
        types = qradar.log_source_types()
        type_id = next((i for i, name in types.items() if name == 'SIM Audit'), None)
        if type_id is None:
            raise aql_search.SearchError('No SIM Audit log source type on this console.')
        qids = []
        for name in ('Search Executed', 'Search Completed'):
            resp = qradar.call('GET', 'api/data_classification/qid_records',
                               params={'filter': 'name = "{0}"'.format(name), 'fields': 'qid'})
            qids += [r['qid'] for r in resp.json()]
        if not qids:
            raise aql_search.SearchError('The search audit QIDs were not found.')
        _ids['type'], _ids['qids'] = type_id, sorted(set(qids))
    return _ids['type'], _ids['qids']


def collector_aql(start_ms, stop_ms):
    type_id, qids = _audit_ids()
    # Only indexed fields, so this query is cheap and never a finding itself.
    return ('SELECT QIDNAME(qid) AS "{0}", starttime AS "Time", UTF8(payload) AS "Payload" '
            'FROM events WHERE devicetype = {1} AND qid IN ({2}) ORDER BY starttime ASC '
            'LIMIT {3} START {4} STOP {5}').format(MARKER, type_id, ', '.join(map(str, qids)),
                                                   AUDIT_ROW_LIMIT, start_ms, stop_ms)


def _first(pattern, text, flags=0):
    match = re.search(pattern, text, flags)
    return match.group(1).strip() if match else None


def _audit_time(text):
    """'26-11-01,20:52:00' (console time) -> epoch ms, or None."""
    try:
        return int(datetime.datetime.strptime(text, '%y-%m-%d,%H:%M:%S').timestamp() * 1000)
    except (TypeError, ValueError):
        return None


def parse_executed(payload):
    """Details from a "Search Executed" payload, or None if it isn't one."""
    if 'SearchExecuted' not in payload:
        return None
    search_id = _first(r'Id:([0-9a-f-]{36})', payload)
    if not search_id:
        return None
    window_from, window_to = None, None
    match = re.search(r'Time:<([^>]*) to ([^>]*)>', payload)
    if match:
        window_from, window_to = match.group(1).strip(), match.group(2).strip()
    seconds = _first(r'last (\d+) secs', payload)
    start, stop = _audit_time(window_from), _audit_time(window_to)
    if seconds is None and start and stop:
        seconds = (stop - start) // 1000
    aql = _first(r',AQL:(.*?)"?\s*$', payload, re.S)
    criteria = _first(r'Criteria=(.*?)(?:, MappingFactory=|, search top|, prio=|,AQL:|"\s*$)',
                      payload, re.S)
    # Log Activity searches built in the UI describe their filters in words instead.
    filters = _first(r'Filters:(.*?)(?:, Columns:|, Aggregates:|"\s*$)', payload, re.S)
    return {'search_id': search_id,
            'user': _first(r'User:([^,]*),', payload) or 'unknown',
            'source': _first(r'Source:([^,]*),', payload) or 'unknown',
            'db': _first(r'DB:<([^@>,]+)', payload),
            'window_from': window_from, 'window_to': window_to,
            'window_seconds': int(seconds) if seconds is not None else None,
            'criteria': criteria, 'filters': filters, 'aql': aql}


def parse_completed(payload):
    """Statistics from a "Search Completed" payload, or None if it isn't one."""
    if 'SearchCompleted' not in payload:
        return None
    search_id = _first(r'Id:([0-9a-f-]{36})', payload)
    if not search_id:
        return None
    stats = {key: float(value) for key, value in
             re.findall(r'(\w+)=(\d+(?:\.\d+)?)(?=[,\]%])', payload)}
    search_ms = _first(r'searchTime=(\d+)ms', payload)
    concurrent = _first(r'concurrent queries="(\d+)"', payload)
    return {'search_id': search_id,
            'status': _first(r'status=(\w+)', payload) or 'unknown',
            'search_ms': int(search_ms) if search_ms else None,
            'data_bytes': int(stats.get('dataTotalSize', 0) + stats.get('compressedDataTotalSize', 0)),
            'index_bytes': int(stats.get('indexTotalSize', 0)),
            'data_files': int(stats.get('dataFileCount', 0) + stats.get('compressedDataFileCount', 0)),
            'index_files': int(stats.get('indexFileCount', 0)),
            'results': int(stats.get('totalResult', 0)),
            'concurrent': int(concurrent) if concurrent else None}


# ---- Rules ---------------------------------------------------------------------------------

# Log Activity filter wording (as the audit log records UI searches) that cannot use indexes.
UI_FILTER_REASONS = [
    (re.compile(r'\bPayload (Contains|Does Not Contain)\b', re.I), 'filters on the raw payload'),
    (re.compile(r'\bMatches Regular Expression\b|\bMatches Regex\b', re.I),
     'uses regular expressions'),
    (re.compile(r'\bQuick Filter\b', re.I), 'uses full-text search'),
    (re.compile(r'\b(?!Payload\b)\w[\w ()-]* (Contains|Does Not Contain)\b', re.I),
     'uses substring matching (Contains)'),
]


def costly_filters(criteria, aql, filters=None):
    """Reasons the search's filters can't use indexes, whatever its time range. criteria and
    aql come from API/AQL searches, filters from Log Activity searches built in the UI."""
    reasons = []
    for clause in re.split(r',\s*(?=[A-Z])', filters or ''):
        for pattern, reason in UI_FILTER_REASONS:
            if pattern.search(clause) and reason not in reasons:
                reasons.append(reason)
                break
    criteria, aql = criteria or '', aql or ''
    match = re.search(r'\bWHERE\b(.*)', aql, re.I | re.S)
    where = match.group(1) if match else ''
    # UTF8() is how payload filters appear; that has its own reason below.
    functions = sorted(set(re.findall(r'pr=(\w+)\(\)', criteria)) - {'UTF8'})
    if functions:
        reasons.append('filters through functions that cannot use indexes: {0}'.format(
            ', '.join(f + '()' for f in functions)))
    if (re.search(r'payload', criteria, re.I) or
            re.search(r'UTF8\s*\(\s*payload\s*\)', where, re.I)) and \
            'filters on the raw payload' not in reasons:
        reasons.append('filters on the raw payload')
    if re.search(r'I?Matches|Regex', criteria) or re.search(r'\bI?MATCHES\b', where, re.I):
        reasons.append('uses regular expressions')
    # LIKE/ILIKE only costs when the pattern has a wildcard; ILIKE 'bob' is just case-insensitive
    # equality. QRadar's parsed criteria show wildcards as regex (.*), the AQL as % or _.
    like_patterns = re.findall(r":I?Like\('([^']*)'\)", criteria) + \
        re.findall(r"\bI?LIKE\s+'([^']*)'", where, re.I)
    if any(w in pattern for pattern in like_patterns for w in ('%', '.*')):
        reasons.append('uses wildcard (LIKE/ILIKE) matching')
    if re.search(r'TEXT\s+SEARCH', aql, re.I) or 'FullText' in criteria:
        reasons.append('uses full-text search')
    return reasons


def thresholds():
    return {'warning_ms': settings.get_config('findings_long_warning_minutes') * 60000,
            'critical_ms': settings.get_config('findings_long_critical_minutes') * 60000,
            'heavy_bytes': settings.get_config('findings_heavy_scan_gb') * 10 ** 9}


def evaluate(start, done, limits):
    """(severity, reasons) for a completed search, or (None, []) when it isn't a finding."""
    reasons, severity = [], None
    duration = done.get('search_ms') or 0
    if duration >= limits['critical_ms']:
        severity = 'critical'
        reasons.append('ran for {0:.1f} min'.format(duration / 60000))
    elif duration >= limits['warning_ms']:
        severity = 'warning'
        reasons.append('ran for {0:.1f} min'.format(duration / 60000))
    if done.get('data_bytes', 0) >= limits['heavy_bytes']:
        severity = severity or 'warning'
        reasons.append('scanned {0:.1f} GB of data'.format(done['data_bytes'] / 10 ** 9))
    start = start or {}
    costly = costly_filters(start.get('criteria'), start.get('aql'), start.get('filters'))
    if costly:
        severity = severity or 'warning'
        reasons += costly
    return severity, reasons


# ---- Grouping repeats ----------------------------------------------------------------------

def normalize(query):
    """The query with literals and the time range removed, so repeats group together."""
    text = re.sub(r'\s+', ' ', query or '').strip()
    text = re.sub(r'\b(LAST\s+\d+\s+\w+|START\s+\S+\s+STOP\s+\S+)\b', '', text, flags=re.I)
    text = re.sub(r"'[^']*'", "'?'", text)
    text = re.sub(r'\b\d+(\.\d+)?\b', '#', text)
    return text.strip().lower()


def normalize_filters(filters):
    """UI filter wording with the values removed: "Payload Contains is x" -> "... is ?"."""
    return re.sub(r'(\bis(?: not)?\s+)[^,]+', r'\1?', filters or '').strip().lower()


def fingerprint(start):
    if not (start.get('aql') or start.get('criteria')) and start.get('filters'):
        query = normalize_filters(start['filters'])
    else:
        query = normalize(start.get('aql') or start.get('criteria') or start.get('search_id'))
    key = '|'.join([start.get('user') or '', start.get('source') or '', query])
    return hashlib.sha256(key.encode()).hexdigest()[:24]


def _title(severity, reasons, start):
    headline = '; '.join(r for r in reasons if r.startswith(('ran for', 'scanned',
                                                             'still running')))
    if not headline:
        headline = 'uses costly filters'
    who = '{0} ({1})'.format(start.get('user', 'unknown'), start.get('source', 'unknown'))
    return 'Search {0} · {1}'.format(headline, who)


def _record(start, done, severity, reasons, seen_ms):
    """Create or update the finding for this search's query, keeping the worst numbers seen."""
    fp = fingerprint(start)
    previous = findingstore.by_fingerprint(CATEGORY, fp)
    worst = dict((previous or {}).get('details', {}).get('worst') or {})
    if done:
        worst['search_ms'] = max(worst.get('search_ms') or 0, done.get('search_ms') or 0)
        worst['data_bytes'] = max(worst.get('data_bytes') or 0, done.get('data_bytes') or 0)
    recent = ((previous or {}).get('details', {}).get('recent') or [])[-4:]
    recent.append({'search_id': start.get('search_id'), 'seen': seen_ms,
                   'status': (done or {}).get('status', 'running')})
    details = {'user': start.get('user'), 'source': start.get('source'), 'db': start.get('db'),
               'aql': start.get('aql'), 'criteria': start.get('criteria'),
               'filters': start.get('filters'),
               'window_seconds': start.get('window_seconds'),
               'window_from': start.get('window_from'), 'window_to': start.get('window_to'),
               'last': done, 'worst': worst, 'reasons': reasons, 'recent': recent}
    return findingstore.upsert(CATEGORY, fp, severity, _title(severity, reasons, start),
                               details, seen_ms)


def _still_executing(search_id):
    """Whether QRadar's live search list shows the search as still running. Completed,
    cancelled, failed or no longer listed all mean no."""
    try:
        resp = qradar.call('GET', 'api/ariel/searches/' + search_id, ok=(200, 404))
    except qradar.QRadarError:
        return False  # can't confirm: don't raise a critical finding on a guess
    if resp.status_code == 404:
        return False
    return resp.json().get('status') in ('WAIT', 'EXECUTE', 'SORTING')


# ---- One run -------------------------------------------------------------------------------

def run():
    """One scheduled run. Returns (new findings, updated findings, message)."""
    now = findingstore.now_ms()
    state = findingstore.task_state(TASK)
    if state['watermark'] is None:
        # Start from now: the first run only marks where to begin.
        findingstore.set_task_state(TASK, watermark=now)
        return 0, 0, 'Watching searches from now on.'
    start_ms = max(state['watermark'] - OVERLAP_MS, now - MAX_WINDOW_MS)

    def build_aql():
        return collector_aql(start_ms, now), None

    rows, _ = aql_search.run_guarded(build_aql, {'task': TASK, 'from': start_ms, 'to': now},
                                     'AI Admin scheduler', limit=AUDIT_ROW_LIMIT)
    limits = thresholds()
    new = updated = 0
    # Starts first: a fast search's start and completion share a timestamp and can come back
    # in either order.
    for row in rows:
        executed = parse_executed(row.get('Payload') or '')
        if executed:
            findingstore.remember_start(executed['search_id'], int(row.get('Time') or now),
                                        executed)
    for row in rows:
        payload, seen = row.get('Payload') or '', int(row.get('Time') or now)
        done = parse_completed(payload)
        if not done or not findingstore.mark_done(done['search_id']):
            continue
        start = (findingstore.start_of(done['search_id']) or {}).get('details') or \
            {'search_id': done['search_id'], 'user': 'unknown', 'source': 'unknown'}
        if MARKER in (start.get('aql') or ''):
            continue
        severity, reasons = evaluate(start, done, limits)
        if severity:
            outcome = _record(start, done, severity, reasons, seen)
            new += outcome == 'new'
            updated += outcome != 'new'

    # Searches still running past the critical duration, flagged before they finish. The audit
    # log alone can miss a completion, so QRadar must confirm the search is still executing.
    for pending in findingstore.still_running(now - limits['critical_ms']):
        start = pending['details']
        if MARKER in (start.get('aql') or '') or not _still_executing(pending['search_id']):
            findingstore.mark_completed(pending['search_id'])
            continue
        minutes = (now - pending['started']) / 60000
        reasons = ['still running after {0:.0f} min'.format(minutes)] + \
            costly_filters(start.get('criteria'), start.get('aql'), start.get('filters'))
        outcome = _record(start, None, 'critical', reasons, now)
        findingstore.mark_flagged_running(pending['search_id'])
        new += outcome == 'new'
        updated += outcome != 'new'

    findingstore.set_task_state(TASK, watermark=now)
    findingstore.prune()
    message = 'Read {0} audit events.'.format(len(rows))
    if len(rows) >= AUDIT_ROW_LIMIT:
        message += ' The audit limit was reached; run the task more often.'
        qpylib.log('Expensive searches: audit row limit reached', level='WARNING')
    return new, updated, message
