"""Read-only tools the AI Admin agent can call.

Each tool is a JSON schema Claude sees plus a handler that runs here. Add a feature by adding a
Tool to TOOLS. Handlers validate their own input (inputs are streamed, so the API does not
validate them), never change QRadar, and return JSON-serializable dicts.
"""

import collections
import datetime
import json
import os
import time

from . import aql_search, findingstore, health_metrics, logsources, qradar

MAX_RESULTS = 200
MAX_TARGETS = 500
MAX_SOURCES_PER_TARGET = 10
STATES = ['connected', 'silent', 'never', 'disabled']


class ToolError(Exception):
    """Bad tool input; the message goes back to Claude so it can correct the call."""


def _now_ms():
    return int(time.time() * 1000)


def _local_time(ms):
    return datetime.datetime.fromtimestamp(ms / 1000).isoformat(timespec='seconds') if ms else None


def _compact(src, now_ms):
    info = logsources.describe(src, now_ms)
    last = src['last_event_time'] or 0
    return {
        'id': src['id'],
        'name': src['name'],
        'type': src['type'],
        'protocol': src['protocol'],
        'identifier': src['identifier'],
        'enabled': src['enabled'],
        'internal': src.get('internal', False),
        'state': info['state'],
        'last_event': _local_time(last),
        'minutes_since_last_event': int((now_ms - last) // 60000) if last > 0 else None,
        'average_eps': src['average_eps'],
        'collector': src['collector'],
        'qradar_status': src['health'],
        'status_messages': src['messages'],
    }


def _int(value, name, low, high, default):
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ToolError('{0} must be an integer from {1} to {2}.'.format(name, low, high))
    return value


def _text(value, name, max_length=200):
    if value is None:
        return ''
    if not isinstance(value, str) or len(value) > max_length:
        raise ToolError('{0} must be a string of at most {1} characters.'.format(name, max_length))
    return value.strip()


def _bool(value, name, default):
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ToolError('{0} must be true or false.'.format(name))
    return value


def search_log_sources(args):
    query = _text(args.get('query'), 'query')
    states = args.get('states')
    if states is not None and (not isinstance(states, list) or
                               any(s not in STATES for s in states)):
        raise ToolError('states must be a list drawn from {0}.'.format(STATES))
    type_text = _text(args.get('type_contains'), 'type_contains').lower()
    collector_text = _text(args.get('collector_contains'), 'collector_contains').lower()
    include_internal = _bool(args.get('include_internal'), 'include_internal', False)
    limit = _int(args.get('limit'), 'limit', 1, MAX_RESULTS, 50)

    now_ms = _now_ms()
    parsed = logsources.parse_question(query) if query else None
    if parsed and not (parsed['ips'] or parsed['hosts'] or parsed['terms']):
        parsed = None
    hits = []
    for src in qradar.log_sources():
        if src.get('internal') and not include_internal:
            continue
        if states and logsources.connection_state(src, now_ms) not in states:
            continue
        if type_text and type_text not in src['type'].lower():
            continue
        if collector_text and collector_text not in src['collector'].lower():
            continue
        rank = logsources.score(src, parsed) if parsed else 1
        if rank > 0:
            hits.append((rank, src))
    hits.sort(key=lambda item: (-item[0], item[1]['name'].lower()))
    return {'total_matches': len(hits), 'returned': min(limit, len(hits)),
            'log_sources': [_compact(src, now_ms) for _, src in hits[:limit]]}


def get_log_source(args):
    source_id = args.get('id')
    if not isinstance(source_id, int) or isinstance(source_id, bool):
        raise ToolError('id must be the integer id of a log source.')
    for src in qradar.log_sources():
        if src['id'] == source_id:
            detail = _compact(src, _now_ms())
            detail['description'] = src['description']
            detail['protocol_settings'] = src.get('parameters', [])
            return detail
    raise ToolError('No log source has id {0}.'.format(source_id))


def check_targets(args):
    targets = args.get('targets')
    if (not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS or
            any(not isinstance(t, str) or not t.strip() or len(t) > 253 for t in targets)):
        raise ToolError('targets must be a list of 1 to {0} IP addresses or hostnames.'
                        .format(MAX_TARGETS))
    now_ms = _now_ms()
    sources = qradar.log_sources()
    results = []
    counts = collections.Counter()
    for target in (t.strip() for t in targets):
        ip = target if logsources.is_ip(target) else None
        found = logsources.match_target(ip, None if ip else target, sources)
        compact = [dict(_compact(src, now_ms), matched_by=how) for src, how in found]
        status = logsources.target_status({c['state'] for c in compact})
        counts[status] += 1
        results.append({'target': target, 'status': status,
                        'matching_log_sources': compact[:MAX_SOURCES_PER_TARGET],
                        'more_matches': max(0, len(compact) - MAX_SOURCES_PER_TARGET)})
    return {'counts': dict(counts), 'results': results}


def log_source_overview(args):
    now_ms = _now_ms()
    external = [s for s in qradar.log_sources() if not s.get('internal')]
    states = collections.Counter()
    by_type = collections.defaultdict(collections.Counter)
    by_collector = collections.defaultdict(collections.Counter)
    problems = collections.defaultdict(list)
    for src in external:
        state = logsources.connection_state(src, now_ms)
        states[state] += 1
        by_type[src['type'] or 'Unknown'][state] += 1
        by_collector[src['collector'] or 'Unknown'][state] += 1
        if state != 'connected':
            problems[state].append(src)
        if src['health'] in ('ERROR', 'WARN'):
            problems['qradar_error_or_warning'].append(src)
    problems['silent'].sort(key=lambda s: s['last_event_time'] or 0)

    def top(counter_map, n=25):
        ranked = sorted(counter_map.items(), key=lambda item: -sum(item[1].values()))
        return [dict(name=name, total=sum(c.values()), **c) for name, c in ranked[:n]]

    return {
        'external_log_sources': len(external),
        'internal_log_sources_excluded': sum(1 for s in qradar.log_sources() if s.get('internal')),
        'receiving_threshold_minutes': logsources.STALE_MINUTES,
        'by_state': dict(states),
        'by_type': top(by_type),
        'by_collector': top(by_collector),
        'examples': {name: [_compact(s, now_ms) for s in items[:25]]
                     for name, items in problems.items()},
    }


def search_events(args, owner=None, should_stop=lambda: False):
    return aql_search.search(args, owner, should_stop)


TOOLS = [
    {
        'name': 'log_source_overview',
        'description': (
            'Health overview of all non-internal QRadar log sources: counts by state, by log '
            'source type and by event collector, plus up to 25 examples each of silent, never '
            'received, disabled, and QRadar ERROR/WARN status log sources (silent ones oldest '
            'first). Start here for broad questions such as "review my log source integration".'),
        'input_schema': {'type': 'object', 'properties': {}, 'additionalProperties': False},
        'handler': log_source_overview,
    },
    {
        'name': 'search_log_sources',
        'description': (
            'Find log sources by free text (IP, hostname, name, product or type words such as '
            '"office 365" or "windows"), by state, by type or by collector. Returns the total '
            'number of matches and up to `limit` of them with state, last event time, minutes '
            'since last event, average EPS (whole numbers; 0 can mean under 1 EPS), collector and '
            'QRadar status messages. States: connected (last event within the threshold), '
            'silent (older), never (no events ever), disabled.'),
        'input_schema': {
            'type': 'object',
            'properties': {
                'query': {'type': 'string', 'description': 'Free text; omit to list everything.'},
                'states': {'type': 'array', 'items': {'type': 'string', 'enum': STATES}},
                'type_contains': {'type': 'string',
                                  'description': 'Case-insensitive part of the type name.'},
                'collector_contains': {'type': 'string'},
                'include_internal': {'type': 'boolean',
                                     'description': "Include QRadar's own internal log "
                                                    'sources. Default false.'},
                'limit': {'type': 'integer', 'minimum': 1, 'maximum': MAX_RESULTS},
            },
            'additionalProperties': False,
        },
        'handler': search_log_sources,
    },
    {
        'name': 'get_log_source',
        'description': ('Full details of one log source by id, including its description and '
                        'non-secret protocol settings (credentials are never included).'),
        'input_schema': {
            'type': 'object',
            'properties': {'id': {'type': 'integer'}},
            'required': ['id'],
            'additionalProperties': False,
        },
        'handler': get_log_source,
    },
    {
        'name': 'check_targets',
        'description': (
            'Check whether each IP address or hostname has a log source receiving events. Each '
            'target is matched on its own: exact identifier or protocol setting first, then '
            'short hostname, then the IP or hostname appearing in the log source name; internal '
            'log sources are skipped. Status per target: connected, not_connected or '
            'not_found. Use for lists the user pastes.'),
        'input_schema': {
            'type': 'object',
            'properties': {'targets': {'type': 'array', 'items': {'type': 'string'},
                                       'minItems': 1, 'maxItems': MAX_TARGETS}},
            'required': ['targets'],
            'additionalProperties': False,
        },
        'handler': check_targets,
    },
]

TOOLS.append({
    'name': 'search_events',
    'description': (
        'Search QRadar events (Ariel). You do not write AQL: describe the search with filters, '
        'a time range and optionally group_by, and the app builds, validates and runs the AQL. '
        'Without group_by it returns up to 50 events, newest first by default, with the default '
        'Log Activity columns (Event Name, Log Source, Event Count, Time, Low Level Category, '
        'Source IP/Port, Destination IP/Port, Username, Magnitude) and the Payload. With '
        'group_by (1 to 3 of the filter fields) it counts instead: one row per distinct '
        'combination with Event Count, First Seen and Last Seen, largest first, up to 50 groups. '
        'Use group_by for "per user", "per source", "top N" and "how many" questions rather than '
        'running one search per value. Rules: filters may only use '
        'source_ip, destination_ip, log_source, log_source_type, username, event_name, '
        'qradar_event_id (QRadar\'s event ID, the device event key QRadar maps to a QID, e.g. '
        '"4625" or "Microsoft-Windows-Security-Auditing_4625") and qid. At least one filter must '
        'include something (equals, in, in_cidr or contains); filters are ANDed. Operators: IPs '
        'equals, not_equals, in, in_cidr; log_source, log_source_type, username and event_name '
        'equals (case-insensitive) or contains; qradar_event_id and qid equals or in. Names of '
        'log sources, log source types and events are resolved to IDs for you. The time range is '
        'required and limited to the configured maximum (days); prefer the shortest range that '
        'answers the question. Results are capped at 50 rows (or 50 groups); when a result has '
        '50 rows, say there may be more rather than presenting it as complete.'),
    'input_schema': {
        'type': 'object',
        'properties': {
            'filters': {
                'type': 'array', 'minItems': 1, 'maxItems': 10,
                'items': {
                    'type': 'object',
                    'properties': {
                        'field': {'type': 'string', 'enum': list(aql_search.ALLOWED_FILTER_FIELDS)},
                        'operator': {'type': 'string', 'enum': ['equals', 'not_equals', 'in',
                                                                'in_cidr', 'contains']},
                        'values': {'type': 'array', 'items': {'type': 'string'},
                                   'minItems': 1, 'maxItems': aql_search.MAX_VALUES_PER_FILTER},
                    },
                    'required': ['field', 'operator', 'values'],
                    'additionalProperties': False,
                },
            },
            'time_range': {
                'type': 'object',
                'description': ('Either {"last_minutes": n} or {"start": "YYYY-MM-DD HH:MM", '
                                '"end": "YYYY-MM-DD HH:MM"} in console time.'),
                'properties': {'last_minutes': {'type': 'integer', 'minimum': 1},
                               'start': {'type': 'string'}, 'end': {'type': 'string'}},
                'additionalProperties': False,
            },
            'group_by': {'type': 'array', 'maxItems': aql_search.MAX_GROUP_FIELDS,
                         'items': {'type': 'string', 'enum': list(aql_search.GROUP_FIELDS)}},
            'order': {'type': 'string', 'enum': ['newest_first', 'oldest_first'],
                      'description': 'Raw events only; groups are always largest first.'},
        },
        'required': ['filters', 'time_range'],
        'additionalProperties': False,
    },
    'handler': search_events,
    'needs_context': True,
})

def query_health_metrics(args, owner=None, should_stop=lambda: False):
    return health_metrics.query(args, owner, should_stop)


_TEXT_FILTER = {
    'type': 'object',
    'properties': {'operator': {'type': 'string', 'enum': list(health_metrics.TEXT_OPERATORS)},
                   'values': {'type': 'array', 'items': {'type': 'string'}, 'minItems': 1,
                              'maxItems': health_metrics.MAX_VALUES}},
    'required': ['operator', 'values'],
    'additionalProperties': False,
}

TOOLS.append({
    'name': 'query_health_metrics',
    'description': (
        'Query QRadar health metrics: the per-host measurements QRadar records every minute or '
        'so (QID 94000001, Health Metrics log sources). Use this, not search_events, for disk '
        'space, EPS, queues, CPU, memory and other system health questions. Each sample has a '
        'Metric ID, an Element (partition, device or component), a Hostname (managed host) and '
        'a Value. Common metrics: DiskUsage (fraction of a partition used, shown as %), '
        'DiskSpaceUsed and DiskSpaceTotal (bytes, shown as GiB; Element is the mount point such '
        'as /store or /), EventRate (EPS at ecs-ec-ingress), EventRateEC (EPS at ecs-ec), '
        'EventRateEPMon (EPS at the event processor), FlowRate, '
        'QueuedEventThrottleFilterDiskSize and IngressToEcDiskSize (events buffered to disk; '
        'above 0 means backlog or license throttling), ParserQueueSize. Host memory: '
        'SystemMemoryUsed (%), SystemPhysicalMemoryUsed and SystemPhysicalMemoryFree (GiB), '
        'SystemSwapMemoryUsed (GiB). CPU: UserCpu, SystemCPU, IdleCpu (%), NumCpu. '
        'HeapMemoryUsed and other per-process metrics average several QRadar processes '
        'together, so do not present them as host memory. Results include a Unit column and '
        'may include notes; follow them. If unsure of a name, use mode "list_metrics" first. '
        'Modes: latest (default; '
        'average over the last 15 minutes, 60 when DiskSpaceTotal is asked for: "what is it '
        'now"), summary (min/avg/max over a time range), trend (hourly averages over a time '
        'range), list_metrics (which metrics exist). A metrics filter is required except for '
        'list_metrics. Optional filters: elements, hosts, source_ips (the reporting host IP). '
        'Asking for DiskUsage, DiskSpaceUsed and DiskSpaceTotal together in latest mode returns '
        'one row per host and partition with used GiB, total GiB and used %. Container storage '
        '(/store/docker-data/..., overlay mounts) is included; set exclude_container_mounts '
        'only when the user asks to leave it out. Time range: at most the configured maximum '
        '(hours). Up to 500 rows; the app converts units, so use the values as shown.'),
    'input_schema': {
        'type': 'object',
        'properties': {
            'mode': {'type': 'string', 'enum': list(health_metrics.MODES)},
            'metrics': _TEXT_FILTER,
            'elements': _TEXT_FILTER,
            'hosts': _TEXT_FILTER,
            'source_ips': {
                'type': 'object',
                'properties': {'operator': {'type': 'string', 'enum': ['equals', 'in', 'in_cidr']},
                               'values': {'type': 'array', 'items': {'type': 'string'},
                                          'minItems': 1, 'maxItems': health_metrics.MAX_VALUES}},
                'required': ['operator', 'values'],
                'additionalProperties': False,
            },
            'group_by': {'type': 'array', 'items': {'type': 'string', 'enum': ['source_ip']},
                         'maxItems': 1},
            'exclude_container_mounts': {'type': 'boolean'},
            'time_range': {
                'type': 'object',
                'description': ('Either {"last_minutes": n} or {"start": "YYYY-MM-DD HH:MM", '
                                '"end": "YYYY-MM-DD HH:MM"} in console time. Required for '
                                'summary and trend.'),
                'properties': {'last_minutes': {'type': 'integer', 'minimum': 1},
                               'start': {'type': 'string'}, 'end': {'type': 'string'}},
                'additionalProperties': False,
            },
        },
        'additionalProperties': False,
    },
    'handler': query_health_metrics,
    'needs_context': True,
})

def list_findings(args):
    status = args.get('status', 'open')
    if status not in findingstore.STATUSES + ('any',):
        raise ToolError('status must be one of: {0}, any.'.format(', '.join(findingstore.STATUSES)))
    severity = args.get('severity')
    if severity is not None and severity not in findingstore.SEVERITY_ORDER:
        raise ToolError('severity must be critical, warning or info.')
    limit = _int(args.get('limit'), 'limit', 1, 50, 20)
    found = findingstore.search(category=args.get('category'), severity=severity,
                                status=None if status == 'any' else status, limit=limit)
    return {'count': len(found), 'findings': [{
        'id': f['id'], 'category': f['category'], 'severity': f['severity'],
        'status': f['status'], 'title': f['title'], 'occurrences': f['occurrences'],
        'first_seen': _local_time(f['first_seen']), 'last_seen': _local_time(f['last_seen']),
        'reasons': f['details'].get('reasons'), 'user': f['details'].get('user'),
        'source': f['details'].get('source'),
        'aql': (f['details'].get('aql') or '')[:1500] or None,
        'latest_statistics': f['details'].get('last'),
        'analysis': (f.get('analysis') or '')[:2000] or None,
    } for f in found]}


TOOLS.append({
    'name': 'list_findings',
    'description': (
        'List the scheduled findings shown in the Findings tab: problems AI Admin found on its '
        'own schedule, starting with expensive searches (long-running, heavy scans, filters '
        'that cannot use indexes). Each finding has a severity, a status (open, acknowledged, '
        'resolved, ignored), how often it happened, the user and source, the query and '
        'statistics, and Claude\'s earlier analysis if any. Defaults to open findings.'),
    'input_schema': {
        'type': 'object',
        'properties': {
            'status': {'type': 'string', 'enum': list(findingstore.STATUSES) + ['any']},
            'severity': {'type': 'string', 'enum': ['critical', 'warning', 'info']},
            'category': {'type': 'string', 'enum': ['expensive_searches']},
            'limit': {'type': 'integer', 'minimum': 1, 'maximum': 50},
        },
        'additionalProperties': False,
    },
    'handler': list_findings,
})

_BY_NAME = {tool['name']: tool for tool in TOOLS}

LABELS = {
    'log_source_overview': 'Reviewing log source health',
    'search_log_sources': 'Searching log sources',
    'get_log_source': 'Reading log source details',
    'check_targets': 'Checking targets',
    'search_events': 'Searching events',
    'query_health_metrics': 'Querying health metrics',
    'list_findings': 'Reading findings',
}


def definitions():
    """Tool definitions for the Messages API. Inputs stream as Claude writes them."""
    return [{'name': t['name'], 'description': t['description'],
             'input_schema': t['input_schema'], 'eager_input_streaming': True} for t in TOOLS]


def run(name, args, owner=None, should_stop=lambda: False):
    """(result_text, is_error). Never raises for bad input or QRadar failures. owner is the
    QRadar user the agent works for, recorded by tools that audit their use; should_stop()
    turns True when the user presses Stop, for tools that run long."""
    tool = _BY_NAME.get(name)
    if tool is None:
        return 'Unknown tool {0}.'.format(name), True
    if not isinstance(args, dict):
        return 'Tool input must be a JSON object.', True
    try:
        result = (tool['handler'](args, owner, should_stop) if tool.get('needs_context')
                  else tool['handler'](args))
        return json.dumps(result, default=str), False
    except (ToolError, aql_search.SearchError) as exc:
        return str(exc), True
    except qradar.QRadarError as exc:
        return 'QRadar error: {0}'.format(exc), True


def summarize_call(name, args):
    """A short human-readable line for the chat UI."""
    label = LABELS.get(name, name)
    if not isinstance(args, dict):
        return label
    if name == 'check_targets' and isinstance(args.get('targets'), list):
        return '{0} ({1})'.format(label, len(args['targets']))
    if name == 'query_health_metrics':
        parts = [str(args.get('mode', 'latest'))]
        for key in ('metrics', 'elements', 'hosts', 'source_ips'):
            spec = args.get(key)
            if isinstance(spec, dict):
                parts.append('{0} {1} {2}'.format(key, spec.get('operator'),
                                                  ', '.join(str(v) for v in spec.get('values') or [])))
        if args.get('exclude_container_mounts'):
            parts.append('without container mounts')
        return '{0} ({1})'.format(label, '; '.join(parts))
    if name == 'search_events' and isinstance(args.get('filters'), list):
        parts = ['{0} {1} {2}'.format(f.get('field'), f.get('operator'),
                                      ', '.join(str(v) for v in f.get('values') or []))
                 for f in args['filters'] if isinstance(f, dict)]
        if isinstance(args.get('group_by'), list) and args['group_by']:
            parts.append('grouped by ' + ', '.join(str(g) for g in args['group_by']))
        return '{0} ({1})'.format(label, '; '.join(parts))
    details = ', '.join('{0}: {1}'.format(k, v) for k, v in args.items()
                        if k in ('query', 'states', 'type_contains', 'collector_contains', 'id'))
    return '{0} ({1})'.format(label, details) if details else label


TIME_ZONE = os.environ.get('TZ', 'the console time zone')
