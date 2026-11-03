"""Feature: QRadar health metrics for the agent (disk, EPS, queues, CPU, memory...).

Every health metric is an event with QID 94000001 from the Health Metrics log sources, with the
properties "Metric ID", "Element" (partition, device or component), "Hostname" (managed host)
and "Value". As with event searches, the agent sends a structured request and this module builds
the AQL, so by construction:
- every query is limited to QID 94000001;
- filters use only metric, element, host and source IP; a metric filter is required except
  when listing the available metrics;
- results are aggregated per host, element and metric, at most MAX_ROWS rows, over a time
  range of at most the configured maximum (hours).
It then runs through the same safeguards as event searches (validator, concurrency cap, time
limit, Stop, audit). Units are converted here (bytes to GiB, fractions to %), so the model
never does that arithmetic.
"""

import re

from . import aql_search, settings
from .aql_search import SearchError

HEALTH_QID = 94000001
MAX_ROWS = 500
MAX_VALUES = 50
LATEST_MINUTES = 15
# DiskSpaceTotal is sampled less often than the other disk metrics.
LATEST_MINUTES_WITH_TOTALS = 60
MODES = ('latest', 'summary', 'trend', 'list_metrics')
TEXT_OPERATORS = ('equals', 'in', 'starts_with')
SAFE_VALUE = re.compile(r'^[A-Za-z0-9_./:@ -]{1,200}$')

PROPERTY = {'metrics': '"Metric ID"', 'elements': '"Element"', 'hosts': '"Hostname"'}
# Container storage QRadar reports alongside the real partitions; excluded only on request.
CONTAINER_MOUNT_PATTERNS = ('/store/docker-data/%', '/var/lib/containers/%',
                            '%overlay-containers%', '%/overlay/%/merged')

# Raw unit QRadar reports -> (factor to the shown unit, shown unit). Units were checked on a
# console: physical memory used + free (KB) equals the deployment API's total_memory (KB), and
# idle + user + system CPU add up to ~100 %. Metrics not listed are shown as reported, with
# the unit marked unknown.
KIB, MIB, GIB = 1024, 1024 ** 2, 1024 ** 3
UNITS = {
    'DiskSpaceUsed': (1 / GIB, 'GiB'), 'DiskSpaceTotal': (1 / GIB, 'GiB'),
    'DiskUsage': (100, '%'), 'DiskSpaceUsageMount': (100, '%'),
    'SystemPhysicalMemoryUsed': (KIB / GIB, 'GiB'), 'SystemPhysicalMemoryFree': (KIB / GIB, 'GiB'),
    'SystemCachedMemoryUsed': (KIB / GIB, 'GiB'), 'SystemSwapMemoryUsed': (KIB / GIB, 'GiB'),
    'SystemBufferedMemory': (KIB / MIB, 'MiB'),
    'SystemMemoryUsed': (1, '%'),
    'IdleCpu': (1, '%'), 'UserCpu': (1, '%'), 'SystemCPU': (1, '%'), 'NiceCpu': (1, '%'),
    'NumCpu': (1, 'CPUs'),
    'HeapMemoryUsed': (1 / MIB, 'MiB'), 'MemoryUsedDirect': (1 / MIB, 'MiB'),
    'MemoryUsedMapped': (1 / MIB, 'MiB'), 'SystemMemoryUsedProcess': (1 / MIB, 'MiB'),
    'EventRate': (1, 'EPS'), 'EventRateEC': (1, 'EPS'), 'EventRateEPMon': (1, 'EPS'),
    'FlowRate': (1, 'FPS'),
}
UNKNOWN_UNIT = 'unit unknown'
# Reported by several QRadar processes (ecs-ec, Tomcat, ...); the process name is only in the
# payload, so rows for one host and element average those processes together.
PER_PROCESS_METRICS = {'HeapMemoryUsed', 'MemoryUsedDirect', 'MemoryUsedMapped',
                       'SystemMemoryUsedProcess', 'ProcessCPU', 'ProcessCPUTime'}
DISK_METRICS = {'DiskUsage', 'DiskSpaceUsed', 'DiskSpaceTotal'}


def _text_condition(key, spec, required=False):
    """'"Metric ID" IN (...)'-style condition for one property, or None when not given."""
    if spec is None:
        if required:
            raise SearchError('metrics is required (use mode "list_metrics" to see which exist).')
        return None
    if not isinstance(spec, dict) or spec.get('operator') not in TEXT_OPERATORS:
        raise SearchError('{0} must be {{"operator": one of {1}, "values": [...]}}.'.format(
            key, ', '.join(TEXT_OPERATORS)))
    values = spec.get('values')
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_VALUES:
        raise SearchError('{0}: give 1 to {1} values.'.format(key, MAX_VALUES))
    for value in values:
        if not isinstance(value, str) or not SAFE_VALUE.match(value):
            raise SearchError('{0}: "{1}" is not allowed (letters, digits, spaces and _ . / : @ - '
                              'only).'.format(key, str(value)[:50]))
    column = PROPERTY[key]
    if spec['operator'] == 'starts_with':
        return '(' + ' OR '.join("{0} ILIKE '{1}%'".format(column, v) for v in values) + ')'
    if len(values) == 1:
        return "{0} = '{1}'".format(column, values[0])
    return '{0} IN ({1})'.format(column, ', '.join("'{0}'".format(v) for v in values))


def _source_ip_condition(spec):
    if spec is None:
        return None
    if not isinstance(spec, dict):
        raise SearchError('source_ips must be {"operator": ..., "values": [...]}.')
    if spec.get('operator') not in ('equals', 'in', 'in_cidr'):
        raise SearchError('source_ips supports equals, in and in_cidr.')
    # The event search filter already validates IPs and CIDR ranges and builds the AQL.
    return aql_search._condition({'field': 'source_ip', 'operator': spec['operator'],
                                  'values': spec.get('values')})


def _time_clause(request, mode, metrics_spec):
    time_range = request.get('time_range')
    max_hours = settings.get_config('health_max_window_hours')
    if time_range is None:
        if mode in ('summary', 'trend'):
            raise SearchError('time_range is required for {0}.'.format(mode))
        wanted = set((metrics_spec or {}).get('values') or [])
        minutes = LATEST_MINUTES_WITH_TOTALS if 'DiskSpaceTotal' in wanted else LATEST_MINUTES
        time_range = {'last_minutes': minutes}
    # Same parsing as event searches, with the health metrics maximum.
    return aql_search._time_clause_minutes(time_range, max_hours * 60,
                                           '{0} hours'.format(max_hours))


def build(request):
    """(aql, mode, columns) from the agent's structured request. Raises SearchError."""
    if not isinstance(request, dict):
        raise SearchError('The request must be an object.')
    mode = request.get('mode', 'latest')
    if mode not in MODES:
        raise SearchError('mode must be one of: {0}.'.format(', '.join(MODES)))
    group_by = request.get('group_by') or []
    if group_by not in ([], ['source_ip']):
        raise SearchError('group_by may only be ["source_ip"].')
    exclude = request.get('exclude_container_mounts', False)
    if not isinstance(exclude, bool):
        raise SearchError('exclude_container_mounts must be true or false.')

    conditions = ['qid = {0}'.format(HEALTH_QID)]
    for key in ('metrics', 'elements', 'hosts'):
        condition = _text_condition(key, request.get(key),
                                    required=(key == 'metrics' and mode != 'list_metrics'))
        if condition:
            conditions.append(condition)
    source_ip = _source_ip_condition(request.get('source_ips'))
    if source_ip:
        conditions.append(source_ip)
    if exclude:
        conditions.append('NOT (' + ' OR '.join(
            "\"Element\" ILIKE '{0}'".format(p) for p in CONTAINER_MOUNT_PATTERNS) + ')')
    where = ' AND '.join(conditions)
    time_clause, _ = _time_clause(request, mode, request.get('metrics'))

    if mode == 'list_metrics':
        select = [('"Metric ID"', 'Metric'), ('UNIQUECOUNT("Element")', 'Elements'),
                  ('UNIQUECOUNT("Hostname")', 'Hosts'), ('COUNT(*)', 'Samples')]
        keys, order = ['"Metric ID"'], '"Metric ID"'
    else:
        select = [('"Hostname"', 'Host'), ('"Element"', 'Element'), ('"Metric ID"', 'Metric')]
        keys = ['"Hostname"', '"Element"', '"Metric ID"']
        if group_by:
            select.insert(1, ('sourceip', 'Source IP'))
            keys.insert(1, 'sourceip')
        order = '"Hostname", "Metric ID", "Element"'
        if mode == 'latest':
            select += [('AVG("Value")', 'Value'), ('COUNT(*)', 'Samples'),
                       ("DATEFORMAT(MAX(starttime), 'yyyy-MM-dd HH:mm:ss')", 'Last Sample')]
        elif mode == 'summary':
            select += [('MIN("Value")', 'Min'), ('AVG("Value")', 'Avg'), ('MAX("Value")', 'Max'),
                       ('COUNT(*)', 'Samples'),
                       ("DATEFORMAT(MIN(starttime), 'yyyy-MM-dd HH:mm:ss')", 'First Sample'),
                       ("DATEFORMAT(MAX(starttime), 'yyyy-MM-dd HH:mm:ss')", 'Last Sample')]
        else:  # trend: hourly averages
            hour = "DATEFORMAT(starttime, 'yyyy-MM-dd HH:00')"
            select = [(hour, 'Hour')] + select + [('AVG("Value")', 'Value'),
                                                  ('COUNT(*)', 'Samples')]
            keys = [hour] + keys
            order = '"Hour", ' + order
    aql = 'SELECT {0} FROM events WHERE {1} GROUP BY {2} ORDER BY {3} LIMIT {4} {5}'.format(
        ', '.join('{0} AS "{1}"'.format(expr, name) for expr, name in select), where,
        ', '.join(keys), order, MAX_ROWS, time_clause)
    return aql, mode, [name for _, name in select]


# ---- Units and the disk view --------------------------------------------------------------

def _number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _convert(rows, columns):
    """Show values in readable units (see UNITS) and add a Unit column. Returns columns."""
    value_columns = [c for c in ('Value', 'Min', 'Avg', 'Max') if c in columns]
    for row in rows:
        metric = row.get('Metric')
        factor, unit = UNITS.get(metric, (1, UNKNOWN_UNIT))
        for column in value_columns:
            number = _number(row.get(column))
            if number is not None:
                row[column] = round(number * factor, 2 if unit in ('GiB', 'MiB') else 3)
        row['Unit'] = unit
        if isinstance(row.get('Samples'), float) and row['Samples'].is_integer():
            row['Samples'] = int(row['Samples'])
    return columns + ['Unit'] if value_columns else columns


def _notes(rows):
    """Caveats Claude needs to read the values correctly."""
    metrics = {row.get('Metric') for row in rows}
    notes = []
    mixed = sorted(metrics & PER_PROCESS_METRICS)
    if mixed:
        notes.append('{0}: reported by several QRadar processes and averaged together per host; '
                     'not one process. For host memory use SystemPhysicalMemoryUsed/Free (GiB) '
                     'or SystemMemoryUsed (%).'.format(', '.join(mixed)))
    unknown = sorted(m for m in metrics if m and m not in UNITS)
    if unknown:
        notes.append('Unit not verified, values shown as reported: {0}.'.format(
            ', '.join(unknown[:30])))
    return notes


def _disk_view(rows):
    """One row per host and partition with used, total and percentage, from the raw metric
    rows (values still in bytes and fractions). Total comes from DiskSpaceTotal when sampled,
    else from used / usage."""
    partitions = {}
    for row in rows:
        key = (row.get('Host'), row.get('Element'))
        partitions.setdefault(key, {})[row.get('Metric')] = row
    out = []
    for (host, element), metrics in sorted(partitions.items(), key=lambda i: (str(i[0][0]),
                                                                              str(i[0][1]))):
        used = _number((metrics.get('DiskSpaceUsed') or {}).get('Value'))
        total = _number((metrics.get('DiskSpaceTotal') or {}).get('Value'))
        fraction = _number((metrics.get('DiskUsage') or {}).get('Value'))
        if total is None and used is not None and fraction:
            total = used / fraction
        if fraction is None and used is not None and total:
            fraction = used / total
        last = max((m.get('Last Sample') or '' for m in metrics.values()), default='')
        out.append({'Host': host, 'Partition': element,
                    'Used (GiB)': round(used / GIB, 2) if used is not None else None,
                    'Total (GiB)': round(total / GIB, 2) if total else None,
                    'Used %': round(fraction * 100, 1) if fraction is not None else None,
                    'Last Sample': last or None})
    return out, ['Host', 'Partition', 'Used (GiB)', 'Total (GiB)', 'Used %', 'Last Sample']


def query(request, owner, should_stop=lambda: False):
    """Build, validate and run one health metrics query. Returns a dict for Claude and the UI."""
    def build_aql():
        aql, mode, columns = build(request)
        return aql, (mode, columns)

    rows, (aql, (mode, columns)) = aql_search.run_guarded(build_aql, request, owner, should_stop,
                                                          limit=MAX_ROWS)
    metrics = set((request.get('metrics') or {}).get('values') or [])
    if mode == 'latest' and metrics and metrics <= DISK_METRICS and rows:
        rows, columns = _disk_view(rows)
        view = 'disk'
    else:
        notes = _notes(rows) if mode != 'list_metrics' else []
        columns = _convert(rows, columns)
        view = mode
        if notes:
            return {'aql': aql, 'mode': mode, 'view': view, 'row_count': len(rows),
                    'limited_to': MAX_ROWS, 'grouped': True, 'columns': columns, 'rows': rows,
                    'notes': notes}
    return {'aql': aql, 'mode': mode, 'view': view, 'row_count': len(rows),
            'limited_to': MAX_ROWS, 'grouped': True, 'columns': columns, 'rows': rows}
