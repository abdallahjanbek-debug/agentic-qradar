"""QRadar REST access for the app: API version discovery, paged reads, token and admin
checks, and a cached log source inventory.

Calls run as the QRadar token an admin saved on the settings page, not as the user who opened
the page. The manifest must have no `authentication` block: with one, qpylib replaces every SEC
header with the injected SEC_ADMIN_TOKEN.
"""

import os
import threading
import time

import requests
from qpylib import qpylib

from . import settings

LOG_SOURCES = 'api/config/event_sources/log_source_management/log_sources'
LOG_SOURCE_TYPES = 'api/config/event_sources/log_source_management/log_source_types'
PROTOCOL_TYPES = 'api/config/event_sources/log_source_management/protocol_types'
EVENT_COLLECTORS = 'api/config/event_sources/event_collectors'
AUTHORIZED_SERVICES = 'api/config/access/authorized_services'

LOG_SOURCE_FIELDS = ('id,name,description,type_id,protocol_type_id,protocol_parameters,enabled,'
                     'internal,status,last_event_time,average_eps,target_event_collector_id')

# Used only when /api/help/versions can't be read. Override with QRADAR_API_VERSION.
FALLBACK_API_VERSION = '16.0'
CACHE_SECONDS = int(os.environ.get('LOGSOURCE_CACHE_SECONDS', '60'))
PAGE_SIZE = 500

# Protocol parameters whose names contain any of these are never searched or returned.
SECRET_PARAM_WORDS = ('pass', 'secret', 'token', 'key', 'credential', 'cert', 'private')

NO_TOKEN = ('No QRadar API token is configured. An admin can add one in '
            'Admin > AI Admin Settings.')


class QRadarError(Exception):
    """A QRadar API call failed; the message is safe to show to the user."""


_lock = threading.Lock()
_api_version = None
_version_retry_at = 0.0
_cache = {'at': 0.0, 'sources': None}


def reset():
    """Forget the API version and inventory, e.g. after the token changes."""
    global _api_version, _version_retry_at
    with _lock:
        _api_version = None
        _version_retry_at = 0.0
        _cache['sources'] = None


def _token():
    token = settings.get(settings.QRADAR_TOKEN)
    if not token:
        raise QRadarError(NO_TOKEN)
    return token


def api_version():
    """The console's highest non-deprecated API version, discovered once per process."""
    global _api_version, _version_retry_at
    if _api_version:
        return _api_version
    override = os.environ.get('QRADAR_API_VERSION')
    if override:
        _api_version = override
        return _api_version
    if time.time() < _version_retry_at:
        return FALLBACK_API_VERSION
    token = settings.get(settings.QRADAR_TOKEN)
    try:
        # Without a saved token, qpylib sends the current user's session instead.
        resp = qpylib.REST('GET', 'api/help/versions', version=FALLBACK_API_VERSION,
                           headers={'SEC': token} if token else None)
        if resp.status_code == 200:
            usable = [v['version'] for v in resp.json()
                      if not v.get('deprecated') and not v.get('removed')]
            if usable:
                _api_version = max(usable, key=lambda v: tuple(int(p) for p in v.split('.')))
    except (requests.RequestException, ValueError, KeyError) as exc:
        qpylib.log('API version discovery failed: {0}'.format(exc), level='WARNING')
    if not _api_version:
        # Not cached: retry in a minute, e.g. once a working token is saved.
        _version_retry_at = time.time() + 60
        return FALLBACK_API_VERSION
    qpylib.log('Using QRadar API version {0}'.format(_api_version), level='INFO')
    return _api_version


def _get_page(path, fields, token, start, end):
    try:
        resp = qpylib.REST('GET', path, version=api_version(), params={'fields': fields},
                           headers={'SEC': token, 'Range': 'items={0}-{1}'.format(start, end)})
    except requests.RequestException as exc:
        qpylib.log('GET {0} failed: {1}'.format(path, exc), level='ERROR')
        raise QRadarError('Could not reach the QRadar API.') from exc
    if resp.status_code == 401:
        raise QRadarError('QRadar rejected the API token (HTTP 401). An admin can replace it in '
                          'Admin > AI Admin Settings.')
    if resp.status_code == 403:
        raise QRadarError("The API token's user isn't allowed to do this "
                          '(it needs the Admin capability).')
    if resp.status_code not in (200, 206):
        qpylib.log('GET {0} returned {1}: {2}'.format(path, resp.status_code, resp.text[:500]),
                   level='ERROR')
        raise QRadarError('QRadar returned HTTP {0} for {1}.'.format(resp.status_code, path))
    return resp


def _get_all(path, fields):
    """GET every item of a list endpoint, PAGE_SIZE items per request."""
    token = _token()
    items, start = [], 0
    while True:
        batch = _get_page(path, fields, token, start, start + PAGE_SIZE - 1).json()
        items.extend(batch)
        if len(batch) < PAGE_SIZE:
            return items
        start += PAGE_SIZE


def check_token(token):
    """Raise QRadarError unless this token works; return the log source count.

    Reading log sources needs the Admin capability, so this also proves the token's role.
    """
    resp = _get_page(LOG_SOURCES, 'id', token, 0, 0)
    total = resp.headers.get('Content-Range', '').rpartition('/')[2]
    return int(total) if total.isdigit() else len(resp.json())


def session_is_admin(sec_session):
    """Whether the QRadar session with this SEC cookie belongs to an Admin user.

    Listing authorized services is Admin-only, so a 200 proves the capability.
    """
    try:
        resp = qpylib.REST('GET', AUTHORIZED_SERVICES, version=api_version(),
                           params={'fields': 'id'},
                           headers={'SEC': sec_session, 'Range': 'items=0-0'})
    except requests.RequestException as exc:
        qpylib.log('Admin check failed: {0}'.format(exc), level='ERROR')
        return False
    return resp.status_code in (200, 206)


def _names(path):
    """id -> name for a small lookup endpoint; empty if the endpoint is unavailable."""
    try:
        return {item['id']: item['name'] for item in _get_all(path, 'id,name')}
    except QRadarError as exc:
        qpylib.log('Lookup {0} unavailable: {1}'.format(path, exc), level='WARNING')
        return {}


def _is_secret(param_name):
    name = (param_name or '').lower()
    return any(word in name for word in SECRET_PARAM_WORDS)


def _normalize(raw, types, protocols, collectors):
    params = [p for p in raw.get('protocol_parameters') or [] if not _is_secret(p.get('name'))]
    identifier = next((p.get('value') for p in params if p.get('name') == 'identifier'), None)
    status = raw.get('status') or {}
    messages = []
    for msg in status.get('messages') or []:
        text = msg.get('text') if isinstance(msg, dict) else msg
        if text:
            messages.append(str(text))
    return {
        'id': raw.get('id'),
        'name': raw.get('name') or '',
        'description': raw.get('description') or '',
        'type': types.get(raw.get('type_id'), ''),
        'protocol': protocols.get(raw.get('protocol_type_id'), ''),
        'identifier': identifier or '',
        'search_values': [str(p['value']) for p in params if p.get('value') not in (None, '')],
        'enabled': bool(raw.get('enabled')),
        'internal': bool(raw.get('internal')),
        'last_event_time': raw.get('last_event_time') or 0,
        'average_eps': raw.get('average_eps'),
        'collector': collectors.get(raw.get('target_event_collector_id'), ''),
        'health': status.get('status') or '',
        'messages': messages,
    }


def log_sources():
    """All log sources, normalized and cached for CACHE_SECONDS across all sessions."""
    with _lock:
        if _cache['sources'] is not None and time.time() - _cache['at'] < CACHE_SECONDS:
            return _cache['sources']
        _token()  # fail with a clear message before the optional lookups
        types = _names(LOG_SOURCE_TYPES)
        protocols = _names(PROTOCOL_TYPES)
        collectors = _names(EVENT_COLLECTORS)
        raw = _get_all(LOG_SOURCES, LOG_SOURCE_FIELDS)
        _cache['sources'] = [_normalize(r, types, protocols, collectors) for r in raw]
        _cache['at'] = time.time()
        qpylib.log('Loaded {0} log sources'.format(len(raw)), level='DEBUG')
        return _cache['sources']
