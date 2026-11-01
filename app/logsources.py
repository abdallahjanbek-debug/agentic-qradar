"""Log source connectivity logic: matching log sources to IPs, hostnames and keywords, and
deciding whether each one is receiving events. Used by the agent's tools and the bulk check.

Pure logic with no QRadar or Flask imports, so it can be tested on its own.
"""

import os
import re

STALE_MINUTES = int(os.environ.get('LOGSOURCE_STALE_MINUTES', '60'))

IPV4 = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
HOSTNAME = re.compile(r'\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\b',
                      re.IGNORECASE)
WORD = re.compile(r'[a-z0-9][a-z0-9_-]*', re.IGNORECASE)

STOPWORDS = {
    'a', 'about', 'alive', 'all', 'an', 'and', 'any', 'are', 'can', 'check', 'connected',
    'connection', 'data', 'did', 'do', 'does', 'down', 'event', 'events', 'for', 'from', 'getting',
    'has', 'have', 'how', 'i', 'if', 'in', 'is', 'it', 'its', 'log', 'logging', 'logs', 'me', 'my',
    'no', 'not', 'now', 'of', 'offline', 'on', 'online', 'or', 'our', 'please', 'qradar',
    'receiving', 'reporting', 'see', 'send', 'sending', 'show', 'source', 'sources', 'status',
    'still', 'tell', 'that', 'the', 'there', 'this', 'to', 'up', 'us', 'we', 'what', 'whether',
    'which', 'with', 'working', 'you',
}

# Short names people type for common SaaS sources -> phrases that appear in QRadar type names.
ALIASES = {
    'o365': ['office 365', 'microsoft 365'],
    'm365': ['microsoft 365', 'office 365'],
    'aad': ['azure active directory', 'entra'],
    'entra': ['entra', 'azure active directory'],
    'aws': ['aws', 'amazon'],
    'gcp': ['google cloud', 'gcp'],
    'gws': ['google workspace', 'g suite'],
    'sfdc': ['salesforce'],
}

STATE_LABELS = {
    'connected': 'Receiving events',
    'silent': 'Not receiving events',
    'never': 'Never received events',
    'disabled': 'Disabled',
}


def parse_question(question):
    """Split a question into IP addresses, hostnames and remaining keyword terms."""
    text = question.strip()
    ips = list(dict.fromkeys(IPV4.findall(text)))
    rest = IPV4.sub(' ', text)
    hosts = list(dict.fromkeys(h.lower() for h in HOSTNAME.findall(rest)))
    rest = HOSTNAME.sub(' ', rest)
    terms = [w.lower() for w in WORD.findall(rest) if w.lower() not in STOPWORDS]
    return {'ips': ips, 'hosts': hosts, 'terms': list(dict.fromkeys(terms))}


def _haystack(src):
    parts = [src['name'], src['description'], src['type'], src['protocol'], src['identifier']]
    return ' '.join(parts + src['search_values']).lower()


def _values(src):
    return {v.lower() for v in [src['identifier']] + src['search_values'] if v}


def _term_matches(term, haystack):
    phrases = ALIASES.get(term, [term])
    return any(re.search(r'\b' + re.escape(p), haystack) for p in phrases)


def score(src, parsed):
    """0 = no match; higher = better. Every IP, host and term in the question must match."""
    haystack = _haystack(src)
    values = _values(src)
    score = 0
    for ip in parsed['ips']:
        if ip in values:
            score += 100
        elif re.search(r'(?<![\d.])' + re.escape(ip) + r'(?![\d.])', haystack):
            score += 60
        else:
            return 0
    for host in parsed['hosts']:
        short = host.split('.')[0]
        if host in values:
            score += 100
        elif host in haystack:
            score += 60
        elif any(v.split('.')[0] == short for v in values):
            score += 40
        else:
            return 0
    for term in parsed['terms']:
        if not _term_matches(term, haystack):
            return 0
        score += 10
    return score


def is_ip(value):
    return bool(IPV4.fullmatch(value))


def _token_in(needle, text):
    return re.search(r'(?<![\w.-])' + re.escape(needle) + r'(?![\w-])', text) is not None


def match_target(ip, hostname, sources):
    """Log sources for one IP and/or hostname, as [(source, matched_by)], best match first.

    Stricter than question matching: an exact identifier or protocol setting first, then the
    short hostname, then the IP or hostname appearing in the log source name. QRadar's internal
    sources are skipped.
    """
    ip = (ip or '').strip()
    host = (hostname or '').strip().lower()
    short = host.split('.')[0] if host and not is_ip(host) else ''
    found = []
    for src in sources:
        if src.get('internal'):
            continue
        identifier = (src['identifier'] or '').lower()
        values = _values(src)
        name = src['name'].lower()
        if ip and ip in values:
            how = (0, 'IP = identifier' if ip == identifier else 'IP = protocol setting')
        elif host and host in values:
            how = (0, 'Hostname = identifier' if host == identifier else
                   'Hostname = protocol setting')
        elif short and any(not is_ip(v) and v.split('.')[0] == short for v in values):
            how = (1, 'Short hostname = identifier')
        elif ip and re.search(r'(?<![\d.])' + re.escape(ip) + r'(?![\d.])', name):
            how = (2, 'IP in log source name')
        elif host and _token_in(host, name):
            how = (2, 'Hostname in log source name')
        elif short and short != host and _token_in(short, name):
            how = (3, 'Short hostname in log source name')
        else:
            continue
        found.append((how, src))
    found.sort(key=lambda item: (item[0][0], item[1]['name'].lower()))
    return [(src, how[1]) for how, src in found]


def target_status(states):
    """One target's overall status from its log sources' states."""
    if not states:
        return 'not_found'
    return 'connected' if 'connected' in states else 'not_connected'


def connection_state(src, now_ms, stale_minutes=STALE_MINUTES):
    """'connected', 'silent', 'never' or 'disabled', based on enabled and last_event_time."""
    if not src['enabled']:
        return 'disabled'
    last = src['last_event_time'] or 0
    if last <= 0:
        return 'never'
    return 'connected' if now_ms - last <= stale_minutes * 60000 else 'silent'


def humanize_age(ms):
    minutes = int(ms // 60000)
    if minutes < 1:
        return 'less than a minute'
    if minutes < 60:
        return '{0} min'.format(minutes)
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return '{0} h {1} min'.format(hours, minutes) if minutes else '{0} h'.format(hours)
    return '{0} days'.format(hours // 24)


def describe(src, now_ms):
    state = connection_state(src, now_ms)
    last = src['last_event_time'] or 0
    age = humanize_age(now_ms - last) if last > 0 else None
    return {
        'id': src['id'],
        'name': src['name'],
        'type': src['type'],
        'identifier': src['identifier'],
        'collector': src['collector'],
        'state': state,
        'state_label': STATE_LABELS[state],
        'last_event_time': last or None,
        'last_event_age': age,
        'average_eps': src['average_eps'],
        'health': src['health'],
        'messages': src['messages'],
    }
