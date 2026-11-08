"""Scheduled findings: the findings themselves, scheduler state and task runs.

Shared by the Flask process (Findings tab, actions) and the scheduler service, through one
SQLite file in WAL mode under the app's persistent store. Findings are shared by all admins.
"""

import contextlib
import json
import os
import sqlite3
import time
import uuid

from qpylib import qpylib

STATUSES = ('open', 'acknowledged', 'resolved', 'ignored')
SEVERITY_ORDER = {'critical': 0, 'warning': 1, 'info': 2}
KEEP_HOURS = 48  # how long search starts are kept waiting for their completion

_SCHEMA = '''
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    occurrences INTEGER NOT NULL,
    details TEXT NOT NULL,
    analysis TEXT,
    analysis_model TEXT,
    analysis_at INTEGER,
    needs_analysis INTEGER NOT NULL DEFAULT 0,
    updated INTEGER NOT NULL,
    UNIQUE (category, fingerprint)
);
CREATE INDEX IF NOT EXISTS findings_list ON findings (status, severity, last_seen);
CREATE TABLE IF NOT EXISTS task_state (
    task TEXT PRIMARY KEY,
    watermark INTEGER,
    last_run INTEGER,
    run_requested INTEGER
);
CREATE TABLE IF NOT EXISTS task_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task TEXT NOT NULL,
    started INTEGER NOT NULL,
    finished INTEGER,
    status TEXT NOT NULL,
    message TEXT,
    new_findings INTEGER NOT NULL DEFAULT 0,
    updated_findings INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS search_starts (
    search_id TEXT PRIMARY KEY,
    started INTEGER NOT NULL,
    details TEXT NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0,
    flagged_running INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS search_done (
    search_id TEXT PRIMARY KEY,
    seen INTEGER NOT NULL
);
'''

_initialized = False


def now_ms():
    return int(time.time() * 1000)


def _connect():
    global _initialized
    path = qpylib.get_store_path('db', 'findings.db')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    if not _initialized:
        conn.execute('PRAGMA journal_mode = WAL')
        conn.executescript(_SCHEMA)
        _initialized = True
    return conn


@contextlib.contextmanager
def _db():
    conn = _connect()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


# ---- Findings ------------------------------------------------------------------------------

def _row(row):
    item = dict(row)
    item['details'] = json.loads(item['details'])
    return item


def upsert(category, fingerprint, severity, title, details, seen_ms):
    """Create a finding or record another occurrence of it. Returns 'new', 'updated' or
    'reopened'. A resolved finding that happens again is reopened; an ignored one stays
    ignored; severity only ever rises."""
    with _db() as conn:
        row = conn.execute('SELECT * FROM findings WHERE category = ? AND fingerprint = ?',
                           (category, fingerprint)).fetchone()
        if row is None:
            conn.execute(
                'INSERT INTO findings (id, category, fingerprint, severity, title, status, '
                'first_seen, last_seen, occurrences, details, needs_analysis, updated) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 1, ?)',
                (uuid.uuid4().hex, category, fingerprint, severity, title, 'open', seen_ms,
                 seen_ms, json.dumps(details), now_ms()))
            return 'new'
        worse = SEVERITY_ORDER.get(severity, 9) < SEVERITY_ORDER.get(row['severity'], 9)
        status, outcome = row['status'], 'updated'
        if status == 'resolved':
            status, outcome = 'open', 'reopened'
        conn.execute(
            'UPDATE findings SET severity = ?, title = ?, status = ?, last_seen = MAX(last_seen, ?),'
            ' occurrences = occurrences + 1, details = ?, updated = ?, '
            'needs_analysis = CASE WHEN ? THEN 1 ELSE needs_analysis END WHERE id = ?',
            (severity if worse else row['severity'], title if worse else row['title'], status,
             seen_ms, json.dumps(details), now_ms(), 1 if (worse or outcome == 'reopened') else 0,
             row['id']))
        return outcome


def get(finding_id):
    with _db() as conn:
        row = conn.execute('SELECT * FROM findings WHERE id = ?', (finding_id,)).fetchone()
    return _row(row) if row else None


def by_fingerprint(category, fingerprint):
    with _db() as conn:
        row = conn.execute('SELECT * FROM findings WHERE category = ? AND fingerprint = ?',
                           (category, fingerprint)).fetchone()
    return _row(row) if row else None


def search(category=None, severity=None, status=None, limit=200):
    clauses, args = [], []
    for column, value in (('category', category), ('severity', severity), ('status', status)):
        if value:
            clauses.append('{0} = ?'.format(column))
            args.append(value)
    where = ('WHERE ' + ' AND '.join(clauses)) if clauses else ''
    with _db() as conn:
        rows = conn.execute(
            'SELECT * FROM findings {0} ORDER BY CASE severity WHEN \'critical\' THEN 0 '
            'WHEN \'warning\' THEN 1 ELSE 2 END, last_seen DESC LIMIT ?'.format(where),
            args + [limit]).fetchall()
    return [_row(r) for r in rows]


def set_status(finding_id, status):
    if status not in STATUSES:
        raise ValueError('status must be one of: {0}.'.format(', '.join(STATUSES)))
    with _db() as conn:
        cur = conn.execute('UPDATE findings SET status = ?, updated = ? WHERE id = ?',
                           (status, now_ms(), finding_id))
    return cur.rowcount > 0


# needs_analysis: 0 none, 1 automatic (new, reopened or worse), 2 requested by an admin.
AUTOMATIC, REQUESTED = 1, 2


def request_analysis(finding_id):
    with _db() as conn:
        cur = conn.execute('UPDATE findings SET needs_analysis = ? WHERE id = ?',
                           (REQUESTED, finding_id))
    return cur.rowcount > 0


def pending_analysis(limit, include_automatic):
    """Findings waiting for analysis: requested ones always, automatic ones if enabled."""
    wanted = (REQUESTED, AUTOMATIC) if include_automatic else (REQUESTED,)
    with _db() as conn:
        rows = conn.execute(
            'SELECT * FROM findings WHERE needs_analysis IN ({0}) AND status != ? '
            'ORDER BY needs_analysis DESC, updated LIMIT ?'.format(','.join('?' * len(wanted))),
            list(wanted) + ['ignored', limit]).fetchall()
    return [_row(r) for r in rows]


def save_analysis(finding_id, text, model):
    with _db() as conn:
        conn.execute('UPDATE findings SET analysis = ?, analysis_model = ?, analysis_at = ?, '
                     'needs_analysis = 0 WHERE id = ?', (text, model, now_ms(), finding_id))


# ---- Scheduler state -------------------------------------------------------------------------

def task_state(task):
    with _db() as conn:
        row = conn.execute('SELECT * FROM task_state WHERE task = ?', (task,)).fetchone()
    return dict(row) if row else {'task': task, 'watermark': None, 'last_run': None,
                                  'run_requested': None}


def set_task_state(task, **fields):
    state = task_state(task)
    state.update(fields)
    with _db() as conn:
        conn.execute('INSERT OR REPLACE INTO task_state (task, watermark, last_run, run_requested) '
                     'VALUES (?, ?, ?, ?)', (task, state['watermark'], state['last_run'],
                                             state['run_requested']))


def request_run(task):
    set_task_state(task, run_requested=now_ms())


def start_run(task):
    with _db() as conn:
        cur = conn.execute('INSERT INTO task_runs (task, started, status) VALUES (?, ?, ?)',
                           (task, now_ms(), 'running'))
    return cur.lastrowid


def finish_run(run_id, status, message='', new=0, updated=0):
    with _db() as conn:
        conn.execute('UPDATE task_runs SET finished = ?, status = ?, message = ?, new_findings = ?, '
                     'updated_findings = ? WHERE id = ?',
                     (now_ms(), status, message[:500], new, updated, run_id))
        conn.execute('DELETE FROM task_runs WHERE started < ?', (now_ms() - 30 * 86400000,))


def last_runs(task, limit=5):
    with _db() as conn:
        rows = conn.execute('SELECT * FROM task_runs WHERE task = ? ORDER BY id DESC LIMIT ?',
                            (task, limit)).fetchall()
    return [dict(r) for r in rows]


# ---- Search starts waiting for their completion -------------------------------------------

def remember_start(search_id, started_ms, details):
    """Store a search start. If its completion was already processed (audit events with the
    same timestamp can arrive in either order), store it as completed."""
    with _db() as conn:
        done = conn.execute('SELECT 1 FROM search_done WHERE search_id = ?',
                            (search_id,)).fetchone() is not None
        conn.execute('INSERT OR IGNORE INTO search_starts (search_id, started, details, completed) '
                     'VALUES (?, ?, ?, ?)', (search_id, started_ms, json.dumps(details), int(done)))


def start_of(search_id):
    with _db() as conn:
        row = conn.execute('SELECT * FROM search_starts WHERE search_id = ?',
                           (search_id,)).fetchone()
    return dict(row, details=json.loads(row['details'])) if row else None


def mark_done(search_id):
    """True the first time a completion is processed; False when it was already handled."""
    with _db() as conn:
        cur = conn.execute('INSERT OR IGNORE INTO search_done (search_id, seen) VALUES (?, ?)',
                           (search_id, now_ms()))
        conn.execute('UPDATE search_starts SET completed = 1 WHERE search_id = ?', (search_id,))
    return cur.rowcount > 0


def still_running(started_before_ms):
    """Starts with no completion yet, started before the given time, not flagged yet."""
    with _db() as conn:
        rows = conn.execute('SELECT * FROM search_starts WHERE completed = 0 AND '
                            'flagged_running = 0 AND started < ?', (started_before_ms,)).fetchall()
    return [dict(r, details=json.loads(r['details'])) for r in rows]


def mark_completed(search_id):
    with _db() as conn:
        conn.execute('UPDATE search_starts SET completed = 1 WHERE search_id = ?', (search_id,))


def mark_flagged_running(search_id):
    with _db() as conn:
        conn.execute('UPDATE search_starts SET flagged_running = 1 WHERE search_id = ?',
                     (search_id,))


def prune():
    cutoff = now_ms() - KEEP_HOURS * 3600000
    with _db() as conn:
        conn.execute('DELETE FROM search_starts WHERE started < ?', (cutoff,))
        conn.execute('DELETE FROM search_done WHERE seen < ?', (cutoff,))
