"""Saved agent conversations, one owner (QRadar username) per conversation.

Messages are stored exactly as sent to and received from the Claude API and are only ever
appended: Claude's thinking blocks stay valid only while the earlier history is unchanged. A
message's `kind` ('error' or 'notice') is for the UI only and is never sent to Claude.

Bulk check uploads are stored next to the messages (with their result workbook) so the chat
shows them, and offers the download, after a reload. They are deleted with the conversation.
SQLite lives in the app's persistent store, so chats survive restarts and upgrades.
"""

import contextlib
import json
import os
import sqlite3
import time
import uuid

from qpylib import qpylib

RETENTION_DAYS = int(os.environ.get('CHAT_RETENTION_DAYS', '90'))
TITLE_LENGTH = 80

_SCHEMA = '''
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    title TEXT NOT NULL,
    created INTEGER NOT NULL,
    updated INTEGER NOT NULL,
    pending_context TEXT
);
CREATE INDEX IF NOT EXISTS conversations_owner ON conversations (owner, updated);
CREATE TABLE IF NOT EXISTS messages (
    conversation_id TEXT NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    usage TEXT,
    created INTEGER NOT NULL,
    kind TEXT,
    PRIMARY KEY (conversation_id, seq)
);
CREATE TABLE IF NOT EXISTS uploads (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    after_messages INTEGER NOT NULL,
    created INTEGER NOT NULL,
    filename TEXT NOT NULL,
    result_filename TEXT NOT NULL,
    summary TEXT NOT NULL,
    counts TEXT NOT NULL,
    workbook BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS uploads_conversation ON uploads (conversation_id, after_messages);
'''

_initialized = False


def _now():
    return int(time.time() * 1000)


def _connect():
    global _initialized
    path = qpylib.get_store_path('db', 'chats.db')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    if not _initialized:
        conn.execute('PRAGMA journal_mode = WAL')
        conn.executescript(_SCHEMA)
        # Databases created by 0.4.0 lack messages.kind.
        if 'kind' not in {r['name'] for r in conn.execute('PRAGMA table_info(messages)')}:
            conn.execute('ALTER TABLE messages ADD COLUMN kind TEXT')
        _initialized = True
    return conn


@contextlib.contextmanager
def _db():
    """A connection that commits on success, rolls back on error, and is always closed."""
    conn = _connect()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def create(owner, title='New chat'):
    conversation_id = uuid.uuid4().hex
    now = _now()
    with _db() as conn:
        conn.execute('INSERT INTO conversations (id, owner, title, created, updated) '
                     'VALUES (?, ?, ?, ?, ?)', (conversation_id, owner, title, now, now))
    return get(conversation_id, owner)


def get(conversation_id, owner):
    """The conversation if it exists and belongs to owner, else None."""
    with _db() as conn:
        row = conn.execute('SELECT * FROM conversations WHERE id = ? AND owner = ?',
                           (conversation_id, owner)).fetchone()
    return dict(row) if row else None


def list_for(owner):
    prune()
    with _db() as conn:
        rows = conn.execute('SELECT id, title, created, updated, pending_context IS NOT NULL '
                            'AS has_attachment FROM conversations WHERE owner = ? '
                            'ORDER BY updated DESC', (owner,)).fetchall()
    return [dict(r) for r in rows]


def delete(conversation_id, owner):
    with _db() as conn:
        cur = conn.execute('DELETE FROM conversations WHERE id = ? AND owner = ?',
                           (conversation_id, owner))
    return cur.rowcount > 0


def messages(conversation_id):
    """[{'role', 'content', 'usage', 'kind'}] in order, content as API-ready lists/strings."""
    with _db() as conn:
        rows = conn.execute('SELECT role, content, usage, kind FROM messages '
                            'WHERE conversation_id = ? ORDER BY seq',
                            (conversation_id,)).fetchall()
    return [{'role': r['role'], 'content': json.loads(r['content']),
             'usage': json.loads(r['usage']) if r['usage'] else None, 'kind': r['kind']}
            for r in rows]


def append(conversation_id, role, content, usage=None, kind=None):
    now = _now()
    with _db() as conn:
        seq = conn.execute('SELECT COALESCE(MAX(seq), -1) + 1 FROM messages '
                           'WHERE conversation_id = ?', (conversation_id,)).fetchone()[0]
        conn.execute('INSERT INTO messages (conversation_id, seq, role, content, usage, created, '
                     'kind) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (conversation_id, seq, role, json.dumps(content),
                      json.dumps(usage) if usage else None, now, kind))
        conn.execute('UPDATE conversations SET updated = ? WHERE id = ?', (now, conversation_id))


def add_upload(conversation_id, filename, result_filename, summary, counts, workbook):
    """Record a bulk check at the current end of the chat. Returns the upload id."""
    upload_id = uuid.uuid4().hex
    now = _now()
    with _db() as conn:
        after = conn.execute('SELECT COUNT(*) FROM messages WHERE conversation_id = ?',
                             (conversation_id,)).fetchone()[0]
        conn.execute('INSERT INTO uploads (id, conversation_id, after_messages, created, filename, '
                     'result_filename, summary, counts, workbook) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                     (upload_id, conversation_id, after, now, filename, result_filename, summary,
                      json.dumps(counts), workbook))
        conn.execute('UPDATE conversations SET updated = ? WHERE id = ?', (now, conversation_id))
    return upload_id


def uploads(conversation_id):
    """Uploads in order, without the workbook bytes."""
    with _db() as conn:
        rows = conn.execute('SELECT id, after_messages, created, filename, result_filename, '
                            'summary, counts FROM uploads WHERE conversation_id = ? '
                            'ORDER BY after_messages, created', (conversation_id,)).fetchall()
    return [dict(r, counts=json.loads(r['counts'])) for r in rows]


def upload_file(conversation_id, upload_id):
    """(result_filename, workbook bytes), or None."""
    with _db() as conn:
        row = conn.execute('SELECT result_filename, workbook FROM uploads '
                           'WHERE id = ? AND conversation_id = ?',
                           (upload_id, conversation_id)).fetchone()
    return (row['result_filename'], row['workbook']) if row else None


def set_title(conversation_id, title):
    with _db() as conn:
        conn.execute('UPDATE conversations SET title = ? WHERE id = ?',
                     (title.strip()[:TITLE_LENGTH] or 'New chat', conversation_id))


def set_pending_context(conversation_id, context):
    """Text attached to the next user message (e.g. a bulk check summary); None clears it."""
    with _db() as conn:
        conn.execute('UPDATE conversations SET pending_context = ?, updated = ? WHERE id = ?',
                     (json.dumps(context) if context else None, _now(), conversation_id))


def take_pending_context(conversation_id):
    with _db() as conn:
        row = conn.execute('SELECT pending_context FROM conversations WHERE id = ?',
                           (conversation_id,)).fetchone()
        conn.execute('UPDATE conversations SET pending_context = NULL WHERE id = ?',
                     (conversation_id,))
    return json.loads(row['pending_context']) if row and row['pending_context'] else None


def prune():
    """Delete conversations untouched for RETENTION_DAYS."""
    cutoff = _now() - RETENTION_DAYS * 86400000
    with _db() as conn:
        conn.execute('DELETE FROM conversations WHERE updated < ?', (cutoff,))
