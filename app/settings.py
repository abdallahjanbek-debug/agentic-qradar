"""App-wide credentials, encrypted with qpylib encdec under a fixed user so every session and
any future background service can read them.

Only a non-secret summary (last 4 characters, update time) is stored in clear text, in
store/settings_meta.json, so the settings page can show what is configured.
"""

import json
import os
import threading
import time

from qpylib import qpylib
from qpylib.encdec import Encryption, EncryptionError

QRADAR_TOKEN = 'qradar_token'
ANTHROPIC_KEY = 'anthropic_api_key'
NAMES = (QRADAR_TOKEN, ANTHROPIC_KEY)

_SECRET_USER = 'app'
_lock = threading.Lock()


def _meta_path():
    return qpylib.get_store_path('settings_meta.json')


def _read_meta():
    try:
        with open(_meta_path()) as meta_file:
            return json.load(meta_file)
    except (OSError, ValueError):
        return {}


def _write_meta(meta):
    tmp = _meta_path() + '.tmp'
    with open(tmp, 'w') as meta_file:
        json.dump(meta, meta_file)
    os.replace(tmp, _meta_path())


def get(name):
    """The decrypted secret, or None when it isn't configured."""
    try:
        value = Encryption({'name': name, 'user': _SECRET_USER}).decrypt()
    except EncryptionError:
        return None
    return value or None


def put(name, value):
    with _lock:
        Encryption({'name': name, 'user': _SECRET_USER}).encrypt(value)
        meta = _read_meta()
        meta[name] = {'hint': value[-4:], 'updated': int(time.time() * 1000)}
        _write_meta(meta)
    qpylib.log('Setting {0} updated'.format(name), level='INFO')


def clear(name):
    # encdec has no delete, so an empty value stands for "not configured".
    with _lock:
        Encryption({'name': name, 'user': _SECRET_USER}).encrypt('')
        meta = _read_meta()
        meta.pop(name, None)
        _write_meta(meta)
    qpylib.log('Setting {0} removed'.format(name), level='INFO')


def summary():
    """What the settings page may show: never the secret itself."""
    meta = _read_meta()
    return {name: {'configured': get(name) is not None,
                   'hint': meta.get(name, {}).get('hint'),
                   'updated': meta.get(name, {}).get('updated')}
            for name in NAMES}
