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

from . import claude

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


# Non-secret configuration, stored as JSON in the app's store. Each setting is either a whole
# number in a range or one of a fixed set of choices.
CONFIG = {
    'aql_max_window_days': {'default': 7, 'min': 1, 'max': 30,
                            'label': 'Maximum time range of an event search, in days'},
    'health_max_window_hours': {'default': 24, 'min': 1, 'max': 168,
                                'label': 'Maximum time range of a health metrics query, in hours'},
    'claude_model': {'default': claude.DEFAULT_MODEL, 'choices': list(claude.MODELS),
                     'label': 'Claude model'},
}


def _config_path():
    return qpylib.get_store_path('config.json')


def _read_config():
    try:
        with open(_config_path()) as config_file:
            return json.load(config_file)
    except (OSError, ValueError):
        return {}


def _valid(spec, value):
    if 'choices' in spec:
        return value in spec['choices']
    return (isinstance(value, int) and not isinstance(value, bool) and
            spec['min'] <= value <= spec['max'])


def get_config(name):
    spec = CONFIG[name]
    value = _read_config().get(name, spec['default'])
    return value if _valid(spec, value) else spec['default']


def set_config(name, value):
    """Raises ValueError for an unknown name or an invalid value."""
    if name not in CONFIG:
        raise ValueError('Unknown setting.')
    spec = CONFIG[name]
    if not _valid(spec, value):
        if 'choices' in spec:
            raise ValueError('{0} must be one of: {1}.'.format(spec['label'],
                                                              ', '.join(spec['choices'])))
        raise ValueError('{0} must be a whole number from {1} to {2}.'.format(
            spec['label'], spec['min'], spec['max']))
    with _lock:
        config = _read_config()
        config[name] = value
        tmp = _config_path() + '.tmp'
        with open(tmp, 'w') as config_file:
            json.dump(config, config_file)
        os.replace(tmp, _config_path())
    qpylib.log('Config {0} set to {1}'.format(name, value), level='INFO')


def config_summary():
    return {name: dict(spec, value=get_config(name)) for name, spec in CONFIG.items()}
