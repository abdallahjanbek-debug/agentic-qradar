"""Server-side access control: every page and API route of AI Admin is for QRadar admins only.

The manifest's required_capabilities only hides the tab and the Admin icon; QRadar's proxy still
forwards any logged-in user's requests, so each route checks the caller here.
"""

import functools
import hashlib
import os
import threading
import time

import requests
from flask import g, jsonify, render_template, request
from qpylib import qpylib

from . import qradar

NOT_ADMIN = 'AI Admin is available to QRadar administrators only.'
CACHE_SECONDS = 60

_lock = threading.Lock()
_verdicts = {}  # sha256(credential) -> (expires_at, is_admin, owner)


def _credential():
    # A browser sends its QRadar session as the SEC cookie; API clients send a token header.
    return request.cookies.get('SEC') or request.headers.get('SEC')


def _owner(sec, key):
    """The QRadar username behind this credential. Authorized-service tokens have no user, so
    they get a stable pseudonym instead."""
    if sec:
        try:
            resp = qpylib.REST('GET', 'api/config/access/users', version=qradar.api_version(),
                               params={'current_user': 'true', 'fields': 'username'},
                               headers={'SEC': sec})
            users = resp.json() if resp.status_code == 200 else []
            if users and users[0].get('username'):
                return users[0]['username']
        except (requests.RequestException, ValueError) as exc:
            qpylib.log('Current user lookup failed: {0!r}'.format(exc), level='WARNING')
    return 'token-' + key[:12]


def is_admin():
    """Whether the caller's own QRadar credential has the Admin capability. Also sets
    flask.g.qradar_user to the caller's username."""
    sdk = os.environ.get('QRADAR_APPFW_SDK', '').lower() == 'true'
    if os.environ.get('SEC_ADMIN_TOKEN') and not sdk:
        # qpylib would send SEC_ADMIN_TOKEN instead of the caller's credential, so the check
        # would pass for everyone. This happens only if the manifest gains `authentication`.
        qpylib.log('SEC_ADMIN_TOKEN is set; refusing all access', level='ERROR')
        return False
    sec = _credential()
    if not (sec or sdk):
        return False
    key = hashlib.sha256((sec or '').encode()).hexdigest()
    now = time.time()
    with _lock:
        cached = _verdicts.get(key)
    if cached and cached[0] > now:
        verdict, owner = cached[1], cached[2]
    else:
        verdict = qradar.session_is_admin(sec)
        owner = _owner(sec, key) if verdict else None
        with _lock:
            for stale in [k for k, entry in _verdicts.items() if entry[0] <= now]:
                del _verdicts[stale]
            _verdicts[key] = (now + CACHE_SECONDS, verdict, owner)
    g.qradar_user = owner
    return verdict


def admin_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not is_admin():
            if request.path.startswith('/api/'):
                return jsonify(error=NOT_ADMIN), 403
            return render_template('forbidden.html', message=NOT_ADMIN), 403
        return view(*args, **kwargs)
    return wrapper
