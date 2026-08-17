"""Encrypted storage for the Anthropic API key.

Module is named `appsecrets` rather than `secrets` to avoid shadowing the stdlib
module of that name.
"""

from qpylib import qpylib
from qpylib.encdec import Encryption

from . import config


def _cipher() -> Encryption:
    # `user` is a fixed synthetic value, not the logged-in admin. encdec keys the
    # stored file by this property; using the real admin username would mean a
    # different admin could not decrypt the key, and the background services --
    # which have no logged-in user -- could never decrypt it at all.
    return Encryption({"name": config.SECRET_NAME, "user": config.SECRET_USER})


def set_api_key(value: str) -> None:
    _cipher().encrypt(value)


def get_api_key():
    """Return the decrypted key, or None if never configured."""
    try:
        return _cipher().decrypt()
    except Exception as error:  # not configured yet, or store unreadable
        qpylib.log("socai: api key unavailable: {}".format(error), level="DEBUG")
        return None


def is_configured() -> bool:
    return bool(get_api_key())


def masked() -> str:
    key = get_api_key()
    if not key:
        return ""
    return "•" * 8 + key[-4:]
