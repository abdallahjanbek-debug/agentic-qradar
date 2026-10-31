"""Anthropic API access. For now this only checks that a saved key works."""

from qpylib import qpylib

MODEL = 'claude-opus-5-5'


class ClaudeError(Exception):
    """An Anthropic API call failed; the message is safe to show to the user.

    rejected is True when Anthropic refused the key itself, False when the check couldn't run.
    """

    def __init__(self, message, rejected=False):
        super().__init__(message)
        self.rejected = rejected


def _client(api_key):
    # Imported here so the SDK only loads when it's needed. The SDK honours the container's
    # https_proxy / no_proxy variables, which QRadar sets from its auto-update proxy.
    import anthropic
    return anthropic, anthropic.Anthropic(api_key=api_key, timeout=20.0, max_retries=1)


def check_key(api_key):
    """Raise ClaudeError unless the key can use MODEL; return the model's display name.

    Retrieving a model is free, so this costs no tokens.
    """
    anthropic, client = _client(api_key)
    try:
        return client.models.retrieve(MODEL).display_name
    except anthropic.AuthenticationError as exc:
        raise ClaudeError('Anthropic rejected this API key.', rejected=True) from exc
    except anthropic.PermissionDeniedError as exc:
        raise ClaudeError("This API key isn't allowed to use {0}.".format(MODEL),
                          rejected=True) from exc
    except anthropic.NotFoundError as exc:
        raise ClaudeError('{0} is not available to this API key.'.format(MODEL),
                          rejected=True) from exc
    except anthropic.RateLimitError as exc:
        raise ClaudeError('Anthropic rate-limited the check; try again in a minute.') from exc
    except anthropic.APIStatusError as exc:
        qpylib.log('Anthropic check returned {0}: {1}'.format(exc.status_code, exc.message),
                   level='ERROR')
        raise ClaudeError('Anthropic returned HTTP {0}.'.format(exc.status_code)) from exc
    except anthropic.APIConnectionError as exc:
        qpylib.log('Anthropic check could not connect: {0}'.format(exc), level='ERROR')
        raise ClaudeError('Could not reach api.anthropic.com from the app. Check that the '
                          'console has internet access or a proxy configured.') from exc
