"""Anthropic API access: the model catalog, the shared client and the saved-key check."""

from qpylib import qpylib

DEFAULT_MODEL = 'claude-opus-5-5'

# The models an admin can choose in AI Admin Settings. Only current models whose request
# parameters the agent supports (adaptive thinking, effort) are listed. `fallback` marks models
# that accept server-side refusal fallback (fallbacks="default"); prices are USD per million
# input / output tokens.
MODELS = {
    'claude-opus-5-5': {'name': 'Claude Opus 5.5', 'price': (4, 20), 'fallback': True,
                        'note': 'Default. Best balance of capability and cost.'},
    'claude-fable-5-1': {'name': 'Claude Fable 5.1', 'price': (10, 50), 'fallback': True,
                         'note': 'Most capable; slowest and most expensive.'},
    'claude-sonnet-5-5': {'name': 'Claude Sonnet 5.5', 'price': (2, 10), 'fallback': True,
                          'note': 'Faster and cheaper; good for everyday questions.'},
    'claude-haiku-5-5': {'name': 'Claude Haiku 5.5', 'price': (0.10, 0.50), 'fallback': False,
                         'note': 'Fastest and cheapest; simple lookups.'},
    'claude-opus-5': {'name': 'Claude Opus 5', 'price': (5, 25), 'fallback': True,
                      'note': 'Previous Opus.'},
    'claude-sonnet-5': {'name': 'Claude Sonnet 5', 'price': (2, 10), 'fallback': False,
                        'note': 'Previous Sonnet.'},
}


class ClaudeError(Exception):
    """An Anthropic API call failed; the message is safe to show to the user.

    rejected is True when Anthropic refused the key itself, False when the check couldn't run.
    """

    def __init__(self, message, rejected=False):
        super().__init__(message)
        self.rejected = rejected


def client(api_key, timeout=20.0, max_retries=1):
    """(anthropic module, client). The SDK honours the container's https_proxy / no_proxy
    variables, which QRadar sets from its auto-update proxy settings."""
    # Imported here so the SDK only loads when it's needed.
    import anthropic
    return anthropic, anthropic.Anthropic(api_key=api_key, timeout=timeout,
                                          max_retries=max_retries)


def check_key(api_key, model=DEFAULT_MODEL):
    """Raise ClaudeError unless the key can use model; return the model's display name.

    Retrieving a model is free, so this costs no tokens.
    """
    anthropic, api = client(api_key)
    try:
        return api.models.retrieve(model).display_name
    except anthropic.AuthenticationError as exc:
        raise ClaudeError('Anthropic rejected this API key.', rejected=True) from exc
    except anthropic.PermissionDeniedError as exc:
        raise ClaudeError("This API key isn't allowed to use {0}.".format(model),
                          rejected=True) from exc
    except anthropic.NotFoundError as exc:
        raise ClaudeError('{0} is not available to this API key.'.format(model),
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


def available_models(api_key):
    """Catalog models this key can use, via the free models list. Raises ClaudeError."""
    anthropic, api = client(api_key)
    try:
        ids = {m.id for m in api.models.list(limit=1000)}
    except anthropic.AuthenticationError as exc:
        raise ClaudeError('Anthropic rejected the saved API key.', rejected=True) from exc
    except anthropic.APIStatusError as exc:
        raise ClaudeError('Anthropic returned HTTP {0}.'.format(exc.status_code)) from exc
    except anthropic.APIConnectionError as exc:
        raise ClaudeError('Could not reach api.anthropic.com from the app.') from exc
    return [model for model in MODELS if model in ids]
