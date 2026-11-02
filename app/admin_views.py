"""Admin > AI Admin Settings: save, test and remove the QRadar token and the Anthropic API key."""

from flask import Blueprint, jsonify, render_template, request

from . import claude, qradar, settings
from .auth import admin_required

# pylint: disable=invalid-name
adminbp = Blueprint('adminbp', __name__, url_prefix='/')

LABELS = {settings.QRADAR_TOKEN: 'QRadar API token', settings.ANTHROPIC_KEY: 'Anthropic API key'}


def _check(name, value):
    """(verified, message). Raises ValueError when the value must not be saved.

    verified is False when the check couldn't run, e.g. no route to api.anthropic.com.
    """
    if name == settings.QRADAR_TOKEN:
        try:
            count = qradar.check_token(value)
        except qradar.QRadarError as exc:
            raise ValueError(str(exc)) from exc
        return True, 'The token works: it can read QRadar configuration ({0} log sources).'.format(
            count)
    try:
        model = claude.check_key(value, settings.get_config('claude_model'))
    except claude.ClaudeError as exc:
        if exc.rejected:
            raise ValueError(str(exc)) from exc
        return False, str(exc)
    return True, 'The key works with {0}.'.format(model)


@adminbp.route('/settings')
@admin_required
def settings_page():
    return render_template('settings.html')


@adminbp.route('/api/settings')
@admin_required
def get_settings():
    return jsonify(settings=settings.summary(), config=settings.config_summary())


@adminbp.route('/api/settings/<name>', methods=['PUT'])
@admin_required
def save_setting(name):
    if name not in settings.NAMES:
        return jsonify(error='Unknown setting.'), 404
    value = str((request.get_json(silent=True) or {}).get('value', '')).strip()
    if not 8 <= len(value) <= 512 or any(c.isspace() for c in value):
        return jsonify(error='Paste the whole {0}, with no spaces.'.format(LABELS[name])), 400
    try:
        verified, message = _check(name, value)
    except ValueError as exc:
        return jsonify(error='Not saved. {0}'.format(exc)), 400
    settings.put(name, value)
    if name == settings.QRADAR_TOKEN:
        qradar.reset()
    if not verified:
        message += ' The key was saved anyway, but is untested.'
    return jsonify(message=message, verified=verified, settings=settings.summary())


@adminbp.route('/api/settings/<name>/test', methods=['POST'])
@admin_required
def test_setting(name):
    if name not in settings.NAMES:
        return jsonify(error='Unknown setting.'), 404
    value = settings.get(name)
    if not value:
        return jsonify(error='No {0} is saved.'.format(LABELS[name])), 400
    try:
        verified, message = _check(name, value)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(message=message, verified=verified)


@adminbp.route('/api/settings/<name>', methods=['DELETE'])
@admin_required
def delete_setting(name):
    if name not in settings.NAMES:
        return jsonify(error='Unknown setting.'), 404
    settings.clear(name)
    if name == settings.QRADAR_TOKEN:
        qradar.reset()
    return jsonify(message='{0} removed.'.format(LABELS[name]), settings=settings.summary())


@adminbp.route('/api/models')
@admin_required
def list_models():
    """The model catalog, marking which models the saved Anthropic key can use."""
    api_key = settings.get(settings.ANTHROPIC_KEY)
    available, note = None, None
    if api_key:
        try:
            available = set(claude.available_models(api_key))
        except claude.ClaudeError as exc:
            note = 'Could not check which models the key can use: {0}'.format(exc)
    else:
        note = 'Save an Anthropic API key to see which models it can use.'
    models = [{'id': model_id, 'name': info['name'],
               'available': None if available is None else model_id in available}
              for model_id, info in claude.MODELS.items()]
    return jsonify(models=models, current=settings.get_config('claude_model'), note=note)


@adminbp.route('/api/config/<name>', methods=['PUT'])
@admin_required
def save_config(name):
    value = (request.get_json(silent=True) or {}).get('value')
    message = 'Saved.'
    if name == 'claude_model' and value in claude.MODELS:
        api_key = settings.get(settings.ANTHROPIC_KEY)
        if api_key:
            try:
                message = 'Saved. New chats now start with {0}.'.format(
                    claude.check_key(api_key, value))
            except claude.ClaudeError as exc:
                if exc.rejected:
                    return jsonify(error='Not saved. {0}'.format(exc)), 400
                message = 'Saved, but untested: {0}'.format(exc)
    try:
        settings.set_config(name, value)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(message=message, config=settings.config_summary())
