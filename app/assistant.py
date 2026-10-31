"""The chat's entry point: sends each question to the feature that can answer it.

Log source connectivity is the first feature. New features, and Claude, plug in here.
"""

import time

from . import logsources, qradar

HELP = ('I can help you administer QRadar. To start with, I can check whether a log source is '
        'connected: name its IP address, hostname or product, for example "Is 10.1.2.3 '
        'connected?" or "Is Office 365 sending events?" To check a long list, upload an Excel '
        'file with IPs and/or hostnames.')


def answer(question):
    """{'feature': str or None, 'answer': str, ...feature-specific fields}.

    Raises qradar.QRadarError when QRadar can't be queried.
    """
    if logsources.can_answer(question):
        result = logsources.answer(question, qradar.log_sources(), int(time.time() * 1000))
        result['feature'] = 'log_source_status'
        return result
    return {'feature': None, 'answer': HELP}
