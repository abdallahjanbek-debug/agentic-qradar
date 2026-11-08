"""The scheduler service: runs the findings tasks on their schedule and analyses new findings.

Declared as a `services` entry in manifest.json, so it runs as its own process next to Flask
(python3 -m app.scheduler from /opt/app-root). It re-reads the settings every cycle, runs a
task when it is due or when an admin pressed Run now, and never lets one failed cycle stop it.
"""

import signal
import time

from qpylib import qpylib

from . import claude, expensive_searches, findings_analysis, findingstore, settings

CYCLE_SECONDS = 15
ANALYSES_PER_CYCLE = 5

# task name -> (enabled setting, run function)
TASKS = {
    expensive_searches.TASK: ('findings_expensive_searches', expensive_searches.run),
}

_running = True


def _stop(*_):
    global _running
    _running = False


def due(task, now_ms, interval_ms):
    """Whether a task should run now: Run now was pressed, or the interval has passed."""
    state = findingstore.task_state(task)
    if state['run_requested'] and (state['last_run'] or 0) < state['run_requested']:
        return True
    return state['last_run'] is None or now_ms - state['last_run'] >= interval_ms


def run_task(task, function):
    run_id = findingstore.start_run(task)
    try:
        new, updated, message = function()
        findingstore.finish_run(run_id, 'completed', message, new, updated)
        qpylib.log('Task {0}: {1} new, {2} updated. {3}'.format(task, new, updated, message),
                   level='INFO')
    except Exception as exc:  # a failed run is recorded and retried next interval
        findingstore.finish_run(run_id, 'failed', str(exc))
        qpylib.log('Task {0} failed: {1!r}'.format(task, exc), level='ERROR')
    finally:
        findingstore.set_task_state(task, last_run=findingstore.now_ms())


def analyse_pending():
    """Claude analysis for new, reopened or worsened findings, a few per cycle."""
    api_key = settings.get(settings.ANTHROPIC_KEY)
    if not api_key:
        return
    automatic = settings.get_config('findings_auto_analysis') == 'on'
    for finding in findingstore.pending_analysis(ANALYSES_PER_CYCLE, automatic):
        try:
            text, model = findings_analysis.analyse(finding, api_key)
            findingstore.save_analysis(finding['id'], text, model)
        except claude.ClaudeError as exc:
            qpylib.log('Analysis of {0} failed: {1}'.format(finding['id'], exc), level='WARNING')
            return  # retry next cycle; don't hammer the API


def cycle():
    now = findingstore.now_ms()
    interval_ms = settings.get_config('findings_interval_minutes') * 60000
    for task, (setting, function) in TASKS.items():
        if settings.get_config(setting) != 'on':
            continue
        if due(task, now, interval_ms):
            run_task(task, function)
    analyse_pending()


def main():
    qpylib.create_log(False)
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    qpylib.log('Scheduler started', level='INFO')
    while _running:
        try:
            cycle()
        except Exception as exc:  # never let one bad cycle kill the service
            qpylib.log('Scheduler cycle failed: {0!r}'.format(exc), level='ERROR')
        for _ in range(CYCLE_SECONDS):
            if not _running:
                break
            time.sleep(1)
    qpylib.log('Scheduler stopped', level='INFO')


if __name__ == '__main__':
    main()
