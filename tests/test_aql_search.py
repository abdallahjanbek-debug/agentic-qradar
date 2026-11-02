"""Event search guardrails: AQL building, validation and running, with a fake QRadar API."""

import os
import shutil
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))
try:
    from app import aql_search, chatstore, qradar, settings
    from qpylib import qpylib
except ImportError as exc:  # run in a venv with the app's wheels, Flask and qpylib
    raise unittest.SkipTest('needs Flask and qpylib: {0}'.format(exc))
from test_logsources import SOURCES  # noqa: E402

TYPES = {12: 'Microsoft Windows Security Event Log', 18: 'Custom Rule Engine', 41: 'Cisco ASA'}


class FakeQRadar:
    """Records calls; answers the endpoints aql_search uses."""

    def __init__(self, validator_errors=(), statuses=('COMPLETED',), rows=()):
        self.calls = []
        self.validator_errors = list(validator_errors)
        self.statuses = list(statuses)
        self.rows = list(rows)

    def __call__(self, method, path, params=None, headers=None, token=None, ok=(200, 206)):
        self.calls.append((method, path, params))
        if path == 'api/data_classification/qid_records':
            body = [{'qid': 39750013}] if 'Logon' in params['filter'] else []
        elif path == 'api/ariel/validators/aql':
            body = {'error_messages': [{'message': m} for m in self.validator_errors]}
        elif path == 'api/ariel/searches' and method == 'POST':
            body = {'search_id': 'sid-1'}
        elif path == 'api/ariel/searches/sid-1' and method == 'GET':
            status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
            body = {'status': status, 'error_messages': []}
        elif path.endswith('/results'):
            body = {'events': self.rows}
        else:
            body = {}
        return types.SimpleNamespace(json=lambda: body, status_code=200)


class AqlTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ['APP_ROOT'] = self.tmp.name
        os.makedirs(os.path.join(self.tmp.name, 'store', 'log'), exist_ok=True)
        shutil.copy(os.path.join(os.path.dirname(__file__), '..', 'manifest.json'), self.tmp.name)
        qpylib.create_log(False)
        chatstore._initialized = False
        self.fake = FakeQRadar()
        self.saved = [(qradar, n, getattr(qradar, n)) for n in ('log_sources', 'log_source_types',
                                                                'call')]
        qradar.log_sources = lambda: SOURCES
        qradar.log_source_types = lambda: TYPES
        qradar.call = self.fake

    def tearDown(self):
        for obj, name, value in self.saved:
            setattr(obj, name, value)
        self.tmp.cleanup()

    def where(self, *filters, time_range=None):
        aql, _ = aql_search.build({'filters': list(filters),
                                   'time_range': time_range or {'last_minutes': 60}})
        return aql.split(' WHERE ', 1)[1].split(' ORDER BY ', 1)[0]


class Build(AqlTestCase):
    def test_shape(self):
        aql, minutes = aql_search.build({
            'filters': [{'field': 'source_ip', 'operator': 'equals', 'values': ['10.0.0.1']}],
            'time_range': {'last_minutes': 90}})
        self.assertTrue(aql.startswith('SELECT QIDNAME(qid) AS "Event Name", '))
        self.assertIn('UTF8(payload) AS "Payload" FROM events', aql)
        self.assertTrue(aql.endswith("WHERE sourceip = '10.0.0.1' ORDER BY starttime DESC "
                                     'LIMIT 50 LAST 90 MINUTES'))
        self.assertEqual(minutes, 90)

    def test_each_field(self):
        self.assertEqual(self.where({'field': 'destination_ip', 'operator': 'in_cidr',
                                     'values': ['10.1.0.0/16', '192.168.8.0/24']}),
                         "(INCIDR('10.1.0.0/16', destinationip) OR "
                         "INCIDR('192.168.8.0/24', destinationip))")
        self.assertEqual(self.where({'field': 'source_ip', 'operator': 'equals',
                                     'values': ['10.0.0.1', '10.0.0.2']}),
                         "sourceip IN ('10.0.0.1', '10.0.0.2')")
        fw = next(s['id'] for s in SOURCES if s['name'] == 'fw01.corp.local')
        self.assertEqual(self.where({'field': 'log_source', 'operator': 'equals',
                                     'values': ['FW01.corp.local']}), 'logsourceid = {0}'.format(fw))
        self.assertEqual(self.where({'field': 'log_source_type', 'operator': 'contains',
                                     'values': ['windows']}), 'devicetype = 12')
        self.assertEqual(self.where({'field': 'username', 'operator': 'contains',
                                     'values': ['adm', 'svc']}),
                         "(username ILIKE '%adm%' OR username ILIKE '%svc%')")
        self.assertEqual(self.where({'field': 'event_name', 'operator': 'contains',
                                     'values': ['Logon']}), 'qid = 39750013')
        self.assertEqual(self.where({'field': 'qradar_event_id', 'operator': 'in',
                                     'values': ['4624', '4625']}),
                         "qideventid IN ('4624', '4625')")
        self.assertEqual(self.where({'field': 'qid', 'operator': 'equals', 'values': ['5000012']},
                                    {'field': 'username', 'operator': 'not_equals',
                                     'values': ['system']}),
                         "qid = 5000012 AND (username NOT ILIKE 'system')")

    def test_start_stop_window(self):
        aql, minutes = aql_search.build({
            'filters': [{'field': 'qid', 'operator': 'equals', 'values': ['1']}],
            'time_range': {'start': '2026-11-01 08:00', 'end': '2026-11-02 08:00'}})
        self.assertRegex(aql, r'START \d{13} STOP \d{13}$')
        self.assertEqual(minutes, 1440)

    def test_rejections(self):
        ip = {'field': 'source_ip', 'operator': 'equals', 'values': ['10.0.0.1']}
        bad = [
            ({'filters': [], 'time_range': {'last_minutes': 5}}, 'At least one filter'),
            ({'filters': [{'field': 'payload', 'operator': 'contains', 'values': ['x']}],
              'time_range': {'last_minutes': 5}}, 'not allowed'),
            ({'filters': [{'field': 'source_ip', 'operator': 'contains', 'values': ['10']}],
              'time_range': {'last_minutes': 5}}, 'supports these operators'),
            ({'filters': [{'field': 'username', 'operator': 'not_equals', 'values': ['a']}],
              'time_range': {'last_minutes': 5}}, 'must include something'),
            ({'filters': [{'field': 'username', 'operator': 'equals',
                           'values': ["x' OR '1'='1"]}],
              'time_range': {'last_minutes': 5}}, 'not allowed'),
            ({'filters': [{'field': 'source_ip', 'operator': 'equals', 'values': ['10.0.0.300']}],
              'time_range': {'last_minutes': 5}}, 'not a valid IP'),
            ({'filters': [ip]}, 'time_range is required'),
            ({'filters': [ip], 'time_range': {'last_minutes': 8 * 1440}}, 'configured maximum'),
            ({'filters': [ip], 'time_range': {'start': '2026-10-01 00:00',
                                              'end': '2026-10-20 00:00'}}, 'maximum is 7 days'),
            ({'filters': [{'field': 'log_source', 'operator': 'equals', 'values': ['nothing']}],
              'time_range': {'last_minutes': 5}}, 'nothing matches'),
            ({'filters': [{'field': 'event_name', 'operator': 'equals', 'values': ['Nope']}],
              'time_range': {'last_minutes': 5}}, 'no QRadar event is named'),
        ]
        for request, message in bad:
            with self.assertRaises(aql_search.SearchError, msg=request) as caught:
                aql_search.build(request)
            self.assertIn(message, str(caught.exception))

    def test_max_window_follows_settings(self):
        settings.set_config('aql_max_window_days', 1)
        with self.assertRaises(aql_search.SearchError):
            aql_search.build({'filters': [{'field': 'qid', 'operator': 'equals', 'values': ['1']}],
                              'time_range': {'last_minutes': 1441}})


class Config(AqlTestCase):
    def test_model_choice(self):
        self.assertEqual(settings.get_config('claude_model'), 'claude-opus-5-5')
        settings.set_config('claude_model', 'claude-sonnet-5-5')
        self.assertEqual(settings.get_config('claude_model'), 'claude-sonnet-5-5')
        for bad in ('gpt-4', 'claude-opus-4-8', 7):
            with self.assertRaises(ValueError):
                settings.set_config('claude_model', bad)
        self.assertEqual(settings.config_summary()['claude_model']['value'], 'claude-sonnet-5-5')


class Run(AqlTestCase):
    REQUEST = {'filters': [{'field': 'username', 'operator': 'equals', 'values': ['bob']}],
               'time_range': {'last_minutes': 30}}

    def audit(self):
        with chatstore._db() as conn:
            return [dict(r) for r in conn.execute('SELECT owner, status, row_count FROM search_audit')]

    def test_completed_search(self):
        self.fake.rows = [{'Event Name': 'Logon', 'Payload': 'x' * 5000}]
        result = aql_search.search(self.REQUEST, 'admin')
        self.assertEqual(result['row_count'], 1)
        self.assertTrue(result['rows'][0]['Payload'].endswith('…[truncated]'))
        paths = [(m, p) for m, p, _ in self.fake.calls]
        self.assertEqual(paths[0], ('POST', 'api/ariel/validators/aql'))
        self.assertIn(('DELETE', 'api/ariel/searches/sid-1'), paths)
        self.assertEqual(self.audit(), [{'owner': 'admin', 'status': 'completed', 'row_count': 1}])

    def test_validator_rejection_never_runs(self):
        self.fake.validator_errors = ['Field "x" does not exist']
        with self.assertRaises(aql_search.SearchError):
            aql_search.search(self.REQUEST, 'admin')
        self.assertNotIn(('POST', 'api/ariel/searches'),
                         [(m, p) for m, p, _ in self.fake.calls])
        self.assertEqual(self.audit()[0]['status'], 'rejected')

    def test_stop_cancels_a_running_search(self):
        self.fake.statuses = ['EXECUTE']
        with self.assertRaises(aql_search.SearchError) as caught:
            aql_search.search(self.REQUEST, 'admin', should_stop=lambda: True)
        self.assertIn('Stopped by the user', str(caught.exception))
        self.assertIn(('POST', 'api/ariel/searches/sid-1', {'status': 'CANCELED'}),
                      self.fake.calls)
        self.assertIn(('DELETE', 'api/ariel/searches/sid-1', None), self.fake.calls)

    def test_limits(self):
        self.assertEqual(aql_search.SEARCH_TIMEOUT_SECONDS, 600)
        self.assertEqual(aql_search.MAX_CONCURRENT_SEARCHES, 5)

    def test_timeout_cancels(self):
        self.fake.statuses = ['EXECUTE']
        original_timeout, original_sleep = aql_search.SEARCH_TIMEOUT_SECONDS, aql_search.time.sleep
        aql_search.SEARCH_TIMEOUT_SECONDS = 0
        aql_search.time.sleep = lambda s: None
        try:
            with self.assertRaises(aql_search.SearchError) as caught:
                aql_search.search(self.REQUEST, 'admin')
        finally:
            aql_search.SEARCH_TIMEOUT_SECONDS = original_timeout
            aql_search.time.sleep = original_sleep
        self.assertIn('cancelled', str(caught.exception))
        self.assertIn(('POST', 'api/ariel/searches/sid-1', {'status': 'CANCELED'}),
                      self.fake.calls)
        self.assertIn(('DELETE', 'api/ariel/searches/sid-1', None), self.fake.calls)
        self.assertEqual(self.audit()[0]['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
