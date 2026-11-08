"""Scheduled findings: audit parsing, rules, the expensive searches task, the store, the
scheduler loop, Claude analysis and the Findings API, against fakes (no QRadar, no Claude)."""

import json
import os
import shutil
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))
try:
    from app import (agent_tools, auth, chatstore, claude, expensive_searches as es,
                     findings_analysis, findingstore, qradar, scheduler, settings)
    from qpylib import qpylib
    from test_agent import FakeAnthropic, FakeStream, message
except ImportError as exc:  # run in a venv with the app's wheels, Flask and qpylib
    raise unittest.SkipTest('needs Flask, qpylib and anthropic: {0}'.format(exc))

SID = '9ac9ca6b-984b-4765-b405-8e9c2661d4bb'
# Payloads as QRadar's SIM Audit log source recorded them on the test console.
EXECUTED = (
    'Nov  3 20:28:45 127.0.0.1 ariel_client /127.0.0.1:59712 | [Action] [Search] '
    '[SearchExecuted] query starts, description="User:app-dev,Source:API,Params:Id:' + SID +
    ', DB:<events@/store/ariel/events/records, /store/ariel/events/payloads>, '
    'Time:<26-11-01,20:52:00 to 26-11-03,20:52:00>, last 172800 secs, Sort order:<StartTime,desc>, '
    "Criteria=(<DeviceType:pr=SensorDeviceTypeName():ILike('SIM Audit.*')> AND "
    '(<Qid:pr=QidName():[Search Completed,Search Completed]> OR '
    '<Qid:pr=QidName():[Search Executed,Search Executed]>)), '
    'MappingFactory=com.q1labs.core.types.event.mapping.NormalizedEventMappingFactory@4ee, '
    'search top 4, prio=NORMAL,AQL:SELECT QIDNAME(qid) AS name FROM events WHERE '
    "LOGSOURCETYPENAME(devicetype) ILIKE 'SIM Audit%' ORDER BY starttime DESC LIMIT 4 "
    'LAST 2 DAYS"')
COMPLETED = (
    'Nov  3 20:28:45 127.0.0.1 ariel_query_3 ' + SID + ' | [Action] [Search] [SearchCompleted] '
    'query finished, status=COMPLETED, stat details="Id:' + SID + ', FileStats [dataFileCount=92, '
    'compressedDataFileCount=0, indexFileCount=847, dataTotalSize=10770487, '
    'compressedDataTotalSize=0, indexTotalSize=10360058, progress=100.0%, totalResult=458, '
    'totalResultDataSize=4604, searchTime=55ms]", concurrent queries="1"')


# A Log Activity search built in the UI (your quick filter "payload contains abdallah").
UI_EXECUTED = (
    '[Action] [Search] [SearchExecuted] query starts, description="User:admin,Source:UI,Params:Id:'
    '21eb1724-1841-4053-9aad-2202f2669089,DB:<events>, Time:<26-11-03,21:25:00 to '
    '26-11-03,21:30:00>, Filters:Payload Contains is abdallah, Columns:Associated With Offense, '
    'Event Name, Log Source, Event Count, Time, Category, Source IP, Source Port, Destination IP, '
    'Destination Port, Username, Magnitude"')
UI_DASHBOARD = (
    '[Action] [Search] [SearchExecuted] query starts, description="User:admin,Source:UI,Params:Id:'
    '5e018a25-ba5c-4217-9a10-5bd2611758e5,DB:<GV_#NORMAL#10065>, Time:<26-11-03,15:29:00 to '
    '26-11-03,21:29:00>, Filters:Custom Rule is BB:CategoryDefinition: Firewall or ACL Denies, '
    'Columns:Destination Port, Log Source, Event Name, Aggregates:Destination Port"')


def executed(search_id, user='alice', source='UI', aql='SELECT sourceip FROM events WHERE '
             "devicetype = 12 LAST 1 HOURS", criteria='(<DeviceType:[12,12]>)'):
    return ('x | [Action] [Search] [SearchExecuted] query starts, description="User:{0},Source:{1},'
            'Params:Id:{2}, DB:<events@/store/x>, Time:<26-11-03,19:00:00 to 26-11-03,20:00:00>, '
            'last 3600 secs, Criteria={3}, MappingFactory=x, search top 50, prio=NORMAL,AQL:{4}"'
            ).format(user, source, search_id, criteria, aql)


def completed(search_id, search_ms=50, data_bytes=1000, status='COMPLETED'):
    return ('x | [Action] [Search] [SearchCompleted] query finished, status={0}, stat details="Id:{1}, '
            'FileStats [dataFileCount=3, compressedDataFileCount=0, indexFileCount=5, '
            'dataTotalSize={2}, compressedDataTotalSize=0, indexTotalSize=10, progress=100.0%, '
            'totalResult=7, totalResultDataSize=10, searchTime={3}ms]", concurrent queries="2"'
            ).format(status, search_id, data_bytes, search_ms)


def ident(n):
    return '{0:08d}-0000-0000-0000-000000000000'.format(n)


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ['APP_ROOT'] = self.tmp.name
        os.makedirs(os.path.join(self.tmp.name, 'store', 'log'), exist_ok=True)
        shutil.copy(os.path.join(os.path.dirname(__file__), '..', 'manifest.json'), self.tmp.name)
        qpylib.create_log(False)
        findingstore._initialized = False
        chatstore._initialized = False
        es._ids.clear()

    def tearDown(self):
        self.tmp.cleanup()


class Parsing(unittest.TestCase):
    def test_executed(self):
        start = es.parse_executed(EXECUTED)
        self.assertEqual((start['user'], start['source'], start['search_id'], start['db']),
                         ('app-dev', 'API', SID, 'events'))
        self.assertEqual(start['window_seconds'], 172800)
        self.assertTrue(start['criteria'].startswith("(<DeviceType:pr=SensorDeviceTypeName()"))
        self.assertTrue(start['aql'].startswith('SELECT QIDNAME(qid)'))
        self.assertTrue(start['aql'].endswith('LAST 2 DAYS'))
        self.assertIsNone(es.parse_executed(COMPLETED))

    def test_completed(self):
        done = es.parse_completed(COMPLETED)
        self.assertEqual(done, {'search_id': SID, 'status': 'COMPLETED', 'search_ms': 55,
                                'data_bytes': 10770487, 'index_bytes': 10360058,
                                'data_files': 92, 'index_files': 847, 'results': 458,
                                'concurrent': 1})
        self.assertIsNone(es.parse_completed(EXECUTED))


class UiSearches(unittest.TestCase):
    LIMITS = {'warning_ms': 5 * 60000, 'critical_ms': 15 * 60000, 'heavy_bytes': 10 * 10 ** 9}

    def test_quick_filter_payload_search_is_flagged(self):
        start = es.parse_executed(UI_EXECUTED)
        self.assertEqual((start['user'], start['source'], start['db']), ('admin', 'UI', 'events'))
        self.assertEqual(start['filters'], 'Payload Contains is abdallah')
        self.assertIsNone(start['aql'])
        self.assertEqual(start['window_seconds'], 300)
        done = {'search_ms': 63, 'data_bytes': 1163998}
        self.assertEqual(es.evaluate(start, done, self.LIMITS),
                         ('warning', ['filters on the raw payload']))

    def test_dashboard_rule_search_is_not(self):
        start = es.parse_executed(UI_DASHBOARD)
        self.assertEqual(start['db'], 'GV_#NORMAL#10065')
        self.assertEqual(es.evaluate(start, {'search_ms': 3}, self.LIMITS), (None, []))

    def test_ui_filter_wording(self):
        self.assertEqual(es.costly_filters(None, None, 'Username Contains is adm'),
                         ['uses substring matching (Contains)'])
        self.assertEqual(es.costly_filters(None, None, 'Payload Matches Regular Expression is a.*b'),
                         ['uses regular expressions'])
        self.assertEqual(es.costly_filters(None, None, 'Quick Filter is failed'),
                         ['uses full-text search'])
        self.assertEqual(es.costly_filters(None, None,
                                           'Log Source is fw01, Source IP is 10.0.0.1'), [])
        self.assertEqual(es.costly_filters(None, None, 'Payload Contains is x, Event Name '
                                                       'Contains is logon'),
                         ['filters on the raw payload', 'uses substring matching (Contains)'])

    def test_ui_searches_group_by_filter_text(self):
        a = es.parse_executed(UI_EXECUTED)
        b = dict(a, filters='Payload Contains is someoneelse', search_id='other')
        self.assertEqual(es.fingerprint(a), es.fingerprint(b))  # same filter, other value


class Rules(unittest.TestCase):
    LIMITS = {'warning_ms': 5 * 60000, 'critical_ms': 15 * 60000, 'heavy_bytes': 10 * 10 ** 9}

    def test_costly_filters(self):
        start = es.parse_executed(EXECUTED)
        self.assertEqual(es.costly_filters(start['criteria'], start['aql']), [
            'filters through functions that cannot use indexes: QidName(), '
            'SensorDeviceTypeName()',
            'uses wildcard (LIKE/ILIKE) matching'])
        self.assertEqual(es.costly_filters('(<DeviceType:[105,105]>)',
                                           'SELECT x FROM events WHERE devicetype = 105'), [])
        self.assertEqual(es.costly_filters('', "SELECT x FROM events WHERE username ILIKE 'bob'"),
                         [])  # case-insensitive equality, no wildcard
        self.assertEqual(es.costly_filters('', "SELECT x FROM events WHERE username ILIKE '%bob%'"),
                         ['uses wildcard (LIKE/ILIKE) matching'])
        self.assertEqual(
            es.costly_filters('', "SELECT UTF8(payload) FROM events WHERE devicetype = 12"), [])
        self.assertEqual(
            es.costly_filters('', "SELECT x FROM events WHERE UTF8(payload) IMATCHES '.*pass.*'"),
            ['filters on the raw payload', 'uses regular expressions'])
        # As QRadar parses a payload filter: UTF8() is not listed again as a function.
        self.assertEqual(es.costly_filters("(<Payload:pr=UTF8():ILike('.*THINKPADU5.*')>)", ''),
                         ['filters on the raw payload', 'uses wildcard (LIKE/ILIKE) matching'])

    def test_evaluate(self):
        cheap = {'criteria': '(<DeviceType:[12,12]>)', 'aql': 'SELECT x FROM events WHERE devicetype = 12'}
        self.assertEqual(es.evaluate(cheap, {'search_ms': 1000, 'data_bytes': 10}, self.LIMITS),
                         (None, []))
        self.assertEqual(es.evaluate(cheap, {'search_ms': 6 * 60000}, self.LIMITS)[0], 'warning')
        self.assertEqual(es.evaluate(cheap, {'search_ms': 16 * 60000}, self.LIMITS),
                         ('critical', ['ran for 16.0 min']))
        self.assertEqual(es.evaluate(cheap, {'search_ms': 1000, 'data_bytes': 11 * 10 ** 9},
                                     self.LIMITS), ('warning', ['scanned 11.0 GB of data']))
        # Costly filters are a finding whatever the time range (here one minute).
        costly = {'criteria': '', 'aql': "SELECT x FROM events WHERE UTF8(payload) ILIKE '%a%' "
                                         'LAST 1 MINUTES', 'window_seconds': 60}
        self.assertEqual(es.evaluate(costly, {'search_ms': 10}, self.LIMITS)[0], 'warning')

    def test_fingerprint_groups_repeats(self):
        a = {'user': 'alice', 'source': 'UI',
             'aql': "SELECT x FROM events WHERE sourceip = '10.0.0.1' LAST 2 HOURS"}
        b = dict(a, aql="SELECT  x FROM events WHERE sourceip = '10.9.9.9' LAST 30 DAYS")
        self.assertEqual(es.fingerprint(a), es.fingerprint(b))
        self.assertNotEqual(es.fingerprint(a), es.fingerprint(dict(a, user='bob')))


class FakeQRadar:
    def __init__(self, events, live=None):
        self.events, self.calls = events, []
        self.live = live or {}  # search id -> live status in QRadar's search list

    def __call__(self, method, path, params=None, headers=None, token=None, ok=(200, 206)):
        self.calls.append((method, path, params))
        if path == 'api/data_classification/qid_records':
            body = [{'qid': 28250254}] if 'Executed' in params['filter'] else [{'qid': 28250295}]
        elif path == 'api/ariel/validators/aql':
            body = {'error_messages': []}
        elif path == 'api/ariel/searches' and method == 'POST':
            self.last_aql = params['query_expression']
            body = {'search_id': 'collector'}
        elif path == 'api/ariel/searches/collector' and method == 'GET':
            body = {'status': 'COMPLETED'}
        elif path.endswith('/results'):
            body = {'events': self.events}
        elif path.startswith('api/ariel/searches/') and method == 'GET':
            search_id = path.rsplit('/', 1)[1]
            if search_id not in self.live:
                return types.SimpleNamespace(json=lambda: {}, status_code=404)
            body = {'status': self.live[search_id]}
        else:
            body = {}
        return types.SimpleNamespace(json=lambda: body, status_code=200)


class Task(StoreTestCase):
    def setUp(self):
        super().setUp()
        self.saved = [(qradar, n, getattr(qradar, n)) for n in ('call', 'log_source_types')]
        qradar.log_source_types = lambda: {105: 'SIM Audit', 12: 'Windows'}

    def tearDown(self):
        for obj, name, value in self.saved:
            setattr(obj, name, value)
        super().tearDown()

    def run_with(self, events, live=None):
        qradar.call = fake = FakeQRadar(events, live)
        return es.run(), fake

    def test_start_from_now_then_findings(self):
        (new, updated, msg), fake = self.run_with([])
        self.assertEqual((new, updated, msg), (0, 0, 'Watching searches from now on.'))
        self.assertFalse(any(p == 'api/ariel/searches' for _, p, _ in fake.calls))

        payload_aql = "SELECT * FROM events WHERE UTF8(payload) ILIKE '%password%' LAST 30 DAYS"
        events = [
            {'Time': 1, 'Payload': executed(ident(1), aql=payload_aql, criteria='(<Payload>)')},
            {'Time': 2, 'Payload': completed(ident(1), search_ms=16 * 60000)},
            {'Time': 3, 'Payload': executed(ident(2))},                    # cheap search
            {'Time': 4, 'Payload': completed(ident(2))},
            {'Time': 5, 'Payload': executed(ident(3), aql='SELECT x AS "{0}" FROM events WHERE '
                                            'devicetype = 105'.format(es.MARKER))},
            {'Time': 6, 'Payload': completed(ident(3), search_ms=20 * 60000)},  # our own, skipped
            {'Time': 7, 'Payload': completed(ident(4), search_ms=10)},     # start unknown, cheap
        ]
        (new, updated, msg), fake = self.run_with(events)
        self.assertEqual((new, updated), (1, 0))
        self.assertIn('devicetype = 105 AND qid IN (28250254, 28250295)', fake.last_aql)
        self.assertIn(es.MARKER, fake.last_aql)
        [finding] = findingstore.search()
        self.assertEqual(finding['severity'], 'critical')
        self.assertEqual(finding['details']['user'], 'alice')
        self.assertEqual(finding['details']['reasons'], [
            'ran for 16.0 min', 'filters on the raw payload', 'uses wildcard (LIKE/ILIKE) matching'])
        self.assertTrue(finding['title'].startswith('Search ran for 16.0 min · alice (UI)'))

        # The same query again (other literal and time range): one finding, two occurrences.
        again = payload_aql.replace('password', 'secret').replace('30 DAYS', '7 DAYS')
        (new, updated, _), _ = self.run_with([
            {'Time': 8, 'Payload': executed(ident(5), aql=again, criteria='(<Payload>)')},
            {'Time': 9, 'Payload': completed(ident(5), search_ms=6 * 60000)},
            {'Time': 9, 'Payload': completed(ident(5), search_ms=6 * 60000)},  # duplicate event
        ])
        self.assertEqual((new, updated), (0, 1))
        [finding] = findingstore.search()
        self.assertEqual(finding['occurrences'], 2)
        self.assertEqual(finding['severity'], 'critical')  # never lowered
        self.assertEqual(finding['details']['worst']['search_ms'], 16 * 60000)

    def test_completion_before_start_is_not_still_running(self):
        # A fast search: QRadar returned its completion before its start (same timestamp).
        self.run_with([])
        old = findingstore.now_ms() - 20 * 60000
        (new, updated, _), _ = self.run_with([
            {'Time': old, 'Payload': completed(ident(7), search_ms=8)},
            {'Time': old, 'Payload': executed(ident(7))}])
        self.assertEqual((new, updated), (0, 0))
        (new, updated, _), _ = self.run_with([], live={})  # nothing pending any more
        self.assertEqual((new, updated), (0, 0))
        self.assertEqual(findingstore.search(), [])

    def test_still_running_needs_qradar_to_confirm(self):
        self.run_with([])
        old = findingstore.now_ms() - 20 * 60000
        # Audit says started 20 min ago, no completion seen, but QRadar says it completed.
        (new, _, _), _ = self.run_with([{'Time': old, 'Payload': executed(ident(8))}],
                                       live={ident(8): 'COMPLETED'})
        self.assertEqual(new, 0)
        self.assertEqual(findingstore.still_running(findingstore.now_ms()), [])

    def test_still_running_searches(self):
        self.run_with([])
        old = findingstore.now_ms() - 20 * 60000
        (new, _, _), _ = self.run_with([{'Time': old, 'Payload': executed(ident(9))}],
                                       live={ident(9): 'EXECUTE'})
        [finding] = findingstore.search()
        self.assertEqual(finding['severity'], 'critical')
        self.assertIn('still running after 20 min', finding['details']['reasons'][0])
        (new, updated, _), _ = self.run_with([])  # flagged once only
        self.assertEqual((new, updated), (0, 0))


class Store(StoreTestCase):
    def test_lifecycle(self):
        self.assertEqual(findingstore.upsert('c', 'f', 'warning', 'T', {}, 1), 'new')
        [f] = findingstore.search()
        self.assertEqual((f['status'], f['needs_analysis']), ('open', findingstore.AUTOMATIC))
        findingstore.save_analysis(f['id'], 'why', 'claude-opus-5-5')
        findingstore.set_status(f['id'], 'resolved')
        self.assertEqual(findingstore.upsert('c', 'f', 'warning', 'T', {}, 2), 'reopened')
        f = findingstore.get(f['id'])
        self.assertEqual((f['status'], f['needs_analysis']), ('open', findingstore.AUTOMATIC))
        findingstore.save_analysis(f['id'], 'why', 'm')
        findingstore.set_status(f['id'], 'ignored')
        self.assertEqual(findingstore.upsert('c', 'f', 'critical', 'Worse', {}, 3), 'updated')
        f = findingstore.get(f['id'])
        self.assertEqual((f['status'], f['severity'], f['title'], f['occurrences']),
                         ('ignored', 'critical', 'Worse', 3))
        self.assertEqual(findingstore.pending_analysis(5, True), [])  # ignored: no analysis
        with self.assertRaises(ValueError):
            findingstore.set_status(f['id'], 'deleted')

    def test_pending_analysis_respects_the_setting(self):
        findingstore.upsert('c', 'auto', 'warning', 'A', {}, 1)
        findingstore.upsert('c', 'asked', 'warning', 'B', {}, 1)
        asked = findingstore.by_fingerprint('c', 'asked')
        findingstore.request_analysis(asked['id'])
        self.assertEqual([f['title'] for f in findingstore.pending_analysis(5, False)], ['B'])
        self.assertEqual(sorted(f['title'] for f in findingstore.pending_analysis(5, True)),
                         ['A', 'B'])


class Scheduler(StoreTestCase):
    def test_due(self):
        self.assertTrue(scheduler.due('t', 1000, 600000))  # never ran
        findingstore.set_task_state('t', last_run=1000)
        self.assertFalse(scheduler.due('t', 2000, 600000))
        self.assertTrue(scheduler.due('t', 1000 + 600000, 600000))
        findingstore.set_task_state('t', run_requested=1500)
        self.assertTrue(scheduler.due('t', 2000, 600000))  # Run now pressed after last run

    def test_failed_run_is_recorded(self):
        def broken():
            raise RuntimeError('QRadar unreachable')
        scheduler.run_task('t', broken)
        [run] = findingstore.last_runs('t')
        self.assertEqual((run['status'], run['message']), ('failed', 'QRadar unreachable'))
        self.assertIsNotNone(findingstore.task_state('t')['last_run'])


class Analysis(StoreTestCase):
    def test_request_and_result(self):
        findingstore.upsert('expensive_searches', 'f', 'critical', 'Search ran for 16 min',
                            {'aql': 'SELECT 1', 'reasons': ['ran for 16.0 min']}, 1)
        finding = findingstore.search()[0]
        requests = []
        reply = message([{'type': 'text', 'text': 'Use an indexed filter.'}], 'end_turn')
        api = types.SimpleNamespace(beta=types.SimpleNamespace(messages=types.SimpleNamespace(
            stream=lambda **kw: requests.append(kw) or FakeStream([], reply))))
        original_client, original_config = claude.client, settings.get_config
        claude.client = lambda key, **kw: (FakeAnthropic, api)
        try:
            settings.get_config = lambda name: ('claude-haiku-5-5' if name == 'findings_model'
                                                else original_config(name))
            text, model = findings_analysis.analyse(finding, 'sk-ant-test')
        finally:
            claude.client, settings.get_config = original_client, original_config
        self.assertEqual(text, 'Use an indexed filter.')
        self.assertEqual(requests[0]['model'], 'claude-haiku-5-5')
        self.assertNotIn('fallbacks', requests[0])  # Haiku has no server-side fallback
        self.assertIn('"aql": "SELECT 1"', requests[0]['messages'][0]['content'])


class Api(StoreTestCase):
    def setUp(self):
        super().setUp()
        self.saved = (auth.is_admin,)
        from flask import g

        def admin():
            g.qradar_user = 'admin'
            return True
        auth.is_admin = admin
        from app import create_app
        self.client = create_app().test_client()

    def tearDown(self):
        auth.is_admin = self.saved[0]
        super().tearDown()

    def test_routes(self):
        findingstore.upsert('expensive_searches', 'f', 'warning', 'Search uses costly filters',
                            {'user': 'alice', 'aql': 'SELECT 1'}, 1)
        data = self.client.get('/api/findings?status=open').get_json()
        self.assertEqual([f['title'] for f in data['findings']], ['Search uses costly filters'])
        self.assertEqual(data['tasks'][0]['task'], 'expensive_searches')
        fid = data['findings'][0]['id']
        self.assertEqual(self.client.put('/api/findings/%s/status' % fid,
                                         json={'status': 'acknowledged'}).status_code, 200)
        self.assertEqual(self.client.put('/api/findings/%s/status' % fid,
                                         json={'status': 'gone'}).status_code, 400)
        self.assertEqual(self.client.post('/api/findings/tasks/expensive_searches/run').status_code,
                         202)
        self.assertIsNotNone(findingstore.task_state('expensive_searches')['run_requested'])
        chat = self.client.post('/api/findings/%s/chat' % fid).get_json()
        context = chatstore.get(chat['chat_id'], 'admin')['pending_context']
        self.assertIn('[Attached: finding \\"Search uses costly filters\\"]', context)
        tool = json.loads(agent_tools.run('list_findings', {'status': 'any'})[0])
        self.assertEqual(tool['findings'][0]['status'], 'acknowledged')


if __name__ == '__main__':
    unittest.main()
