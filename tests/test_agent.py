"""Agent loop, tools, chat store and transcript, with a fake Claude client (no API calls).

Needs the app's dependencies (Flask, qpylib, anthropic); run in a venv with them.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))
try:
    from anthropic.types.beta import BetaMessage
    from app import agent, agent_tools, chatstore, claude, qradar, settings
    from qpylib import qpylib
except ImportError as exc:  # run in a venv with the app's wheels, Flask and qpylib
    raise unittest.SkipTest('needs anthropic, Flask and qpylib: {0}'.format(exc))
from test_logsources import NOW, SOURCES  # noqa: E402

OWNER = 'admin'


def message(content, stop_reason):
    return BetaMessage.model_validate({
        'id': 'msg_test', 'type': 'message', 'role': 'assistant', 'model': claude.MODEL,
        'content': content, 'stop_reason': stop_reason, 'stop_sequence': None,
        'usage': {'input_tokens': 10, 'output_tokens': 5}})


def text_events(text):
    return [types.SimpleNamespace(type='content_block_start',
                                  content_block=types.SimpleNamespace(type='text')),
            types.SimpleNamespace(type='content_block_delta',
                                  delta=types.SimpleNamespace(type='text_delta', text=text))]


class FakeStream:
    def __init__(self, events, final):
        self.events, self.final = events, final

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __iter__(self):
        return iter(self.events)

    def get_final_message(self):
        return self.final


class FakeAPI:
    """Replays scripted (events, final message) turns and records each request."""

    def __init__(self, turns):
        self.turns = list(turns)
        self.requests = []
        self.beta = types.SimpleNamespace(messages=types.SimpleNamespace(stream=self.stream))

    def stream(self, **kwargs):
        self.requests.append(json.loads(json.dumps(kwargs, default=str)))
        events, final = self.turns.pop(0)
        return FakeStream(events, final)


class FakeAnthropic:
    class APIStatusError(Exception):
        pass

    class APIConnectionError(Exception):
        pass


class AgentTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ['APP_ROOT'] = self.tmp.name
        os.makedirs(os.path.join(self.tmp.name, 'store', 'log'), exist_ok=True)
        shutil.copy(os.path.join(os.path.dirname(__file__), '..', 'manifest.json'), self.tmp.name)
        qpylib.create_log(False)  # as create_app() does; a no-op after the first call
        chatstore._initialized = False
        self.patches = [(qradar, 'log_sources', lambda: SOURCES),
                        (settings, 'get', lambda name: 'sk-ant-test'),
                        (agent_tools, '_now_ms', lambda: NOW)]
        self.saved = [(obj, name, getattr(obj, name)) for obj, name, _ in self.patches]
        for obj, name, value in self.patches:
            setattr(obj, name, value)

    def tearDown(self):
        for obj, name, value in self.saved:
            setattr(obj, name, value)
        self.tmp.cleanup()

    def run_agent(self, turns, text='Is fw01 sending?'):
        api = FakeAPI(turns)
        original = claude.client
        claude.client = lambda key, **kw: (FakeAnthropic, api)
        try:
            chat = chatstore.create(OWNER)
            run = agent.start(chat, OWNER, text)
            for _ in range(200):
                if run.done:
                    break
                time.sleep(0.01)
        finally:
            claude.client = original
        events, done = run.since(0)
        self.assertTrue(done)
        return chat, api, events


class AgentLoop(AgentTestCase):
    def test_tool_call_then_answer(self):
        tool_turn = message([{'type': 'tool_use', 'id': 'toolu_1', 'name': 'search_log_sources',
                              'input': {'query': 'fw01'}}], 'tool_use')
        answer_turn = message([{'type': 'text', 'text': 'fw01 is silent.'}], 'end_turn')
        chat, api, events = self.run_agent([([], tool_turn),
                                            (text_events('fw01 is silent.'), answer_turn)])

        stored = chatstore.messages(chat['id'])
        self.assertEqual([m['role'] for m in stored], ['user', 'assistant', 'user', 'assistant'])
        result = stored[2]['content'][0]
        self.assertEqual(result['tool_use_id'], 'toolu_1')
        self.assertFalse(result['is_error'])
        self.assertEqual(json.loads(result['content'])['log_sources'][0]['name'],
                         'fw01.corp.local')
        self.assertEqual(chatstore.get(chat['id'], OWNER)['title'], 'Is fw01 sending?')

        first, second = api.requests
        self.assertEqual(first['model'], 'claude-opus-5-5')
        self.assertEqual(first['fallbacks'], 'default')
        self.assertIn('server-side-fallback-2026-07-01', first['betas'])
        self.assertEqual(first['thinking']['block_binding'],
                         {'prefix_mismatch_behavior': 'drop_block'})
        # System prompt and tools must not change within a conversation.
        self.assertEqual(first['system'], second['system'])
        self.assertEqual(first['tools'], second['tools'])
        self.assertEqual(second['messages'][:1], first['messages'])

        kinds = [e['type'] for e in events]
        self.assertIn('tool', kinds)
        self.assertEqual(''.join(e['text'] for e in events if e['type'] == 'text'),
                         'fw01 is silent.')
        self.assertEqual(kinds[-1], 'done')

    def test_refusal_closes_the_turn(self):
        chat, _, events = self.run_agent([(text_events('partial'), message([], 'refusal'))])
        stored = chatstore.messages(chat['id'])
        self.assertEqual([m['role'] for m in stored], ['user', 'assistant'])
        self.assertIn('declined', stored[1]['content'][0]['text'])
        self.assertEqual(stored[1]['kind'], 'error')
        self.assertIn('reset_text', [e['type'] for e in events])
        self.assertIn('error', [e['type'] for e in events])

    def test_no_api_key(self):
        settings.get = lambda name: None
        chat = chatstore.create(OWNER)
        with self.assertRaises(agent.AgentError):
            agent.start(chat, OWNER, 'hello')
        self.assertEqual(chatstore.messages(chat['id']), [])

    def test_cancel_mid_stream(self):
        gate = threading.Event()

        class SlowStream(FakeStream):
            def __iter__(self):
                yield from text_events('half')
                gate.wait(2)
                yield from text_events(' more')

        api = FakeAPI([])
        api.beta.messages.stream = lambda **kw: SlowStream([], message([], 'end_turn'))
        original = claude.client
        claude.client = lambda key, **kw: (FakeAnthropic, api)
        try:
            chat = chatstore.create(OWNER)
            run = agent.start(chat, OWNER, 'hi')
            time.sleep(0.05)
            run.cancelled = True
            gate.set()
            for _ in range(200):
                if run.done:
                    break
                time.sleep(0.01)
        finally:
            claude.client = original
        stored = chatstore.messages(chat['id'])
        self.assertEqual([m['role'] for m in stored], ['user', 'assistant'])
        self.assertEqual(stored[1]['content'][0]['text'], 'Stopped by the user.')
        self.assertEqual(stored[1]['kind'], 'notice')

    def test_attachment_goes_with_next_message(self):
        chat = chatstore.create(OWNER)
        chatstore.set_pending_context(chat['id'], {'text': '[Attached: bulk check of a.xlsx]\n...'})
        api = FakeAPI([(text_events('ok'), message([{'type': 'text', 'text': 'ok'}], 'end_turn'))])
        original = claude.client
        claude.client = lambda key, **kw: (FakeAnthropic, api)
        try:
            run = agent.start(chatstore.get(chat['id'], OWNER), OWNER, 'Summarize it')
            while not run.done:
                time.sleep(0.01)
        finally:
            claude.client = original
        sent = api.requests[0]['messages'][0]['content']
        self.assertEqual([b['text'][:9] for b in sent], ['[Attached', 'Summarize'])
        items = agent.transcript(chatstore.messages(chat['id']))
        self.assertEqual(items[0]['attachment'], '[Attached: bulk check of a.xlsx]')
        self.assertIsNone(chatstore.take_pending_context(chat['id']))


class Errors(AgentTestCase):
    def test_api_error_is_saved_with_its_detail(self):
        import httpx2
        import anthropic

        class Failing(FakeAPI):
            def stream(self, **kwargs):
                request = httpx2.Request('POST', 'https://api.anthropic.com/v1/messages')
                body = {'type': 'error', 'error': {'type': 'invalid_request_error',
                                                   'message': 'Your credit balance is too low.'}}
                response = httpx2.Response(400, request=request, json=body)
                raise anthropic.BadRequestError('Error code: 400', response=response, body=body)

        api = Failing([])
        original = claude.client
        claude.client = lambda key, **kw: (anthropic, api)
        try:
            chat = chatstore.create(OWNER)
            run = agent.start(chat, OWNER, 'hi')
            while not run.done:
                time.sleep(0.01)
        finally:
            claude.client = original
        expected = 'Claude rejected the request (HTTP 400): Your credit balance is too low.'
        self.assertIn({'type': 'error', 'message': expected}, run.since(0)[0])
        items = agent.transcript(chatstore.messages(chat['id']))
        self.assertEqual(items[-1], {'role': 'assistant', 'text': expected, 'tools': [],
                                     'kind': 'error'})


class Store(AgentTestCase):
    def test_uploads_appear_where_they_happened(self):
        chat = chatstore.create(OWNER)
        chatstore.append(chat['id'], 'user', [{'type': 'text', 'text': 'hello'}])
        chatstore.append(chat['id'], 'assistant', [{'type': 'text', 'text': 'hi'}])
        upload_id = chatstore.add_upload(chat['id'], 'a.xlsx', 'result.xlsx', 'Checked 1 rows.',
                                         {'targets': 1, 'connected': 1, 'not_connected': 0,
                                          'not_found': 0}, b'PK-bytes')
        chatstore.append(chat['id'], 'user', [{'type': 'text', 'text': 'next'}])
        items = agent.transcript(chatstore.messages(chat['id']), chatstore.uploads(chat['id']))
        self.assertEqual([i['role'] for i in items], ['user', 'assistant', 'upload', 'user'])
        self.assertEqual(items[2]['id'], upload_id)
        self.assertEqual(chatstore.upload_file(chat['id'], upload_id), ('result.xlsx', b'PK-bytes'))
        self.assertIsNone(chatstore.upload_file('other-chat', upload_id))
        chatstore.delete(chat['id'], OWNER)
        self.assertEqual(chatstore.uploads(chat['id']), [])

    def test_upgrades_a_040_database(self):
        import sqlite3
        path = os.path.join(self.tmp.name, 'store', 'db', 'chats.db')
        os.makedirs(os.path.dirname(path))
        old = sqlite3.connect(path)
        old.executescript('''
            CREATE TABLE conversations (id TEXT PRIMARY KEY, owner TEXT NOT NULL,
                title TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL,
                pending_context TEXT);
            CREATE TABLE messages (conversation_id TEXT NOT NULL, seq INTEGER NOT NULL,
                role TEXT NOT NULL, content TEXT NOT NULL, usage TEXT, created INTEGER NOT NULL,
                PRIMARY KEY (conversation_id, seq));
            INSERT INTO conversations VALUES ('c1', 'admin', 'old', 1, 1, NULL);
            INSERT INTO messages VALUES ('c1', 0, 'user', '[{"type": "text", "text": "hi"}]',
                NULL, 1);
        ''')
        old.commit()
        old.close()
        self.assertEqual(chatstore.messages('c1')[0]['kind'], None)
        chatstore.append('c1', 'assistant', [{'type': 'text', 'text': 'x'}], kind='error')
        self.assertEqual(chatstore.messages('c1')[1]['kind'], 'error')
    def test_owner_isolation_and_delete(self):
        chat = chatstore.create('alice')
        self.assertIsNone(chatstore.get(chat['id'], 'bob'))
        self.assertEqual(chatstore.list_for('bob'), [])
        self.assertFalse(chatstore.delete(chat['id'], 'bob'))
        self.assertTrue(chatstore.delete(chat['id'], 'alice'))

    def test_transcript_merges_tool_rounds(self):
        msgs = [
            {'role': 'user', 'content': [{'type': 'text', 'text': 'review'}]},
            {'role': 'assistant', 'content': [
                {'type': 'thinking', 'thinking': 'x', 'signature': 's'},
                {'type': 'tool_use', 'id': 't1', 'name': 'log_source_overview', 'input': {}}]},
            {'role': 'user', 'content': [{'type': 'tool_result', 'tool_use_id': 't1',
                                          'content': '{}'}]},
            {'role': 'assistant', 'content': [{'type': 'text', 'text': 'All good.'}]},
        ]
        self.assertEqual(agent.transcript(msgs), [
            {'role': 'user', 'text': 'review', 'attachment': None},
            {'role': 'assistant', 'text': 'All good.', 'tools': ['Reviewing log source health'],
             'kind': None},
        ])


class Tools(AgentTestCase):
    def call(self, name, args):
        text, is_error = agent_tools.run(name, args)
        return (text if is_error else json.loads(text)), is_error

    def test_overview_excludes_internal(self):
        result, _ = self.call('log_source_overview', {})
        self.assertEqual(result['external_log_sources'], 5)
        self.assertEqual(result['internal_log_sources_excluded'], 1)
        self.assertEqual(result['by_state'], {'connected': 2, 'silent': 1, 'never': 1,
                                              'disabled': 1})
        self.assertEqual([s['name'] for s in result['examples']['qradar_error_or_warning']],
                         ['fw01.corp.local'])

    def test_search_filters(self):
        result, _ = self.call('search_log_sources', {'states': ['silent', 'never']})
        self.assertEqual(sorted(s['name'] for s in result['log_sources']),
                         ['Okta', 'fw01.corp.local'])
        result, _ = self.call('search_log_sources', {'query': 'microsoft', 'limit': 1})
        self.assertEqual((result['total_matches'], result['returned']), (2, 1))

    def test_get_and_check_targets(self):
        okta = next(s for s in SOURCES if s['name'] == 'Okta')
        detail, _ = self.call('get_log_source', {'id': okta['id']})
        self.assertEqual(detail['protocol_settings'], [{'name': 'identifier',
                                                        'value': 'okta.example.com'}])
        result, _ = self.call('check_targets', {'targets': ['10.0.0.1', 'ghost.local']})
        self.assertEqual([r['status'] for r in result['results']], ['connected', 'not_found'])

    def test_bad_input_is_an_error_result(self):
        for name, args in [('search_log_sources', {'limit': 0}),
                           ('search_log_sources', {'states': ['broken']}),
                           ('get_log_source', {'id': 'x'}),
                           ('check_targets', {'targets': []}),
                           ('nope', {})]:
            message_text, is_error = agent_tools.run(name, args)
            self.assertTrue(is_error, (name, args))


if __name__ == '__main__':
    unittest.main()
