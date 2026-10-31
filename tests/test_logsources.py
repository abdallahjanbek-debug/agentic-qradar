import os
import sys
import unittest

# Import logsources.py on its own: importing the app package needs Flask and qpylib.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
import logsources as assistant  # noqa: E402

NOW = 1_800_000_000_000
MIN = 60_000


def source(name, type_='', identifier='', values=(), enabled=True, last=NOW - MIN, eps=1.5,
           internal=False):
    return {'id': hash(name) % 1000, 'name': name, 'description': '', 'type': type_,
            'protocol': 'Syslog', 'identifier': identifier, 'search_values': list(values),
            'enabled': enabled, 'internal': internal, 'last_event_time': last, 'average_eps': eps,
            'collector': 'eventcollector0', 'health': 'SUCCESS', 'messages': []}


SOURCES = [
    source('FortiGate @ 10.0.0.1', 'Fortinet FortiGate Security Gateway', '10.0.0.1'),
    source('fw01.corp.local', 'Cisco ASA', 'fw01.corp.local', last=NOW - 3 * 60 * MIN),
    source('Microsoft 365 - Tenant A', 'Microsoft 365', 'tenant-a', last=NOW - 5 * MIN),
    source('Okta', 'Okta', 'okta.example.com', last=0),
    source('Old DC', 'Microsoft Windows Security Event Log', '10.0.0.10', enabled=False),
    source('Custom Rule Engine-8 :: qradar', 'Custom Rule Engine', '10.0.0.1', last=0,
           internal=True),
]


class ParseQuestion(unittest.TestCase):
    def test_extracts_ip_host_and_terms(self):
        parsed = assistant.parse_question('Is 10.0.0.1 or fw01.corp.local still sending logs?')
        self.assertEqual(parsed['ips'], ['10.0.0.1'])
        self.assertEqual(parsed['hosts'], ['fw01.corp.local'])
        self.assertEqual(parsed['terms'], [])

    def test_keywords_without_stopwords(self):
        self.assertEqual(assistant.parse_question('Is Office 365 connected?')['terms'],
                         ['office', '365'])


class Answer(unittest.TestCase):
    def ask(self, question):
        return assistant.answer(question, SOURCES, NOW)

    def test_ip_connected(self):
        result = self.ask('Is 10.0.0.1 connected?')
        self.assertEqual(len(result['matches']), 1)
        self.assertEqual(result['matches'][0]['state'], 'connected')
        self.assertTrue(result['answer'].startswith('Yes.'))

    def test_ip_does_not_match_longer_ip(self):
        result = self.ask('10.0.0.1')
        self.assertNotIn('Old DC', [m['name'] for m in result['matches']])

    def test_hostname_silent(self):
        result = self.ask('is fw01.corp.local up')
        self.assertEqual(result['matches'][0]['state'], 'silent')
        self.assertIn('3 h', result['answer'])

    def test_short_hostname(self):
        self.assertEqual(self.ask('fw01')['matches'][0]['name'], 'fw01.corp.local')

    def test_saas_alias(self):
        result = self.ask('Is o365 sending events?')
        self.assertEqual([m['name'] for m in result['matches']], ['Microsoft 365 - Tenant A'])

    def test_never_and_disabled(self):
        self.assertEqual(self.ask('okta')['matches'][0]['state'], 'never')
        self.assertEqual(self.ask('10.0.0.10')['matches'][0]['state'], 'disabled')

    def test_multiple_matches_summary(self):
        result = self.ask('microsoft')
        self.assertEqual(len(result['matches']), 2)
        self.assertIn('2 log sources match', result['answer'])

    def test_internal_sources_only_for_keywords(self):
        self.assertEqual([m['name'] for m in self.ask('10.0.0.1')['matches']],
                         ['FortiGate @ 10.0.0.1'])
        self.assertEqual(self.ask('custom rule engine')['matches'][0]['state'], 'never')

    def test_no_match(self):
        result = self.ask('Is 192.168.99.99 connected?')
        self.assertEqual(result['matches'], [])
        self.assertIn('no log source', result['answer'])

    def test_several_ips_are_checked_separately(self):
        result = self.ask('Are 10.0.0.1 and 10.0.0.10 connected?')
        self.assertTrue(result['answer'].startswith('1 of 2 have a log source receiving events.'))
        self.assertIn('Not receiving: 10.0.0.10.', result['answer'])
        self.assertEqual({(m['target'], m['state']) for m in result['matches']},
                         {('10.0.0.1', 'connected'), ('10.0.0.10', 'disabled')})

    def test_several_targets_with_unknown(self):
        result = self.ask('10.0.0.1, fw01.corp.local and 9.9.9.9')
        self.assertIn('No log source found for: 9.9.9.9.', result['answer'])
        self.assertIn('Not receiving: fw01.corp.local.', result['answer'])


class MatchTarget(unittest.TestCase):
    def names(self, ip, host):
        return [(s['name'], how) for s, how in assistant.match_target(ip, host, SOURCES)]

    def test_exact_ip_skips_internal(self):
        self.assertEqual(self.names('10.0.0.1', ''), [('FortiGate @ 10.0.0.1', 'IP = identifier')])

    def test_ip_does_not_match_longer_ip(self):
        self.assertEqual(self.names('10.0.0.1', '')[0][0], 'FortiGate @ 10.0.0.1')
        self.assertEqual(len(self.names('10.0.0.1', '')), 1)

    def test_short_hostname(self):
        self.assertEqual(self.names('', 'FW01'), [('fw01.corp.local', 'Short hostname = identifier')])

    def test_fqdn_matches_short_identifier_in_name(self):
        sources = SOURCES + [source('WinCollect @ THINKPAD01', 'WinCollect', 'THINKPAD01')]
        found = assistant.match_target('', 'thinkpad01.corp.local', sources)
        self.assertEqual([s['name'] for s, _ in found], ['WinCollect @ THINKPAD01'])

    def test_ip_and_hostname_both_used(self):
        names = [n for n, _ in self.names('10.0.0.1', 'okta.example.com')]
        self.assertEqual(sorted(names), ['FortiGate @ 10.0.0.1', 'Okta'])

    def test_no_match(self):
        self.assertEqual(self.names('192.168.1.1', 'nothing.local'), [])

    def test_target_status(self):
        self.assertEqual(assistant.target_status(set()), 'not_found')
        self.assertEqual(assistant.target_status({'silent', 'connected'}), 'connected')
        self.assertEqual(assistant.target_status({'never', 'disabled'}), 'not_connected')


class AnswerHelpers(unittest.TestCase):
    def ask(self, question):
        return assistant.answer(question, SOURCES, NOW)

    def test_can_answer(self):
        self.assertFalse(assistant.can_answer('is it connected?'))
        self.assertFalse(assistant.can_answer('hello'))
        self.assertFalse(assistant.can_answer('how do I tune a rule?'))
        self.assertTrue(assistant.can_answer('is fw01 up'))
        self.assertTrue(assistant.can_answer('Is Office 365 sending events?'))
        self.assertTrue(assistant.can_answer('10.0.0.1'))
        self.assertTrue(assistant.can_answer('fw01.corp.local'))


if __name__ == '__main__':
    unittest.main()
