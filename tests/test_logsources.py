import os
import sys
import unittest

# Import logsources.py on its own: importing the app package needs Flask and qpylib.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
import logsources  # noqa: E402

NOW = 1_800_000_000_000
MIN = 60_000


def source(name, type_='', identifier='', values=(), enabled=True, last=NOW - MIN, eps=1.5,
           internal=False, health='SUCCESS', messages=()):
    return {'id': sum(map(ord, name)), 'name': name, 'description': '', 'type': type_,
            'protocol': 'Syslog', 'identifier': identifier, 'search_values': list(values),
            'parameters': [{'name': 'identifier', 'value': identifier}],
            'enabled': enabled, 'internal': internal, 'last_event_time': last, 'average_eps': eps,
            'collector': 'eventcollector0', 'health': health, 'messages': list(messages)}


SOURCES = [
    source('FortiGate @ 10.0.0.1', 'Fortinet FortiGate Security Gateway', '10.0.0.1'),
    source('fw01.corp.local', 'Cisco ASA', 'fw01.corp.local', last=NOW - 3 * 60 * MIN,
           health='ERROR', messages=['Events have not been received in over 120 minutes.']),
    source('Microsoft 365 - Tenant A', 'Microsoft 365', 'tenant-a', last=NOW - 5 * MIN),
    source('Okta', 'Okta', 'okta.example.com', last=0),
    source('Old DC', 'Microsoft Windows Security Event Log', '10.0.0.10', enabled=False),
    source('Custom Rule Engine-8 :: qradar', 'Custom Rule Engine', '10.0.0.1', last=0,
           internal=True),
]


def search(text):
    parsed = logsources.parse_question(text)
    return sorted(s['name'] for s in SOURCES if logsources.score(s, parsed) > 0)


class ParseQuestion(unittest.TestCase):
    def test_extracts_ip_host_and_terms(self):
        parsed = logsources.parse_question('Is 10.0.0.1 or fw01.corp.local still sending logs?')
        self.assertEqual(parsed['ips'], ['10.0.0.1'])
        self.assertEqual(parsed['hosts'], ['fw01.corp.local'])
        self.assertEqual(parsed['terms'], [])

    def test_keywords_without_stopwords(self):
        self.assertEqual(logsources.parse_question('Is Office 365 connected?')['terms'],
                         ['office', '365'])


class Score(unittest.TestCase):
    def test_ip_does_not_match_longer_ip(self):
        self.assertEqual(search('10.0.0.1'), ['Custom Rule Engine-8 :: qradar',
                                              'FortiGate @ 10.0.0.1'])

    def test_alias_and_terms(self):
        self.assertEqual(search('o365'), ['Microsoft 365 - Tenant A'])
        self.assertEqual(search('microsoft'), ['Microsoft 365 - Tenant A', 'Old DC'])

    def test_short_hostname(self):
        self.assertEqual(search('fw01'), ['fw01.corp.local'])


class MatchTarget(unittest.TestCase):
    def names(self, ip, host):
        return [(s['name'], how) for s, how in logsources.match_target(ip, host, SOURCES)]

    def test_exact_ip_skips_internal(self):
        self.assertEqual(self.names('10.0.0.1', ''), [('FortiGate @ 10.0.0.1', 'IP = identifier')])

    def test_short_hostname(self):
        self.assertEqual(self.names('', 'FW01'), [('fw01.corp.local', 'Short hostname = identifier')])

    def test_fqdn_matches_short_identifier_in_name(self):
        sources = SOURCES + [source('WinCollect @ THINKPAD01', 'WinCollect', 'THINKPAD01')]
        found = logsources.match_target('', 'thinkpad01.corp.local', sources)
        self.assertEqual([s['name'] for s, _ in found], ['WinCollect @ THINKPAD01'])

    def test_ip_and_hostname_both_used(self):
        names = [n for n, _ in self.names('10.0.0.1', 'okta.example.com')]
        self.assertEqual(sorted(names), ['FortiGate @ 10.0.0.1', 'Okta'])

    def test_no_match(self):
        self.assertEqual(self.names('192.168.1.1', 'nothing.local'), [])

    def test_target_status(self):
        self.assertEqual(logsources.target_status(set()), 'not_found')
        self.assertEqual(logsources.target_status({'silent', 'connected'}), 'connected')
        self.assertEqual(logsources.target_status({'never', 'disabled'}), 'not_connected')


class States(unittest.TestCase):
    def test_connection_states(self):
        states = {s['name']: logsources.connection_state(s, NOW) for s in SOURCES}
        self.assertEqual(states['FortiGate @ 10.0.0.1'], 'connected')
        self.assertEqual(states['fw01.corp.local'], 'silent')
        self.assertEqual(states['Okta'], 'never')
        self.assertEqual(states['Old DC'], 'disabled')

    def test_humanize_age(self):
        self.assertEqual(logsources.humanize_age(30_000), 'less than a minute')
        self.assertEqual(logsources.humanize_age(3 * 60 * MIN), '3 h')
        self.assertEqual(logsources.humanize_age(50 * 60 * MIN), '2 days')


if __name__ == '__main__':
    unittest.main()
