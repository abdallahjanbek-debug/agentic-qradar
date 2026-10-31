"""Bulk Excel check. Needs openpyxl and the app package importable (Flask + qpylib)."""

import io
import os
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))
try:
    from openpyxl import Workbook, load_workbook
    from app import bulk
except ImportError as exc:  # run in a venv with the app's wheels, Flask and qpylib
    raise unittest.SkipTest('needs openpyxl, Flask and qpylib: {0}'.format(exc))
from test_logsources import NOW, SOURCES, source  # noqa: E402


def xlsx(rows):
    workbook = Workbook()
    for row in rows:
        workbook.active.append(row)
        for cell in workbook.active[workbook.active.max_row]:
            if isinstance(cell.value, str):
                cell.data_type = 's'  # text that looks like a formula stays text
    out = io.BytesIO()
    workbook.save(out)
    return out.getvalue()


class ReadTargets(unittest.TestCase):
    def test_ip_and_hostname_with_header(self):
        targets = bulk.read_targets(xlsx([['IP', 'Hostname'], ['10.0.0.1', 'fw01.corp.local']]))
        self.assertEqual(targets, [{'row': 2, 'ip': '10.0.0.1', 'hostname': 'fw01.corp.local'}])

    def test_ip_only_and_hostname_only_columns(self):
        self.assertEqual([t['ip'] for t in bulk.read_targets(xlsx([['10.0.0.1'], ['10.0.0.10']]))],
                         ['10.0.0.1', '10.0.0.10'])
        self.assertEqual([t['hostname'] for t in bulk.read_targets(xlsx([['Host'], ['okta']]))],
                         ['okta'])

    def test_swapped_columns_and_gaps(self):
        targets = bulk.read_targets(xlsx([['fw01', '10.0.0.1'], [None, None], [None, 'dc01']]))
        self.assertEqual([(t['row'], t['ip'], t['hostname']) for t in targets],
                         [(1, '10.0.0.1', 'fw01'), (3, '', 'dc01')])

    def test_numbers_become_text(self):
        self.assertEqual(bulk.read_targets(xlsx([[12345.0]]))[0]['hostname'], '12345')

    def test_empty_and_invalid_files(self):
        with self.assertRaises(bulk.BulkError):
            bulk.read_targets(xlsx([['IP', 'Hostname']]))
        with self.assertRaises(bulk.BulkError):
            bulk.read_targets(b'not a spreadsheet')

    def test_row_limit(self):
        original = bulk.MAX_ROWS
        bulk.MAX_ROWS = 3
        try:
            with self.assertRaises(bulk.BulkError):
                bulk.read_targets(xlsx([['10.0.0.{0}'.format(i)] for i in range(1, 6)]))
        finally:
            bulk.MAX_ROWS = original


class CheckAndWorkbook(unittest.TestCase):
    def setUp(self):
        self.targets = bulk.read_targets(xlsx([
            ['IP', 'Hostname'],
            ['10.0.0.1', ''],                # connected
            ['', 'fw01.corp.local'],         # silent
            ['10.0.0.10', 'okta.example.com'],  # disabled + never
            ['192.168.99.99', 'ghost.local'],   # not found
        ]))

    def test_counts(self):
        result = bulk.check(self.targets, SOURCES, NOW)
        self.assertEqual(result['counts'], {'targets': 4, 'connected': 1, 'not_connected': 2,
                                            'not_found': 1})
        self.assertEqual([t['ip'] for t in result['not_found']], ['192.168.99.99'])

    def test_workbook_sheets(self):
        result = bulk.check(self.targets, SOURCES, NOW)
        book = load_workbook(io.BytesIO(bulk.build_workbook(result, 'hosts.xlsx', NOW)))
        self.assertEqual(book.sheetnames, ['Summary', 'Connected', 'Not connected', 'Not found'])
        connected = [row for row in book['Connected'].iter_rows(min_row=2, values_only=True)]
        self.assertEqual([(r[0], r[3], r[6]) for r in connected],
                         [(2, 'FortiGate @ 10.0.0.1', 'Receiving events')])
        others = sorted(r[3] for r in book['Not connected'].iter_rows(min_row=2, values_only=True))
        self.assertEqual(others, ['Okta', 'Old DC', 'fw01.corp.local'])
        self.assertEqual(list(book['Not found'].iter_rows(min_row=2, values_only=True)),
                         [(5, '192.168.99.99', 'ghost.local')])

    def test_text_never_becomes_a_formula(self):
        evil = source('=HYPERLINK("http://evil.example","click")', 'Syslog', '10.9.9.9')
        targets = bulk.read_targets(xlsx([['10.9.9.9', '=1+1']]))
        result = bulk.check(targets, SOURCES + [evil], NOW)
        data = bulk.build_workbook(result, '=cmd.xlsx', NOW)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            sheets = [archive.read(n) for n in archive.namelist() if n.startswith('xl/worksheets/')]
        self.assertFalse(any(b'<f>' in sheet for sheet in sheets))
        row = next(load_workbook(io.BytesIO(data))['Connected'].iter_rows(min_row=2,
                                                                          values_only=True))
        self.assertEqual(row[2], '=1+1')
        self.assertTrue(row[3].startswith('=HYPERLINK'))

    def test_template_round_trip(self):
        targets = bulk.read_targets(bulk.template_workbook())
        self.assertEqual([(t['ip'], t['hostname']) for t in targets],
                         [('10.1.2.3', 'fw01.example.local'), ('10.1.2.4', ''),
                          ('', 'dc01.example.local')])


if __name__ == '__main__':
    unittest.main()
