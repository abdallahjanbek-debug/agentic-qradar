"""Health metrics queries: AQL building, units, the disk view and the shared safeguards."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))
try:
    from app import agent, agent_tools, aql_search, chatstore, health_metrics, settings
    from test_aql_search import AqlTestCase
except ImportError as exc:  # run in a venv with the app's wheels, Flask and qpylib
    raise unittest.SkipTest('needs Flask and qpylib: {0}'.format(exc))

GIB = 1024 ** 3
DISK = {'operator': 'in', 'values': ['DiskUsage', 'DiskSpaceUsed', 'DiskSpaceTotal']}


class Build(AqlTestCase):
    def build(self, **request):
        return health_metrics.build(request)

    def test_latest_disk(self):
        aql, mode, columns = self.build(metrics=DISK,
                                        hosts={'operator': 'equals', 'values': ['qradar']})
        self.assertEqual(mode, 'latest')
        self.assertEqual(aql, (
            'SELECT "Hostname" AS "Host", "Element" AS "Element", "Metric ID" AS "Metric", '
            'AVG("Value") AS "Value", COUNT(*) AS "Samples", '
            'DATEFORMAT(MAX(starttime), \'yyyy-MM-dd HH:mm:ss\') AS "Last Sample" FROM events '
            "WHERE qid = 94000001 AND \"Metric ID\" IN ('DiskUsage', 'DiskSpaceUsed', "
            "'DiskSpaceTotal') AND \"Hostname\" = 'qradar' "
            'GROUP BY "Hostname", "Element", "Metric ID" '
            'ORDER BY "Hostname", "Metric ID", "Element" LIMIT 500 LAST 60 MINUTES'))
        self.assertNotIn('docker-data', aql)  # container mounts are included by default
        self.assertEqual(columns, ['Host', 'Element', 'Metric', 'Value', 'Samples',
                                   'Last Sample'])

    def test_latest_without_totals_uses_15_minutes(self):
        aql, _, _ = self.build(metrics={'operator': 'equals', 'values': ['EventRate']})
        self.assertTrue(aql.endswith('LAST 15 MINUTES'))

    def test_exclude_container_mounts_on_request(self):
        aql, _, _ = self.build(metrics=DISK, exclude_container_mounts=True)
        self.assertIn("NOT (\"Element\" ILIKE '/store/docker-data/%' OR ", aql)

    def test_other_modes(self):
        aql, _, columns = self.build(mode='list_metrics')
        self.assertIn('UNIQUECOUNT("Element") AS "Elements"', aql)
        self.assertIn('GROUP BY "Metric ID"', aql)
        aql, _, columns = self.build(mode='summary', time_range={'last_minutes': 120},
                                     metrics={'operator': 'starts_with', 'values': ['EventRate']},
                                     elements={'operator': 'equals', 'values': ['/store']})
        self.assertIn("(\"Metric ID\" ILIKE 'EventRate%')", aql)
        self.assertEqual(columns[3:6], ['Min', 'Avg', 'Max'])
        aql, _, columns = self.build(mode='trend', time_range={'last_minutes': 1440},
                                     metrics={'operator': 'equals', 'values': ['EventRate']})
        self.assertIn("GROUP BY DATEFORMAT(starttime, 'yyyy-MM-dd HH:00'), \"Hostname\"", aql)
        self.assertEqual(columns[0], 'Hour')

    def test_source_ip(self):
        aql, _, columns = self.build(metrics={'operator': 'equals', 'values': ['EventRate']},
                                     source_ips={'operator': 'in_cidr',
                                                 'values': ['192.168.8.0/24']},
                                     group_by=['source_ip'])
        self.assertIn("(INCIDR('192.168.8.0/24', sourceip))", aql)
        self.assertIn('GROUP BY "Hostname", sourceip, "Element"', aql)
        self.assertEqual(columns[1], 'Source IP')

    def test_rejections(self):
        metric = {'operator': 'equals', 'values': ['EventRate']}
        bad = [
            ({}, 'metrics is required'),
            ({'metrics': {'operator': 'contains', 'values': ['x']}}, 'operator'),
            ({'metrics': {'operator': 'equals', 'values': ["x' OR '1'='1"]}}, 'not allowed'),
            ({'metrics': metric, 'mode': 'raw'}, 'mode must be'),
            ({'metrics': metric, 'mode': 'summary'}, 'time_range is required'),
            ({'metrics': metric, 'time_range': {'last_minutes': 1441}}, '24 hours'),
            ({'metrics': metric, 'group_by': ['username']}, 'group_by may only'),
            ({'metrics': metric, 'source_ips': {'operator': 'contains', 'values': ['10']}},
             'source_ips supports'),
            ({'metrics': metric, 'source_ips': {'operator': 'equals', 'values': ['10.0.0.999']}},
             'not a valid IP'),
            ({'metrics': metric, 'exclude_container_mounts': 'yes'}, 'true or false'),
        ]
        for request, message in bad:
            with self.assertRaises(aql_search.SearchError, msg=request) as caught:
                health_metrics.build(request)
            self.assertIn(message, str(caught.exception))

    def test_max_window_follows_settings(self):
        settings.set_config('health_max_window_hours', 48)
        aql, _, _ = self.build(metrics={'operator': 'equals', 'values': ['EventRate']},
                               time_range={'last_minutes': 2880})
        self.assertTrue(aql.endswith('LAST 2880 MINUTES'))


class Units(unittest.TestCase):
    def test_disk_view(self):
        rows = [
            {'Host': 'qradar', 'Element': '/store', 'Metric': 'DiskSpaceUsed',
             'Value': 16 * GIB, 'Last Sample': '2026-11-03 19:40:35'},
            {'Host': 'qradar', 'Element': '/store', 'Metric': 'DiskUsage', 'Value': 0.11,
             'Last Sample': '2026-11-03 19:40:35'},
            {'Host': 'qradar', 'Element': '/', 'Metric': 'DiskSpaceUsed', 'Value': 4 * GIB,
             'Last Sample': '2026-11-03 19:40:35'},
            {'Host': 'qradar', 'Element': '/', 'Metric': 'DiskSpaceTotal', 'Value': 12 * GIB,
             'Last Sample': '2026-11-03 19:10:00'},
        ]
        view, columns = health_metrics._disk_view(rows)
        self.assertEqual(columns, ['Host', 'Partition', 'Used (GiB)', 'Total (GiB)', 'Used %',
                                   'Last Sample'])
        self.assertEqual(view, [
            {'Host': 'qradar', 'Partition': '/', 'Used (GiB)': 4.0, 'Total (GiB)': 12.0,
             'Used %': 33.3, 'Last Sample': '2026-11-03 19:40:35'},
            {'Host': 'qradar', 'Partition': '/store', 'Used (GiB)': 16.0, 'Total (GiB)': 145.45,
             'Used %': 11.0, 'Last Sample': '2026-11-03 19:40:35'},
        ])

    def test_convert(self):
        rows = [{'Metric': 'DiskSpaceUsed', 'Min': GIB, 'Avg': 2 * GIB, 'Max': 3 * GIB,
                 'Samples': 10.0},
                {'Metric': 'DiskUsage', 'Min': 0.1, 'Avg': 0.125, 'Max': 0.15, 'Samples': 10.0},
                {'Metric': 'EventRate', 'Min': 110.59658, 'Avg': 120.0, 'Max': 174.2,
                 'Samples': 60.0}]
        columns = health_metrics._convert(rows, ['Metric', 'Min', 'Avg', 'Max', 'Samples'])
        self.assertEqual(columns[-1], 'Unit')
        self.assertEqual([(r['Avg'], r['Unit'], r['Samples']) for r in rows],
                         [(2.0, 'GiB', 10), (12.5, '%', 10), (120.0, 'EPS', 60)])
        self.assertEqual(rows[2]['Min'], 110.597)

    def test_memory_and_cpu_units(self):
        # Values seen on the test console; used + free KB = deployment total_memory.
        rows = [{'Metric': 'SystemPhysicalMemoryUsed', 'Value': 17686151.778},
                {'Metric': 'SystemPhysicalMemoryFree', 'Value': 2238483.644},
                {'Metric': 'SystemMemoryUsed', 'Value': 71.705},
                {'Metric': 'IdleCpu', 'Value': 89.63},
                {'Metric': 'HeapMemoryUsed', 'Value': 409876306.15},
                {'Metric': 'SomethingNew', 'Value': 5.0}]
        health_metrics._convert(rows, ['Metric', 'Value'])
        self.assertEqual([(r['Value'], r['Unit']) for r in rows], [
            (16.87, 'GiB'), (2.13, 'GiB'), (71.705, '%'), (89.63, '%'), (390.89, 'MiB'),
            (5.0, 'unit unknown')])
        notes = health_metrics._notes(rows)
        self.assertIn('HeapMemoryUsed: reported by several QRadar processes', notes[0])
        self.assertIn('Unit not verified, values shown as reported: SomethingNew.', notes[1])


class Query(AqlTestCase):
    def test_disk_question_end_to_end(self):
        self.fake.rows = [
            {'Host': 'qradar', 'Element': '/store', 'Metric': 'DiskSpaceUsed', 'Value': 8 * GIB,
             'Samples': 10.0, 'Last Sample': '2026-11-03 19:40:35'},
            {'Host': 'qradar', 'Element': '/store', 'Metric': 'DiskUsage', 'Value': 0.5,
             'Samples': 10.0, 'Last Sample': '2026-11-03 19:40:35'},
        ]
        text, is_error = agent_tools.run('query_health_metrics',
                                         {'metrics': DISK}, 'admin')
        self.assertFalse(is_error, text)
        result = __import__('json').loads(text)
        self.assertEqual(result['view'], 'disk')
        self.assertEqual(result['rows'], [{'Host': 'qradar', 'Partition': '/store',
                                           'Used (GiB)': 8.0, 'Total (GiB)': 16.0,
                                           'Used %': 50.0, 'Last Sample': '2026-11-03 19:40:35'}])
        self.assertEqual(self.fake.calls[0][1], 'api/ariel/validators/aql')
        with chatstore._db() as conn:
            self.assertEqual(conn.execute('SELECT status FROM search_audit').fetchone()[0],
                             'completed')
        view = agent._search_view(text, False)
        self.assertEqual(view['title'], 'Health metrics')

    def test_label(self):
        self.assertEqual(
            agent_tools.summarize_call('query_health_metrics',
                                       {'metrics': DISK, 'exclude_container_mounts': True}),
            'Querying health metrics (latest; metrics in DiskUsage, DiskSpaceUsed, '
            'DiskSpaceTotal; without container mounts)')


if __name__ == '__main__':
    unittest.main()
