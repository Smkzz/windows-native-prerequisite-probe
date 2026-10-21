"""P7/P8: measured LocalControl telemetry, SHA-only batch reads, usage breakdowns."""
from __future__ import annotations

from tests.v070.fixture import V070Case


class BatchStat(V070Case):
    def test_stat_returns_sha_without_content(self):
        seeded = self.seed('a.txt', 'line one\nline two\n')
        result = self.call('read_batch', requests=[{'path': 'a.txt', 'stat': True},
                                                   {'path': 'missing.txt', 'stat': True}])
        self.assertTrue(result['ok'], result)
        first, second = result['data']['items']
        self.assertTrue(first['stat'])
        self.assertEqual(first['sha256'], seeded['data']['sha256'])
        self.assertNotIn('content', first)
        self.assertFalse(second['ok'])
        self.assertEqual(second['error'], 'NOT_FOUND')

    def test_stat_rejects_conflicting_arguments(self):
        self.seed('a.txt', 'x\n')
        for request in ({'path': 'a.txt', 'stat': True, 'offset': 0},
                        {'path': 'a.txt', 'stat': True, 'previous': 'x'},
                        {'path': 'a.txt', 'stat': 'yes'}):
            self.assert_error('INVALID_ARGUMENT', self.call('read_batch', requests=[request]))

    def test_stat_batch_is_smaller_than_content_batch(self):
        self.seed('big.txt', 'q' * 4000 + '\n')
        content = self.call('read_batch', requests=[{'path': 'big.txt'}])
        stat = self.call('read_batch', requests=[{'path': 'big.txt', 'stat': True}])
        self.assertTrue(content['ok'] and stat['ok'])
        self.assertLess(len(str(stat['data'])), len(str(content['data'])))


class LocalTelemetry(V070Case):
    v060 = False

    def test_efficiency_metrics_reports_measured_calls_and_bytes(self):
        self.call('system_info', '')
        result = self.call('efficiency_metrics')
        self.assertTrue(result['ok'], result)
        local = result['data']['localcontrol']
        self.assertGreaterEqual(local['tool_calls_total'], 1)
        self.assertGreaterEqual(local['tool_response_bytes_total'], 1)
        self.assertIn('system_info', local['calls_by_tool'])
        self.assertIsNone(local['model_tokens'])
        self.assertTrue(result['data']['model_tokens'] is None)
        self.assertIn('never', local['scope'])

    def test_errors_are_counted(self):
        before = self.call('efficiency_metrics')['data']['localcontrol']['tool_errors_total']
        self.assert_error('INVALID_ARGUMENT', self.call('system_info', admin=True))
        after = self.call('efficiency_metrics')['data']['localcontrol']['tool_errors_total']
        self.assertEqual(after, before + 1)


class UsageBreakdown(V070Case):
    def ingest(self, task: str, model: str, input_total: int, cached: int, output: int):
        record = {'schema': 1, 'event_id': f'event-{task}-{model}', 'project': 'pilot', 'task': task,
                  'model': model, 'stage': 'implementation', 'basis': 'per_request', 'finalized': True,
                  'tokens': {'input_total': input_total, 'cached_input': cached,
                             'output_total': output, 'reasoning_output': 1},
                  'evidence_sha256': 'a' * 64, 'adapter': 'test'}
        return self.facade.v060.usage.ingest(record)

    def test_usage_summary_groups_by_task(self):
        self.ingest('task-a', 'model-x', 100, 40, 20)
        self.ingest('task-b', 'model-y', 200, 50, 30)
        result = self.call('usage_summary', '*', task=None)
        self.assertTrue(result['ok'], result)
        by_task = {row['task']: row for row in result['data']['by_task']}
        self.assertEqual(by_task['task-a']['tokens']['uncached_input']['total'], 60)
        self.assertEqual(by_task['task-b']['tokens']['uncached_input']['total'], 150)
        self.assertFalse(result['data']['by_task_truncated'])
        self.assertIsNone(result['data']['estimated_cost'])

    def test_usage_never_claims_inference(self):
        result = self.call('usage_summary', '*')
        self.assertFalse(result['data'].get('inferred_from_tool_bytes', False))
        self.assertIsNone(result['data']['estimated_cost'])
