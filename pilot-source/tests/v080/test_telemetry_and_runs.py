"""v0.8 durable telemetry and supervised-run semantics."""
from __future__ import annotations

from localcontrol.facade import Facade
from localcontrol.v080.telemetry import TelemetryStore
from tests.v080.fixture import V080Case


def restart(case: V080Case) -> Facade:
    """Close the current server instance and rebuild it from disk (real restart)."""
    case.facade.close()
    case.facade = Facade(case.facade.policy, case.facade.backend,
                         v060_options={'enabled': True, 'allowed_usage_adapters': ['test']},
                         v080_options={'enabled': True}, config_path=case.config)
    return case.facade


class TelemetryTests(V080Case):
    def test_operations_are_recorded_and_summarized(self):
        self.call('system_info', '*')
        self.call('file_write', path='a.txt', content='x\n', expected_sha256='absent', request_id='tel-write-0001')
        summary = self.telemetry()
        self.assertGreaterEqual(summary['totals']['operations'], 2)
        self.assertEqual(summary['totals']['errors'], 0)
        self.assertGreater(summary['totals']['request_bytes'], 0)
        self.assertGreater(summary['totals']['response_bytes'], 0)
        self.assertIn('file_write', summary['per_tool'])
        self.assertTrue(summary['integrity'])
        self.assertEqual(summary['schema_version'], 1)
        self.assertIsNone(summary['model_tokens'])

    def test_error_calls_are_classified(self):
        self.assert_error('NOT_FOUND', self.call('file_read', path='missing.txt'))
        summary = self.telemetry(tool='file_read')
        self.assertEqual(summary['totals']['operations'], 1)
        self.assertEqual(summary['totals']['errors'], 1)
        ops = self.call('telemetry_summary', '*', view='operations', tool='file_read')
        self.assertTrue(ops['ok'], ops)
        self.assertEqual(ops['data']['items'][0]['failure_class'], 'not_found')
        self.assertEqual(ops['data']['items'][0]['error_code'], 'NOT_FOUND')

    def test_delta_and_cursor(self):
        self.call('system_info', '*')
        cursor = self.facade.v080.telemetry.latest_sequence()
        self.call('health_status', '*')
        delta = self.call('telemetry_summary', '*', view='delta', after_sequence=cursor)
        self.assertTrue(delta['ok'], delta)
        self.assertEqual(delta['data']['operations'], 1)
        self.assertIn('health_status', delta['data']['per_tool'])
        self.assertEqual(delta['data']['next_sequence'], cursor + 1)

    def test_durable_across_process_restart(self):
        self.call('system_info', '*')
        before = self.telemetry()
        restart(self)
        summary = self.telemetry()
        self.assertEqual(summary['totals']['operations'], before['totals']['operations'] + 1)
        self.assertEqual(summary['totals']['request_bytes'], before['totals']['request_bytes']
                         + summary['per_tool']['telemetry_summary']['request_bytes'])
        self.assertTrue(summary['integrity'])

    def test_malformed_store_fails_closed(self):
        path = self.state / 'v080' / 'bad.sqlite'
        path.write_bytes(b'this is not a database')
        with self.assertRaises(Exception) as raised:
            TelemetryStore(path)
        self.assertEqual(getattr(raised.exception, 'code', None), 'TELEMETRY_CORRUPT')

    def test_run_association(self):
        run = self.begin_run()
        self.call('system_info', 'pilot')
        operations = self.call('telemetry_summary', '*', view='operations', run_id=run['run_id'])
        self.assertTrue(operations['ok'], operations)
        tools = {row['tool'] for row in operations['data']['items']}
        self.assertIn('system_info', tools)
        self.assertEqual(operations['data']['items'][0]['run_id'], run['run_id'])

    def test_summary_and_operations_with_run_filter(self):
        run = self.begin_run()
        self.call('system_info', 'pilot')
        summary = self.call('telemetry_summary', '*', run_id=run['run_id'])
        self.assertTrue(summary['ok'], summary)
        self.assertGreaterEqual(summary['data']['totals']['operations'], 1)
        self.assertIn('system_info', summary['data']['per_tool'])
        status = self.call('run_status', run_id=run['run_id'], include=['telemetry'])
        self.assertTrue(status['ok'], status)
        self.assertEqual(status['data']['telemetry']['scope']['run_id'], run['run_id'])

    def test_compaction_preserves_totals(self):
        store = self.facade.v080.telemetry
        for index in range(40):
            store.record(tool='system_info', category='discovery', start_ns=index * 1000, end_ns=index * 1000 + 500,
                         request_bytes=3, response_bytes=5, status='ok')
        before = store.summary()['totals']
        with store.lock:
            with store._tx():
                store._compact_locked()
        after = store.summary()['totals']
        self.assertEqual(before['operations'], after['operations'])
        self.assertEqual(before['request_bytes'], after['request_bytes'])
        self.assertEqual(before['response_bytes'], after['response_bytes'])
        self.assertEqual(before['errors'], after['errors'])


class RunTests(V080Case):
    def test_context_sections_include_run_and_telemetry(self):
        run = self.begin_run()
        context = self.call('localcontrol_context', '', include=['run', 'telemetry'])
        self.assertTrue(context['ok'], context)
        data = context['data']
        self.assertEqual(data['active_run']['run_id'], run['run_id'])
        self.assertIn('telemetry', data)
        self.assertTrue(data['telemetry']['integrity'])
        self.assertEqual(data['tool_count'], 46)

    def test_capability_parity_46(self):
        names = sorted(self.facade.fields)
        cap = self.call('capabilities', 'pilot', client_observed=names)
        self.assertTrue(cap['ok'], cap)
        self.assertEqual(cap['data']['client_visibility'], 'matches')
        self.assertEqual(len(cap['data']['enabled']), 46)

    def test_run_lifecycle_and_token_rotation(self):
        run = self.begin_run()
        first_token = run['token']
        beat = self.call('run_heartbeat', run_id=run['run_id'], token=first_token, request_id='run-beat-0001',
                         notes={'progress': 'halfway', 'next_action': 'finish tests'})
        self.assertTrue(beat['ok'], beat)
        second_token = beat['data']['token']
        self.assertNotEqual(first_token, second_token)
        stale = self.call('run_heartbeat', run_id=run['run_id'], token=first_token, request_id='run-beat-0002')
        self.assert_error('RUN_TOKEN_INVALID', stale)
        status = self.call('run_status', run_id=run['run_id'])
        self.assertTrue(status['ok'], status)
        self.assertEqual(status['data']['run']['state'], 'active')
        self.assertEqual(status['data']['run']['notes']['progress'], 'halfway')
        self.assertTrue(status['data']['run']['chain_ok'])
        finish = self.call('run_finish', run_id=run['run_id'], token=second_token, state='completed',
                           summary='done', request_id='run-finish-0001')
        self.assertTrue(finish['ok'], finish)
        self.assertEqual(finish['data']['state'], 'completed')
        terminal = self.call('run_status', run_id=run['run_id'])
        self.assertEqual(terminal['data']['run']['state'], 'completed')
        self.assertFalse(terminal['data']['run']['lease_live'])

    def test_interrupted_run_cannot_be_finished_without_resume(self):
        run = self.begin_run()
        token = run['token']
        restart(self)
        status = self.call('run_status', run_id=run['run_id'])
        self.assertEqual(status['data']['run']['state'], 'interrupted')
        refused = self.call('run_finish', run_id=run['run_id'], token=token, state='completed',
                            request_id='run-false-0001')
        self.assert_error('RUN_NOT_ACTIVE', refused)
        resumed = self.call('run_begin', run_id=run['run_id'], request_id='run-resume-0001')
        self.assertTrue(resumed['ok'], resumed)
        self.assertEqual(resumed['data']['state'], 'active')
        self.assertEqual(resumed['data']['previous_state'], 'interrupted')
        finished = self.call('run_finish', run_id=run['run_id'], token=resumed['data']['token'],
                             state='completed', request_id='run-finish-0002')
        self.assertTrue(finished['ok'], finished)

    def test_watched_file_divergence_requires_acceptance(self):
        seeded = self.seed('tracked.txt', 'original\n')
        run = self.begin_run(watch_paths=['tracked.txt'])
        replaced = self.call('file_write', path='tracked.txt', content='changed\n',
                             expected_sha256=seeded['data']['sha256'], request_id='change-0001')
        self.assertTrue(replaced['ok'], replaced)
        refused = self.call('run_begin', run_id=run['run_id'], token=run['token'], request_id='resume-0001')
        self.assert_error('RUN_WORKSPACE_DIVERGED', refused)
        self.assertEqual(refused['error']['details']['classification'], 'files_changed')
        accepted = self.call('run_begin', run_id=run['run_id'], token=run['token'],
                             accept_divergence='files_changed', request_id='resume-0002')
        self.assertTrue(accepted['ok'], accepted)
        self.assertTrue(accepted['data']['resumed'])

    def test_live_lease_blocks_duplicate_begin(self):
        run = self.begin_run()
        duplicate = self.call('run_begin', run_id=run['run_id'], request_id='dup-begin-0001')
        self.assert_error('RUN_ACTIVE', duplicate)

    def test_stale_lease_takeover_after_expiry(self):
        run = self.begin_run(ttl_s=30)
        with self.facade.v080.runs.lock:
            with self.facade.v080.runs._tx():
                self.facade.v080.runs.db.execute('UPDATE runs SET lease_expires_ns=0 WHERE run_id=?',
                                                 (run['run_id'],))
        resumed = self.call('run_begin', run_id=run['run_id'], takeover=True, request_id='takeover-0001')
        self.assertTrue(resumed['ok'], resumed)
        self.assertTrue(resumed['data']['resumed'])

    def test_tampered_event_chain_is_refused(self):
        run = self.begin_run()
        with self.facade.v080.runs.lock:
            with self.facade.v080.runs._tx():
                self.facade.v080.runs.db.execute('UPDATE run_events SET detail=? WHERE run_id=?',
                                                 ('{"evil":true}', run['run_id']))
        status = self.call('run_status', run_id=run['run_id'])
        self.assertTrue(status['ok'], status)
        self.assertFalse(status['data']['run']['chain_ok'])
        refused = self.call('run_begin', run_id=run['run_id'], request_id='tamper-resume-0001')
        self.assert_error('RUN_STATE_TAMPERED', refused)

    def test_invalid_inputs_rejected(self):
        self.assert_error('OBJECTIVE_REQUIRED', self.call('run_begin', request_id='no-objective-0001'))
        self.assert_error('INVALID_ARGUMENT', self.call('run_begin', objective='x', ttl_s=10,
                                                        request_id='bad-ttl-0001'))
        run = self.begin_run()
        self.assert_error('UNKNOWN_RUN', self.call('run_status', run_id='run-' + '1' * 20))
        self.assert_error('INVALID_NOTES', self.call('run_heartbeat', run_id=run['run_id'], token=run['token'],
                                                     notes={'mystery': []}, request_id='bad-notes-0002'))
        self.assert_error('INVALID_RUN_STATE', self.call('run_finish', run_id=run['run_id'], token=run['token'],
                                                         state='active', request_id='bad-state-0001'))
        self.assert_error('INVALID_ARGUMENT', self.call('telemetry_summary', '*', view='everything'))
        self.assert_error('INVALID_ARGUMENT', self.call('telemetry_summary', '*', view='delta'))

