"""Durable scheduler: queueing, dependencies, retries, recurrences, deadlines, restart."""
from __future__ import annotations

import time

from localcontrol.v100.missions import MissionStore
from localcontrol.v100.scheduler import DurableScheduler
from tests.v100.fixture import V100Case


class SchedulerTests(V100Case):
    def schedule(self, **kwargs):
        args = {'action': 'create', 'objective': 'scheduled mission', 'request_id': 'schedule-create-0001',
                'delay_s': 0, 'max_attempts': 1}
        args.update(kwargs)
        result = self.call('mission_schedule', **args)
        self.assertTrue(result['ok'], result)
        return result['data']

    def due(self, schedule_id):
        with self.facade.v100.store.lock:
            self.facade.v100.store.db.execute('UPDATE schedules SET run_at_ns=1 WHERE schedule_id=?', (schedule_id,))
            self.facade.v100.store.db.commit()

    def test_due_schedule_dispatches_once(self):
        created = self.schedule()
        self.assertTrue(self.facade.v100.scheduler_tick()['actions'], 'expected dispatch')
        status = self.call('mission_schedule', action='status', schedule_id=created['schedule_id'])
        self.assertTrue(status['ok'], status)
        self.assertEqual(status['data']['attempts'], 1)
        self.assertTrue(status['data']['mission_id'])
        self.assertEqual(self.facade.v100.scheduler_tick()['actions'], [])
        mission = self.mission(status['data']['mission_id'])
        self.assertEqual(mission['state'], 'RUNNING')
        self.assertEqual(mission['schedule_id'], created['schedule_id'])

    def test_delayed_schedule_not_dispatched_early(self):
        created = self.schedule(delay_s=3600)
        self.assertEqual(self.facade.v100.scheduler_tick()['actions'], [])
        self.due(created['schedule_id'])
        self.assertTrue(self.facade.v100.scheduler_tick()['actions'])

    def test_dependency_waits_for_success(self):
        first = self.schedule(request_id='schedule-create-0002')
        second = self.schedule(request_id='schedule-create-0003', depends_on=first['schedule_id'])
        self.facade.v100.scheduler_tick()
        status = self.call('mission_schedule', action='status', schedule_id=second['schedule_id'])
        self.assertFalse(status['data']['mission_id'])
        first_mission = self.call('mission_schedule', action='status', schedule_id=first['schedule_id'])['data']
        result = self.finish_mission(first_mission['mission_id'],
                                     self._token(first_mission['mission_id']))
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['data']['state'], 'SUCCEEDED')
        self.assertTrue(self.facade.v100.scheduler_tick()['actions'])
        second_status = self.call('mission_schedule', action='status', schedule_id=second['schedule_id'])
        self.assertTrue(second_status['data']['mission_id'])

    def test_dependency_failure_fails_schedule(self):
        failing = self.schedule(request_id='schedule-create-0006',
                                success_contract={'required_files': [{'path': 'missing-dep.txt'}]})
        dependent = self.schedule(request_id='schedule-create-0007', depends_on=failing['schedule_id'])
        self.facade.v100.scheduler_tick()
        failing_mission = self.call('mission_schedule', action='status', schedule_id=failing['schedule_id'])['data']
        self.finish_mission(failing_mission['mission_id'], self._token(failing_mission['mission_id']),
                            request_id='finish-failing-0001')
        self.facade.v100.scheduler_tick()
        dependent_status = self.call('mission_schedule', action='status', schedule_id=dependent['schedule_id'])
        self.assertEqual(dependent_status['data']['state'], 'FAILED')
        self.assertEqual(dependent_status['data']['last_error'], 'dependency failed')

    def test_retry_with_backoff_then_exhaustion(self):
        created = self.schedule(request_id='schedule-create-0008', max_attempts=2, backoff_base_s=1,
                                success_contract={'required_files': [{'path': 'never.txt'}]})
        self.facade.v100.scheduler_tick()
        first = self.call('mission_schedule', action='status', schedule_id=created['schedule_id'])['data']
        self.finish_mission(first['mission_id'], self._token(first['mission_id']), request_id='finish-retry-0001')
        self.facade.v100.scheduler_tick()
        after = self.call('mission_schedule', action='status', schedule_id=created['schedule_id'])['data']
        self.assertEqual(after['state'], 'ACTIVE')
        self.assertFalse(after['mission_id'])
        self.assertEqual(after['attempts'], 1)
        self.due(created['schedule_id'])
        self.facade.v100.scheduler_tick()
        second = self.call('mission_schedule', action='status', schedule_id=created['schedule_id'])['data']
        self.assertEqual(second['attempts'], 2)
        self.finish_mission(second['mission_id'], self._token(second['mission_id']), request_id='finish-retry-0002')
        self.facade.v100.scheduler_tick()
        final = self.call('mission_schedule', action='status', schedule_id=created['schedule_id'])['data']
        self.assertEqual(final['state'], 'FAILED')
        self.assertEqual(final['last_error'], 'attempts exhausted')

    def test_recurring_reschedules_after_success(self):
        created = self.schedule(request_id='schedule-create-0009', recur_s=3600)
        self.facade.v100.scheduler_tick()
        first = self.call('mission_schedule', action='status', schedule_id=created['schedule_id'])['data']
        self.finish_mission(first['mission_id'], self._token(first['mission_id']), request_id='finish-recur-0001')
        self.facade.v100.scheduler_tick()
        after = self.call('mission_schedule', action='status', schedule_id=created['schedule_id'])['data']
        self.assertEqual(after['state'], 'ACTIVE')
        self.assertEqual(after['attempts'], 0)
        self.assertGreater(after['run_at_ns'], created['run_at_ns'])

    def test_recurring_dispatch_creates_distinct_mission_after_reschedule(self):
        created = self.schedule(request_id='schedule-create-0013', recur_s=3600)
        self.facade.v100.scheduler_tick()
        first = self.call('mission_schedule', action='status', schedule_id=created['schedule_id'])['data']
        self.finish_mission(first['mission_id'], self._token(first['mission_id']), request_id='finish-recur-0013')
        self.facade.v100.scheduler_tick()
        self.due(created['schedule_id'])
        self.facade.v100.scheduler_tick()
        second = self.call('mission_schedule', action='status', schedule_id=created['schedule_id'])['data']
        self.assertNotEqual(second['mission_id'], first['mission_id'])
        self.assertEqual(second['dispatch_generation'], 2)
        with self.facade.v100.store.lock:
            count = self.facade.v100.store.db.execute(
                'SELECT count(*) AS n FROM missions WHERE schedule_id=?',
                (created['schedule_id'],)).fetchone()['n']
        self.assertEqual(count, 2)

    def test_deadline_expires(self):
        created = self.schedule(request_id='schedule-create-0010')
        with self.facade.v100.store.lock:
            self.facade.v100.store.db.execute('UPDATE schedules SET deadline_ns=1, grace_s=0 WHERE schedule_id=?',
                                              (created['schedule_id'],))
            self.facade.v100.store.db.commit()
        self.facade.v100.scheduler_tick()
        status = self.call('mission_schedule', action='status', schedule_id=created['schedule_id'])
        self.assertEqual(status['data']['state'], 'EXPIRED')

    def test_cancel_schedule(self):
        created = self.schedule(request_id='schedule-create-0011', delay_s=3600)
        cancelled = self.call('mission_schedule', action='cancel', schedule_id=created['schedule_id'],
                              reason='not needed', request_id='schedule-cancel-0001')
        self.assertTrue(cancelled['ok'], cancelled)
        self.assertEqual(cancelled['data']['state'], 'CANCELLED')
        self.due(created['schedule_id'])
        self.assertEqual(self.facade.v100.scheduler_tick()['actions'], [])

    def test_restart_does_not_duplicate_dispatch(self):
        created = self.schedule(request_id='schedule-create-0012')
        self.facade.v100.scheduler_tick()
        other_store = MissionStore(self.state, 'runtime-foreign-scheduler')
        other = DurableScheduler(other_store)
        actions = other.tick()['actions']
        other_store.close()
        self.assertEqual(actions, [])
        status = self.call('mission_schedule', action='status', schedule_id=created['schedule_id'])
        self.assertEqual(status['data']['attempts'], 1)

    def _token(self, mission_id: str) -> str:
        with self.facade.v100.store.lock:
            row = self.facade.v100.store.db.execute('SELECT owner_token_sha256 FROM missions WHERE mission_id=?',
                                                    (mission_id,)).fetchone()
        # Tests that need the token hold it from begin; scheduler-created missions need a takeover.
        return self._issue_token(mission_id)

    def _issue_token(self, mission_id: str) -> str:
        import secrets
        from localcontrol.nextlib.core import digest
        token = secrets.token_urlsafe(24)
        with self.facade.v100.store.lock:
            self.facade.v100.store.db.execute('UPDATE missions SET owner_token_sha256=? WHERE mission_id=?',
                                              (digest(token), mission_id))
            self.facade.v100.store.db.commit()
        return token
