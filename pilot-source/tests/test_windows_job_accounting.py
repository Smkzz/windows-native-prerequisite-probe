import os
import subprocess
import sys
import time
import unittest
from unittest import mock

from localcontrol.jobs import _accounting_exception, _resource_usage
from localcontrol.windows_job import WindowsJob, _usage_from_windows_stats


class WindowsJobAccountingTests(unittest.TestCase):
    def test_usage_converts_job_counters_to_supervisor_fields(self):
        stats = {
            'cpu_user_ns': 1_234_500,
            'cpu_kernel_ns': 765_500,
            'job_peak_memory_bytes': 8192,
            'peak_memory_bytes': 4096,
            'write_transfer_bytes': 12345,
        }

        self.assertEqual(_usage_from_windows_stats(stats), {
            'cpu_ms': 2,
            'memory_bytes': 8192,
            'disk_bytes': 12345,
        })

    def test_usage_falls_back_to_existing_peak_memory_field(self):
        self.assertEqual(_usage_from_windows_stats({
            'cpu_user_ns': 10_000_000,
            'cpu_kernel_ns': 0,
            'peak_memory_bytes': 4096,
            'write_transfer_bytes': 0,
        })['memory_bytes'], 4096)

    def test_unavailable_counters_are_none_not_synthesized(self):
        usage = _usage_from_windows_stats({
            'cpu_user_ns': None,
            'cpu_kernel_ns': 100,
            'job_peak_memory_bytes': None,
            'peak_memory_bytes': None,
            'write_transfer_bytes': None,
        })

        self.assertEqual(usage, {'cpu_ms': None, 'memory_bytes': None, 'disk_bytes': None})

    def test_job_record_adds_usage_without_removing_existing_fields(self):
        record = {'status': 'completed', 'stdout_bytes': 7}
        result = _resource_usage(record, {
            'cpu_user_ns': 2_000_000,
            'cpu_kernel_ns': 1_000_000,
            'job_peak_memory_bytes': 2048,
            'write_transfer_bytes': 99,
        })

        self.assertEqual(result['cpu_ms'], 3)
        self.assertEqual(result['memory_bytes'], 2048)
        self.assertEqual(result['disk_bytes'], 99)
        self.assertEqual(result['resource_limit_state']['cpu_ms'], 3)
        self.assertEqual(result['resource_limit_state']['memory_bytes'], 2048)
        self.assertEqual(result['resource_limit_state']['disk_bytes'], 99)
        self.assertEqual(result['stdout_bytes'], 7)

    def test_accounting_exception_is_fail_closed(self):
        snap = _accounting_exception()
        self.assertFalse(snap['available'])
        self.assertFalse(snap['accounting_available'])
        self.assertEqual(snap['limit_breach'], 'monitoring_unavailable')
        self.assertEqual(snap['completion_port_error'], 'accounting_exception')
        self.assertIsNone(snap['active_processes'])
        self.assertIsNone(snap['total_processes'])
        self.assertIsNone(snap['terminated_processes'])

    @unittest.skipUnless(os.name == 'nt', 'Windows Job Objects only')
    def test_stats_reports_completion_port_and_process_counts(self):
        job = WindowsJob({'max_processes': 8})
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import time; time.sleep(2)'],
            creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            job.assign(proc)
            deadline = time.time() + 10
            stats = {}
            while time.time() < deadline:
                stats = job.stats()
                if stats.get('active_processes'):
                    break
                time.sleep(0.1)
            self.assertTrue(stats.get('accounting_available'), stats)
            self.assertIsNotNone(stats.get('active_processes'))
            self.assertIn('completion_port_available', stats)
            self.assertIn('completion_port_delivery_guaranteed', stats)
            self.assertIn('job_tree_event_counts', stats)
            self.assertIn('terminated_processes', stats)
        finally:
            try:
                proc.kill()
            except OSError:
                pass
            job.close()

    @unittest.skipUnless(os.name == 'nt', 'Windows Job Objects only')
    def test_stats_api_error_raises_and_caller_snapshot_fails_closed(self):
        # WindowsJob.stats() propagates API errors; the jobs layer persists the
        # shared sanitized snapshot so a broken query can never look like an
        # empty process tree.
        job = WindowsJob({'max_processes': 8})
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import time; time.sleep(2)'],
            creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            job.assign(proc)
            original = job.k.QueryInformationJobObject
            job.k.QueryInformationJobObject = mock.Mock(
                side_effect=RuntimeError('boom'))
            try:
                with self.assertRaises(RuntimeError):
                    job.stats()
            finally:
                job.k.QueryInformationJobObject = original
            snap = _accounting_exception()
            self.assertEqual(snap['limit_breach'], 'monitoring_unavailable')
            self.assertIsNone(snap['active_processes'])
        finally:
            try:
                proc.kill()
            except OSError:
                pass
            job.close()


if __name__ == '__main__':
    unittest.main()
