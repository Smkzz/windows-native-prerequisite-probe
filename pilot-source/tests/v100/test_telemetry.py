"""C-D6: bounded durable telemetry sampling, gaps, retention, overhead."""
from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from localcontrol.v100.telemetry import TelemetrySampler
from tests.v100.fixture import V100Case


class SamplerUnit(unittest.TestCase):
    def _sampler(self, tmp: str, **kwargs) -> TelemetrySampler:
        return TelemetrySampler(Path(tmp), collect=lambda: {'marker': 1}, **kwargs)

    def test_samples_persist_and_ring_bounds(self):
        with tempfile.TemporaryDirectory(prefix='lc-c6-tele-') as tmp:
            sampler = self._sampler(tmp, max_samples=24)
            try:
                for _ in range(30):
                    sampler.sample()
                with sampler.lock:
                    rows = sampler.db.execute('SELECT count(*) FROM telemetry_samples').fetchone()
                self.assertEqual(rows[0], 24)
                status = sampler.status()
                self.assertEqual(status['samples'], 24)
                self.assertIn('overhead_ms', status)
                self.assertGreaterEqual(status['overhead_ms']['p50'], 0)
            finally:
                sampler.close()

    def test_gaps_reported_not_filled(self):
        with tempfile.TemporaryDirectory(prefix='lc-c6-gap-') as tmp:
            sampler = self._sampler(tmp, interval_s=5)
            try:
                base = 1_000_000_000_000
                with sampler.lock:
                    for i, delta in enumerate((0, 5e9, 200e9, 205e9)):
                        sampler.db.execute(
                            'INSERT INTO telemetry_samples(time_ns,utc,payload_json) VALUES(?,?,?)',
                            (base + int(delta), 'u', '{"x":1}'))
                    sampler.db.commit()
                status = sampler.status()
                self.assertEqual(status['gap_count'], 1)
                self.assertEqual(status['gaps'][0]['gap_s'], 195.0)
                self.assertLess(status['coverage_pct'], 20)
            finally:
                sampler.close()

    def test_empty_reports_unknown_not_healthy(self):
        with tempfile.TemporaryDirectory(prefix='lc-c6-empty-') as tmp:
            sampler = self._sampler(tmp)
            try:
                status = sampler.status()
                self.assertEqual(status['state'], 'unknown-no-samples')
                self.assertIsNone(status['coverage_pct'])
            finally:
                sampler.close()

    def test_collect_failure_counted_sample_still_recorded(self):
        with tempfile.TemporaryDirectory(prefix='lc-c6-fail-') as tmp:
            def boom():
                raise RuntimeError('probe failed')
            sampler = TelemetrySampler(Path(tmp), collect=boom)
            try:
                payload = sampler.sample()
                status = sampler.status()
                self.assertEqual(status['collect_failures'], 1)
                self.assertEqual(status['samples'], 1)
                self.assertTrue(payload['collect_error'])
            finally:
                sampler.close()

    def test_boot_count_increments_per_instance(self):
        with tempfile.TemporaryDirectory(prefix='lc-c6-boot-') as tmp:
            first = self._sampler(tmp)
            try:
                self.assertEqual(first.boot_count, 1)
            finally:
                first.close()
            second = self._sampler(tmp)
            try:
                self.assertEqual(second.boot_count, 2)
            finally:
                second.close()


class SamplerIntegration(V100Case):
    def test_telemetry_enabled_by_default_and_in_health(self):
        self.assertIsNotNone(self.facade.v100.telemetry)
        payload = self.facade.v100._telemetry_collect(self.facade._telemetry_probe)
        self.assertIn('missions_by_state', payload)
        self.assertIn('jobs', payload)
        self.assertIn('disk_free_bytes', payload)
        self.assertIn('audit', payload)
        self.assertIn('runtime_instance', payload)
        health = self.facade.v100.health()
        self.assertIn('telemetry', health)
        self.assertIn(health['telemetry']['state'], {'collecting', 'stale'})

    def test_host_probe_isolation(self):
        payload = self.facade.v100._telemetry_collect(lambda: 1 / 0)
        self.assertEqual(payload['host_probe'], 'unknown')
        self.assertIn('missions_by_state', payload)

    def test_telemetry_disabled_option(self):
        self.facade.v100.telemetry.close()
        self.facade.v100.telemetry = None
        health = self.facade.v100.health()
        self.assertEqual(health['telemetry']['state'], 'disabled')
