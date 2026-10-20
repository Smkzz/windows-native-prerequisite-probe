"""C-D6: bounded durable telemetry sampling.

Derived telemetry is incremental and rebuildable: it lives in its own SQLite
database (telemetry.db) so it can never contend with the mandatory audit
chain. Sampling is a small daemon thread; every sample records its own
collection cost so overhead claims are measured, not asserted. Missing
intervals are reported as gaps — never inferred healthy or unhealthy.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

MAX_PAYLOAD_BYTES = 16384
MIN_INTERVAL_S = 5
MAX_INTERVAL_S = 3600
MIN_SAMPLES = 24
MAX_SAMPLES = 100_000


class TelemetrySampler:
    """Periodic bounded sampler with ring retention and loss counters."""

    def __init__(self, state_dir: Path, *, interval_s: int = 60,
                 max_samples: int = 1440, collect=None):
        self.interval_s = min(MAX_INTERVAL_S, max(MIN_INTERVAL_S, int(interval_s)))
        self.max_samples = min(MAX_SAMPLES, max(MIN_SAMPLES, int(max_samples)))
        self._collect = collect or (lambda: {})
        self._dir = Path(state_dir) / 'v100'
        self._dir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self._dir / 'telemetry.db', check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = None
        try:
            with self.lock:
                self.db.execute(
                    'CREATE TABLE IF NOT EXISTS telemetry_samples('
                    'seq INTEGER PRIMARY KEY AUTOINCREMENT, time_ns INTEGER NOT NULL,'
                    'utc TEXT NOT NULL, payload_json TEXT NOT NULL)')
                self.db.execute(
                    'CREATE TABLE IF NOT EXISTS telemetry_meta(key TEXT PRIMARY KEY, value TEXT)')
                boot = int(self._meta_get('boot_count', '0')) + 1
                self.db.execute("INSERT OR REPLACE INTO telemetry_meta(key,value) VALUES('boot_count',?)",
                                (str(boot),))
                self.db.commit()
                self.boot_count = boot
        except BaseException:
            self.db.close()
            raise

    def _meta_get(self, key: str, default: str) -> str:
        row = self.db.execute('SELECT value FROM telemetry_meta WHERE key=?', (key,)).fetchone()
        return row['value'] if row else default

    def _meta_add(self, key: str, delta: int = 1) -> None:
        current = int(self._meta_get(key, '0')) + delta
        self.db.execute('INSERT OR REPLACE INTO telemetry_meta(key,value) VALUES(?,?)',
                        (key, str(current)))

    def close(self) -> None:
        self.stop()
        with self.lock:
            self.db.close()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name='localcontrol-telemetry')
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=10)

    def _loop(self) -> None:
        # Immediate first sample: a baseline exists even if the process dies early.
        self.sample()
        while not self._stop.wait(self.interval_s):
            self.sample()

    def sample(self) -> dict:
        started = time.monotonic()
        try:
            payload = dict(self._collect())
        except Exception:
            payload = {'collect_error': True}
            with self.lock:
                self._meta_add('collect_failures')
                self.db.commit()
        payload['sample_ms'] = round((time.monotonic() - started) * 1000, 3)
        payload['boot_count'] = self.boot_count
        now_ns = time.time_ns()
        utc = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now_ns / 1e9))
        try:
            body = json.dumps(payload, separators=(',', ':'), sort_keys=True,
                              ensure_ascii=True)
            if len(body) > MAX_PAYLOAD_BYTES:
                body = json.dumps({'truncated': True, 'sample_ms': payload['sample_ms'],
                                   'boot_count': self.boot_count},
                                  separators=(',', ':'), sort_keys=True)
        except (TypeError, ValueError):
            body = json.dumps({'unserializable': True, 'boot_count': self.boot_count})
        with self.lock:
            try:
                self.db.execute(
                    'INSERT INTO telemetry_samples(time_ns,utc,payload_json) VALUES(?,?,?)',
                    (now_ns, utc, body))
                # Ring retention: keep only the newest max_samples rows.
                self.db.execute(
                    'DELETE FROM telemetry_samples WHERE seq <= '
                    '(SELECT max(seq) FROM telemetry_samples) - ?', (self.max_samples,))
                self.db.commit()
            except sqlite3.Error:
                self._meta_add('insert_failures')
                try:
                    self.db.commit()
                except sqlite3.Error:
                    pass
        return payload

    def status(self) -> dict:
        """Bounded telemetry report: counts, gaps, coverage, loss counters,
        measured overhead. Gaps are evidence of missing observation, never
        silently filled."""
        with self.lock:
            rows = self.db.execute(
                'SELECT seq,time_ns,payload_json FROM telemetry_samples ORDER BY seq').fetchall()
            meta = {r['key']: r['value'] for r in
                    self.db.execute('SELECT key,value FROM telemetry_meta')}
        count = len(rows)
        result = {'samples': count, 'interval_s': self.interval_s,
                  'max_samples': self.max_samples,
                  'boot_count': self.boot_count,
                  'collect_failures': int(meta.get('collect_failures', '0')),
                  'insert_failures': int(meta.get('insert_failures', '0')),
                  'gaps': [], 'coverage_pct': None, 'state': 'unknown-no-samples'}
        if not rows:
            return result
        first_ns, last_ns = rows[0]['time_ns'], rows[-1]['time_ns']
        result['first_time_ns'] = first_ns
        result['last_time_ns'] = last_ns
        result['last_utc'] = self.db and time.strftime(
            '%Y-%m-%dT%H:%M:%SZ', time.gmtime(last_ns / 1e9))
        gap_threshold = int(self.interval_s * 2.5 * 1e9)
        gaps = []
        prev = first_ns
        for row in rows[1:]:
            delta = row['time_ns'] - prev
            if delta > gap_threshold:
                gaps.append({'after_time_ns': prev, 'gap_s': round(delta / 1e9, 1)})
            prev = row['time_ns']
        result['gaps'] = gaps[:64]
        result['gap_count'] = len(gaps)
        span_s = max(0.0, (last_ns - first_ns) / 1e9)
        expected = max(1, int(span_s / self.interval_s) + 1)
        result['coverage_pct'] = round(100.0 * count / expected, 1)
        # Measured overhead: sample_ms percentiles from stored payloads.
        costs = []
        for row in rows[-512:]:
            try:
                costs.append(json.loads(row['payload_json']).get('sample_ms', 0.0))
            except (TypeError, ValueError):
                pass
        costs.sort()
        if costs:
            result['overhead_ms'] = {
                'p50': costs[len(costs) // 2],
                'p95': costs[min(len(costs) - 1, int(len(costs) * 0.95))],
                'max': costs[-1], 'n': len(costs)}
        age_s = (time.time_ns() - last_ns) / 1e9
        result['state'] = 'stale' if age_s > self.interval_s * 2.5 else 'collecting'
        result['last_sample_age_s'] = round(age_s, 1)
        return result
