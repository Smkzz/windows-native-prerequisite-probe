"""v0.8 fixture: v0.6 maintenance family plus durable telemetry and supervision."""
from __future__ import annotations

from tests.v070.fixture import V070Case


class V080Case(V070Case):
    v080 = True

    def begin_run(self, objective: str = 'qualification run', **kwargs):
        result = self.call('run_begin', objective=objective, request_id=kwargs.pop('request_id', 'run-begin-0001'),
                           **kwargs)
        self.assertTrue(result['ok'], result)
        return result['data']

    def telemetry(self, **kwargs):
        result = self.call('telemetry_summary', '*', **kwargs)
        self.assertTrue(result['ok'], result)
        return result['data']
