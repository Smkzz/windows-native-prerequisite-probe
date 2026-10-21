"""v1.0 fixture: mission runtime, scheduler, verifier and backup/restore."""
from __future__ import annotations

from tests.v080.fixture import V080Case


class V100Case(V080Case):
    v100 = True

    def begin_mission(self, objective: str = 'qualification mission', contract: dict | None = None,
                      budgets: dict | None = None, **kwargs) -> dict:
        args = {'objective': objective, 'request_id': kwargs.pop('request_id', 'mission-begin-0001'),
                'success_contract': contract or {}, 'budgets': budgets or {}}
        args.update(kwargs)
        result = self.call('mission_begin', **args)
        self.assertTrue(result['ok'], result)
        return result['data']

    def finish_mission(self, mission_id: str, token: str, request_id: str = 'mission-finish-0001',
                       summary: str | None = None) -> dict:
        return self.call('mission_finish', mission_id=mission_id, token=token, request_id=request_id,
                         summary=summary)

    def checkpoint(self, mission_id: str, token: str, request_id: str = 'mission-checkpoint-0001',
                   **kwargs) -> dict:
        return self.call('mission_checkpoint', mission_id=mission_id, token=token,
                         request_id=request_id, **kwargs)

    def mission(self, mission_id: str, **kwargs) -> dict:
        result = self.call('mission_status', mission_id=mission_id, **kwargs)
        self.assertTrue(result['ok'], result)
        return result['data']
