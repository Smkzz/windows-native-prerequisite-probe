from __future__ import annotations
from .core import need, same_or_child, win_abs
from .registry import RegistrySnapshot

def validate_control_plane_isolation(snapshot:RegistrySnapshot, *, runtime_roots:list[str], state_root:str, config_paths:list[str]=())->dict:
    protected=[win_abs(x) for x in runtime_roots]+[win_abs(state_root)]+[win_abs(x) for x in config_paths]
    managed=[w.root for w in snapshot.workspaces]+[c.root for c in snapshot.collections]
    conflicts=[]
    for p in protected:
        for m in managed:
            if same_or_child(p,m) or same_or_child(m,p):conflicts.append({'protected':p,'managed':m})
    need(not conflicts,'CONTROL_PLANE_OVERLAP')
    return {'isolated':True,'protected_count':len(protected),'managed_root_count':len(managed)}
