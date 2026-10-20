"""Pure registry editor for the LOCAL operator process. This module is not imported by MCP server code."""
from __future__ import annotations
from dataclasses import replace
from .core import need
from .registry import RegistrySnapshot,Workspace,Collection
from .isolation import validate_control_plane_isolation

class RegistryEditor:
    def __init__(self,snapshot:RegistrySnapshot):self.current=snapshot
    def _next(self,workspaces,collections):return RegistrySnapshot(self.current.revision+1,tuple(workspaces),tuple(collections))
    def add_workspace(self,w:Workspace)->RegistrySnapshot:
        need(all(x.name.casefold()!=w.name.casefold() for x in (*self.current.workspaces,*self.current.collections)),'DUPLICATE_NAME')
        return self._next((*self.current.workspaces,w),self.current.collections)
    def remove_workspace(self,name:str)->RegistrySnapshot:
        kept=tuple(x for x in self.current.workspaces if x.name.casefold()!=name.casefold());need(len(kept)!=len(self.current.workspaces),'UNKNOWN_WORKSPACE')
        return self._next(kept,self.current.collections)
    def add_collection(self,c:Collection)->RegistrySnapshot:
        need(all(x.name.casefold()!=c.name.casefold() for x in (*self.current.workspaces,*self.current.collections)),'DUPLICATE_NAME')
        return self._next(self.current.workspaces,(*self.current.collections,c))
    def remove_collection(self,name:str)->RegistrySnapshot:
        kept=tuple(x for x in self.current.collections if x.name.casefold()!=name.casefold());need(len(kept)!=len(self.current.collections),'UNKNOWN_COLLECTION')
        return self._next(self.current.workspaces,kept)

def validate_publish(candidate:RegistrySnapshot,*,runtime_roots:list[str],state_root:str,config_paths:list[str]=(),
                     unresolved_moves:list[dict]|tuple[dict,...]=())->dict:
    need(isinstance(unresolved_moves,(list,tuple)),'INVALID_MOVE_STATE')
    need(not unresolved_moves,'UNRESOLVED_MOVE')
    isolation=validate_control_plane_isolation(candidate,runtime_roots=runtime_roots,state_root=state_root,config_paths=config_paths)
    return {'publishable':True,'revision':candidate.revision,'registry_sha256':candidate.sha256,'isolation':isolation,
            'unresolved_moves':0}
