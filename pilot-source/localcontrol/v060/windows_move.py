"""Windows-only adapter for v0.6 same-volume project relocation.

Not used on non-Windows hosts. Input paths remain normal drive-letter paths; this
module adds the Win32 extended prefix internally so callers cannot supply device/
UNC namespaces. Reparse entries are recorded but never traversed.
"""
from __future__ import annotations
import ctypes as c
from ctypes import wintypes as w
import os, stat, time, ntpath
from pathlib import Path
from .core import Rejected, need, win_abs, same_or_child, strict_child
from .migration import Entry,TreeSnapshot

FILE_READ_ATTRIBUTES=0x80
FILE_SHARE_READ=0x1;FILE_SHARE_WRITE=0x2;FILE_SHARE_DELETE=0x4
OPEN_EXISTING=3
FILE_FLAG_BACKUP_SEMANTICS=0x02000000
FILE_FLAG_OPEN_REPARSE_POINT=0x00200000
FILE_ATTRIBUTE_REPARSE_POINT=0x400
FILE_ID_INFO_CLASS=18
INVALID_HANDLE_VALUE=c.c_void_p(-1).value

class FILE_ID_128(c.Structure): _fields_=[('Identifier',c.c_ubyte*16)]
class FILE_ID_INFO(c.Structure): _fields_=[('VolumeSerialNumber',c.c_ulonglong),('FileId',FILE_ID_128)]

def _extended(path:str)->str:
    p=win_abs(path)
    return '\\\\?\\' + p

class WindowsMoveAdapter:
    def __init__(self,*,max_entries:int=100000,max_scan_seconds:int=20):
        need(os.name=='nt','PLATFORM_UNSUPPORTED');need(type(max_entries)is int and 1<=max_entries<=1_000_000,'INVALID_LIMIT')
        need(type(max_scan_seconds)is int and 1<=max_scan_seconds<=120,'INVALID_LIMIT')
        self.max_entries,self.max_scan_seconds=max_entries,max_scan_seconds
        k=c.WinDLL('kernel32',use_last_error=True);self.k=k
        self.create=k.CreateFileW;self.create.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE];self.create.restype=w.HANDLE
        self.info=k.GetFileInformationByHandleEx;self.info.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD];self.info.restype=w.BOOL
        self.close=k.CloseHandle;self.close.argtypes=[w.HANDLE];self.close.restype=w.BOOL
        self.move=k.MoveFileExW;self.move.argtypes=[w.LPCWSTR,w.LPCWSTR,w.DWORD];self.move.restype=w.BOOL
    def _assert_no_reparse_chain(self,path:str,authority_root:str,*,include_leaf:bool=True)->None:
        target=win_abs(path);root=win_abs(authority_root);need(same_or_child(target,root),'OUTSIDE_AUTHORITY')
        rel=ntpath.relpath(target,root)
        parts=[] if rel=='.' else rel.replace('/','\\').split('\\')
        candidates=[root]
        current=Path(root)
        for part in parts:
            current=current/part;candidates.append(str(current))
        if not include_leaf and len(candidates)>1:candidates=candidates[:-1]
        for candidate in candidates:
            try: st=os.lstat(_extended(candidate))
            except FileNotFoundError: raise Rejected('PATH_COMPONENT_MISSING') from None
            need(not (getattr(st,'st_file_attributes',0)&FILE_ATTRIBUTE_REPARSE_POINT),'REPARSE_ANCESTOR')
    def validate_paths(self,source:str,destination:str,source_authority_root:str,destination_collection_root:str,*,source_may_be_missing:bool=False)->None:
        source=win_abs(source);destination=win_abs(destination);source_authority_root=win_abs(source_authority_root);destination_collection_root=win_abs(destination_collection_root)
        need(same_or_child(source,source_authority_root),'SOURCE_OUTSIDE_AUTHORITY')
        need(strict_child(destination,destination_collection_root),'DESTINATION_OUTSIDE_COLLECTION')
        if self.exists(source):
            self._assert_no_reparse_chain(source,source_authority_root,include_leaf=True)
        else:
            need(source_may_be_missing,'PATH_COMPONENT_MISSING')
            # An exact source grant may itself have been renamed away. Never follow
            # or recreate it during recovery. If its parent remains inside a wider
            # authority root, validate that surviving chain.
            parent=str(Path(source).parent)
            if same_or_child(parent,source_authority_root):
                self._assert_no_reparse_chain(parent,source_authority_root,include_leaf=True)
        # Before rename validate the destination parent; after rename validate the
        # full destination chain so an attacker cannot substitute a reparse point.
        dcheck=destination if self.exists(destination) else str(Path(destination).parent)
        self._assert_no_reparse_chain(dcheck,destination_collection_root,include_leaf=True)
    def _identity(self,path:str)->tuple[str,str]:
        h=self.create(_extended(path),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,None,OPEN_EXISTING,
                      FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,None)
        if h==INVALID_HANDLE_VALUE:raise c.WinError(c.get_last_error())
        try:
            info=FILE_ID_INFO()
            if not self.info(h,FILE_ID_INFO_CLASS,c.byref(info),c.sizeof(info)):raise c.WinError(c.get_last_error())
            volume=f'{int(info.VolumeSerialNumber):016x}';fid=bytes(info.FileId.Identifier).hex()
            return volume,volume+':'+fid
        finally:self.close(h)
    def exists(self,path:str)->bool:
        try:os.lstat(_extended(path));return True
        except FileNotFoundError:return False
    def parent_volume(self,path:str)->str:
        parent=str(Path(win_abs(path)).parent);return self._identity(parent)[0]
    def snapshot(self,path:str)->TreeSnapshot:
        root=win_abs(path);volume,identity=self._identity(root);deadline=time.monotonic()+self.max_scan_seconds;entries=[]
        stack=[root]
        while stack:
            if len(entries)>=self.max_entries or time.monotonic()>=deadline:
                return TreeSnapshot(root,identity,volume,tuple(entries),complete=False)
            directory=stack.pop()
            with os.scandir(_extended(directory)) as it:
                for d in it:
                    if len(entries)>=self.max_entries or time.monotonic()>=deadline:
                        return TreeSnapshot(root,identity,volume,tuple(entries),complete=False)
                    full=str(Path(directory)/d.name);rel=os.path.relpath(full,root);st=d.stat(follow_symlinks=False)
                    attrs=getattr(st,'st_file_attributes',0);reparse=bool(attrs&FILE_ATTRIBUTE_REPARSE_POINT)
                    fid=f'{int(st.st_dev):x}:{int(st.st_ino):x}'
                    if reparse:
                        
                        try: target=os.readlink(_extended(full))
                        except OSError: target=None
                        entries.append(Entry(rel,'reparse',int(st.st_size),None,fid,target,mtime_ns=int(st.st_mtime_ns)));continue
                    if stat.S_ISDIR(st.st_mode):entries.append(Entry(rel,'dir',0,None,fid,mtime_ns=int(st.st_mtime_ns)));stack.append(full)
                    elif stat.S_ISREG(st.st_mode):entries.append(Entry(rel,'file',int(st.st_size),None,fid,mtime_ns=int(st.st_mtime_ns)))
                    else:raise Rejected('UNSUPPORTED_ENTRY_TYPE')
        return TreeSnapshot(root,identity,volume,tuple(entries),complete=True)
    def rename(self,source:str,destination:str)->None:
        # Flags=0: no replace-existing, no copy fallback, no delayed reboot behavior.
        if not self.move(_extended(source),_extended(destination),0):raise c.WinError(c.get_last_error())
