"""Pinned metadata-only Windows project discovery helper.

This is a trusted local adapter, not arbitrary MCP filesystem access. It accepts
only operator-configured roots, never reads file contents, never follows reparse
points, and returns only directories that contain recognized project markers.
"""
from __future__ import annotations
import os,time
from pathlib import Path
from .core import need,win_abs
from .discovery import DirectoryObservation,VENDOR_PARTS

MARKER_NAMES=frozenset({'.git','pyproject.toml','package.json','cargo.toml','go.mod','composer.json','pom.xml','build.gradle','build.gradle.kts','requirements.txt','setup.py','cmakelists.txt','makefile','dockerfile'})
SYSTEM_SKIP=frozenset({'windows','program files','program files (x86)','programdata','$recycle.bin','system volume information','recovery'})
SENSITIVE_SKIP=frozenset({'.ssh','.aws','.azure','.gnupg','.codex','appdata'})

def should_skip_dir(name:str,depth:int)->bool:
    n=name.casefold()
    return n in VENDOR_PARTS or n in SENSITIVE_SKIP or (depth==0 and n in SYSTEM_SKIP)

def discover(operator_roots:tuple[str,...],*,max_depth:int=6,max_dirs:int=50000,deadline_s:int=60)->dict:
    need(os.name=='nt','PLATFORM_UNSUPPORTED');need(isinstance(operator_roots,tuple) and 1<=len(operator_roots)<=16,'INVALID_ROOTS')
    roots=tuple(win_abs(x) for x in operator_roots);need(type(max_depth)is int and 1<=max_depth<=12,'INVALID_LIMIT');need(type(max_dirs)is int and 1<=max_dirs<=250000,'INVALID_LIMIT')
    deadline=time.monotonic()+deadline_s;visited=0;observations=[];skipped=0;errors=0;queue=[(r,0) for r in roots]
    while queue and visited<max_dirs and time.monotonic()<deadline:
        directory,depth=queue.pop();visited+=1;markers=[];children=[]
        try:
            with os.scandir(directory) as it:
                for d in it:
                    try:
                        st=d.stat(follow_symlinks=False);attrs=getattr(st,'st_file_attributes',0)
                        if attrs&0x400:skipped+=1;continue
                        if d.is_dir(follow_symlinks=False):
                            if depth<max_depth and not should_skip_dir(d.name,depth):children.append(d.path)
                        elif d.is_file(follow_symlinks=False):
                            n=d.name.casefold()
                            if n in MARKER_NAMES or n.endswith('.sln') or n.endswith('.csproj'):markers.append(d.name)
                    except OSError:errors+=1
        except (PermissionError,OSError):errors+=1;continue
        if markers:observations.append(DirectoryObservation(directory,tuple(markers),direct_dirs=len(children)))
        queue.extend((x,depth+1) for x in children)
    from .discovery import classify
    candidates=classify(observations)
    return {'candidates':[c.__dict__ for c in candidates if c.classification!='likely_vendor'],
            'visited_dirs':visited,'skipped_reparse_or_vendor':skipped,'errors':errors,
            'truncated':bool(queue or visited>=max_dirs or time.monotonic()>=deadline),
            'content_read':False,'operator_roots':list(roots)}
