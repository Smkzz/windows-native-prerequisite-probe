"""Bounded relocation-risk scanner for an already authorized project tree.

Never follows reparse points and never reads known credential/secret files. The
full TreeSnapshot fingerprint is the staleness guard; these findings are only
functional relocation evidence (absolute paths, Git worktrees, venvs, etc.).
"""
from __future__ import annotations
import hashlib, ntpath, os, time
from pathlib import Path
from .core import Rejected, digest, need, same_or_child, win_abs
from .migration import Entry, Risk, TreeSnapshot, scan_reparse_risks, scan_structural_risks, scan_text_risks

_REPARSE=0x400

_SECRET_NAMES={'.env','.npmrc','.pypirc','.netrc','.git-credentials','credentials','id_rsa','id_ed25519'}
_TEXT_NAMES={'.git','pyvenv.cfg','package.json','package-lock.json','pnpm-lock.yaml','yarn.lock','pyproject.toml',
            'requirements.txt','setup.py','setup.cfg','cargo.toml','go.mod','composer.json','pom.xml','build.gradle',
            'build.gradle.kts','cmakelists.txt','makefile','dockerfile','.gitmodules'}
_TEXT_EXT={'.json','.toml','.yaml','.yml','.ini','.cfg','.conf','.properties','.xml','.gradle','.ps1','.cmd','.bat',
           '.sh','.py','.js','.jsx','.ts','.tsx','.mjs','.cjs','.cs','.fs','.vb','.cpp','.c','.h','.hpp','.rs','.go',
           '.java','.kt','.kts','.md','.txt'}

def _secret(name:str)->bool:
    n=name.casefold()
    return n in _SECRET_NAMES or n.startswith('.env.') or n.startswith('credentials.') or n.startswith('id_rsa.') or n.startswith('id_ed25519.')

def _text_candidate(rel:str)->bool:
    name=ntpath.basename(rel).casefold()
    return name in _TEXT_NAMES or Path(name).suffix.casefold() in _TEXT_EXT

def _no_reparse_chain(full:str,root:str)->None:
    full,root=win_abs(full),win_abs(root);need(same_or_child(full,root),'OUTSIDE_AUTHORITY')
    rel=ntpath.relpath(full,root);current=Path(root)
    for candidate in [current]+([] if rel=='.' else [current.joinpath(*rel.replace('/','\\').split('\\')[:i]) for i in range(1,len(rel.replace('/','\\').split('\\'))+1)]):
        try:st=os.lstat(candidate)
        except OSError:raise Rejected('RISK_SCAN_PATH_CHANGED') from None
        need(not (getattr(st,'st_file_attributes',0)&_REPARSE),'RISK_SCAN_REPARSE_ANCESTOR')

def scan_project_risks(snapshot:TreeSnapshot, *, max_files:int=1200, max_file_bytes:int=1_048_576,
                       max_total_bytes:int=16_777_216, deadline_s:int=15)->dict:
    need(snapshot.complete,'INCOMPLETE_SNAPSHOT')
    need(type(max_files)is int and 1<=max_files<=5000,'INVALID_LIMIT')
    need(type(max_file_bytes)is int and 4096<=max_file_bytes<=4_194_304,'INVALID_LIMIT')
    need(type(max_total_bytes)is int and max_file_bytes<=max_total_bytes<=67_108_864,'INVALID_LIMIT')
    need(type(deadline_s)is int and 1<=deadline_s<=60,'INVALID_LIMIT')
    root=win_abs(snapshot.root);deadline=time.monotonic()+deadline_s
    texts=[];evidence=[];sensitive=[];scanned=0;used=0;truncated=False;decode_skipped=0
    entries=sorted(snapshot.entries,key=lambda e:ntpath.normcase(e.relative))
    for e in entries:
        if time.monotonic()>=deadline or scanned>=max_files:
            truncated=True;break
        if e.kind!='file' or not _text_candidate(e.relative):continue
        name=ntpath.basename(e.relative)
        if _secret(name):
            sensitive.append(e.relative);continue
        if e.size>max_file_bytes:
            evidence.append({'path':e.relative,'sha256':None,'size':e.size,'status':'oversize'});continue
        if used+e.size>max_total_bytes:
            truncated=True;break
        full=str(Path(root)/e.relative)
        need(same_or_child(full,root),'OUTSIDE_AUTHORITY');_no_reparse_chain(full,root)
        # Re-open only regular files represented by that snapshot; do not follow links.
        try:
            st=os.lstat(full)
            if getattr(st,'st_file_attributes',0)&0x400:
                truncated=True;continue
            with open(full,'rb') as f:data=f.read(max_file_bytes+1)
        except (OSError,PermissionError):
            evidence.append({'path':e.relative,'sha256':None,'size':e.size,'status':'unreadable'});continue
        if len(data)>max_file_bytes:
            evidence.append({'path':e.relative,'sha256':None,'size':e.size,'status':'grew_oversize'});continue
        scanned+=1;used+=len(data);sha=hashlib.sha256(data).hexdigest()
        try:text=data.decode('utf-8')
        except UnicodeDecodeError:
            decode_skipped+=1;evidence.append({'path':e.relative,'sha256':sha,'size':len(data),'status':'non_utf8'});continue
        texts.append((e.relative,text));evidence.append({'path':e.relative,'sha256':sha,'size':len(data),'status':'scanned'})
    risks=list(scan_structural_risks(entries))+list(scan_reparse_risks(root,entries))+list(scan_text_risks(root,texts))
    if sensitive:
        risks.append(Risk('SENSITIVE_CONFIG_UNSCANNED','warning',sensitive[0],
                          f'{len(sensitive)} sensitive configuration file(s) were deliberately not read; validate application configuration after relocation.'))
    if truncated:
        risks.append(Risk('TEXT_RISK_SCAN_TRUNCATED','warning',None,'Relocation-sensitive text scan hit its bounded budget; additional references may exist.'))
    if any(x['status'] in {'unreadable','oversize','grew_oversize'} for x in evidence):
        risks.append(Risk('TEXT_RISK_SCAN_INCOMPLETE','warning',None,'Some relocation-sensitive files could not be inspected within the safe read bounds.'))
    seen=set();dedup=[]
    for r in risks:
        k=(r.code,r.severity,r.path,r.detail)
        if k not in seen:seen.add(k);dedup.append(r)
    return {'risks':tuple(dedup),'files_scanned':scanned,'bytes_scanned':used,'non_utf8_skipped':decode_skipped,
            'sensitive_files_unread':len(sensitive),'truncated':truncated,'evidence_sha256':digest(evidence)}
