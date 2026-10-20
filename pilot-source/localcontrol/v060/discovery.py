from __future__ import annotations
from dataclasses import dataclass
import ntpath
from .core import need, win_abs, strict_child

VENDOR_PARTS=frozenset({"node_modules",".venv","venv","vendor","dist","build","target",".git","__pycache__",".next","coverage"})
STRONG=frozenset({".git","pyproject.toml","package.json","cargo.toml","go.mod","composer.json","pom.xml","build.gradle","build.gradle.kts"})
WEAK=frozenset({"requirements.txt","setup.py","cmakelists.txt","makefile","dockerfile"})

@dataclass(frozen=True)
class DirectoryObservation:
    path: str
    markers: tuple[str,...]
    direct_files: int=0
    direct_dirs: int=0
    def __post_init__(self):
        object.__setattr__(self,"path",win_abs(self.path));need(type(self.markers)is tuple)

@dataclass(frozen=True)
class ProjectCandidate:
    path: str
    score: int
    confidence: str
    markers: tuple[str,...]
    parent_candidate: str|None
    classification: str  # top_level|nested_component|likely_vendor


def _vendor(path:str)->bool:
    return any(p.casefold() in VENDOR_PARTS for p in ntpath.normpath(path).split("\\"))

def classify(observations:list[DirectoryObservation])->list[ProjectCandidate]:
    raw=[]
    for o in observations:
        markers=tuple(sorted({m.casefold() for m in o.markers}))
        strong=sum(m in STRONG or m.endswith('.sln') or m.endswith('.csproj') for m in markers)
        weak=sum(m in WEAK for m in markers)
        score=(6 if '.git' in markers else 0)+3*max(0,strong-('.git' in markers))+weak
        if _vendor(o.path):
            conf='low';classification='likely_vendor'
        elif score>=6: conf='high';classification='top_level'
        elif score>=3: conf='medium';classification='top_level'
        elif score>=1: conf='low';classification='top_level'
        else: continue
        raw.append((o,score,conf,classification,markers))
    raw.sort(key=lambda x:(len(ntpath.normpath(x[0].path).split('\\')),ntpath.normcase(x[0].path)))
    candidates=[]
    for o,score,conf,classification,markers in raw:
        parents=[c for c in candidates if c.classification!='likely_vendor' and strict_child(o.path,c.path)]
        parent=max(parents,key=lambda c:len(c.path)) if parents else None
        if parent and classification!='likely_vendor': classification='nested_component'
        candidates.append(ProjectCandidate(o.path,score,conf,markers,parent.path if parent else None,classification))
    return candidates
