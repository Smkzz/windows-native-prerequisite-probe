import json
from pathlib import Path
import pytest
from localcontrol.v060.core import Rejected
from localcontrol.v060.registry import Workspace, Collection, RegistrySnapshot, RegistryCodec, RegistryStore

KEY=b'k'*32

def code(exc): return exc.value.code

def test_collection_may_contain_workspace():
    s=RegistrySnapshot(1,(Workspace('ww2',r'C:\Projects\WW2'),),(Collection('projects',r'C:\Projects',True),))
    assert s.revision==1

def test_workspace_overlap_rejected():
    with pytest.raises(Rejected) as e:
        RegistrySnapshot(1,(Workspace('a',r'C:\Projects\A'),Workspace('b',r'C:\Projects\A\B')))
    assert code(e)=='OVERLAPPING_WORKSPACES'

def test_collection_equal_workspace_rejected():
    with pytest.raises(Rejected) as e:
        RegistrySnapshot(1,(Workspace('a',r'C:\Projects'),),(Collection('projects',r'C:\Projects'),))
    assert code(e)=='COLLECTION_EQUALS_WORKSPACE'

def test_maintenance_workspace_cannot_exec():
    with pytest.raises(Rejected) as e: Workspace('m',r'C:\Projects',maintenance=True,exec_enabled=True)
    assert code(e)=='MAINTENANCE_EXEC_FORBIDDEN'

def test_normal_workspace_can_exec(): assert Workspace('a',r'C:\A').exec_enabled

def test_codec_roundtrip():
    s=RegistrySnapshot(3,(Workspace('a',r'C:\A'),),(Collection('p',r'C:\Projects'),))
    c=RegistryCodec(KEY); assert c.decode(c.encode(s))==s

def test_codec_tamper_rejected():
    s=RegistrySnapshot(1,(Workspace('a',r'C:\A'),));c=RegistryCodec(KEY)
    o=json.loads(c.encode(s));o['body']['revision']=2
    with pytest.raises(Rejected) as e:c.decode(json.dumps(o).encode())
    assert code(e)=='REGISTRY_SIGNATURE'

def test_wrong_key_rejected():
    s=RegistrySnapshot(1,(Workspace('a',r'C:\A'),));raw=RegistryCodec(KEY).encode(s)
    with pytest.raises(Rejected) as e:RegistryCodec(b'x'*32).decode(raw)
    assert code(e)=='REGISTRY_SIGNATURE'

def test_store_monotonic_replace(tmp_path):
    p=tmp_path/'registry.json';c=RegistryCodec(KEY);p.write_bytes(c.encode(RegistrySnapshot(1,(Workspace('a',r'C:\A'),))))
    st=RegistryStore(p,c);out=st.replace(1,RegistrySnapshot(2,(Workspace('b',r'C:\B'),)))
    assert out['revision']==2 and st.load().workspaces[0].name=='b'

def test_store_revision_conflict(tmp_path):
    p=tmp_path/'registry.json';c=RegistryCodec(KEY);p.write_bytes(c.encode(RegistrySnapshot(2,(Workspace('a',r'C:\A'),))))
    with pytest.raises(Rejected) as e:RegistryStore(p,c).replace(1,RegistrySnapshot(3,(Workspace('b',r'C:\B'),)))
    assert code(e)=='REVISION_CONFLICT'

def test_store_revision_gap(tmp_path):
    p=tmp_path/'registry.json';c=RegistryCodec(KEY);p.write_bytes(c.encode(RegistrySnapshot(2,(Workspace('a',r'C:\A'),))))
    with pytest.raises(Rejected) as e:RegistryStore(p,c).replace(2,RegistrySnapshot(4,(Workspace('b',r'C:\B'),)))
    assert code(e)=='REVISION_GAP'

def test_duplicate_name_cross_kind_rejected():
    with pytest.raises(Rejected) as e:RegistrySnapshot(1,(Workspace('same',r'C:\A'),),(Collection('SAME',r'C:\P'),))
    assert code(e)=='DUPLICATE_NAME'

def test_unc_workspace_rejected():
    with pytest.raises(Rejected) as e: Workspace('net',r'\\server\share\repo')
    assert code(e)=='LOCAL_DRIVE_REQUIRED'

def test_device_path_rejected():
    with pytest.raises(Rejected): Workspace('dev',r'\\?\C:\Projects')

def test_overlapping_collections_rejected():
    with pytest.raises(Rejected) as e: RegistrySnapshot(1,(),(Collection('a',r'C:\Projects'),Collection('b',r'C:\Projects\Nested')))
    assert code(e)=='OVERLAPPING_COLLECTIONS'

def test_concurrent_publish_only_one_wins(tmp_path):
    import threading
    p=tmp_path/'registry.json';c=RegistryCodec(KEY);p.write_bytes(c.encode(RegistrySnapshot(1,(Workspace('a',r'C:\A'),))))
    st=RegistryStore(p,c);results=[]
    def worker(i):
        try:
            st.replace(1,RegistrySnapshot(2,(Workspace('w'+str(i),fr'C:\W{i}'),)));results.append('ok')
        except Rejected as e:results.append(e.code)
    threads=[threading.Thread(target=worker,args=(i,)) for i in range(8)]
    [t.start() for t in threads];[t.join() for t in threads]
    assert results.count('ok')==1 and results.count('REVISION_CONFLICT')==7

def _publish_process(path,key,index,queue):
    from pathlib import Path
    from localcontrol.v060.registry import RegistryStore,RegistryCodec,RegistrySnapshot,Workspace
    from localcontrol.v060.core import Rejected
    try:
        RegistryStore(Path(path),RegistryCodec(key)).replace(1,RegistrySnapshot(2,(Workspace('p'+str(index),fr'C:\P{index}'),)))
        queue.put('ok')
    except Rejected as e:queue.put(e.code)

def test_cross_process_publish_only_one_wins(tmp_path):
    import multiprocessing as mp
    p=tmp_path/'registry.json';c=RegistryCodec(KEY);p.write_bytes(c.encode(RegistrySnapshot(1,(Workspace('a',r'C:\A'),))))
    ctx=mp.get_context('spawn');q=ctx.Queue();ps=[ctx.Process(target=_publish_process,args=(str(p),KEY,i,q)) for i in range(4)]
    [x.start() for x in ps];[x.join(10) for x in ps];results=[q.get(timeout=2) for _ in ps]
    assert results.count('ok')==1 and results.count('REVISION_CONFLICT')==3
