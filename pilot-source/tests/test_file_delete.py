from __future__ import annotations
import asyncio, hashlib, os, tempfile, unittest
from pathlib import Path
from localcontrol.facade import Facade
from localcontrol.policy import Policy, Project
from localcontrol.server import SCHEMAS
from tests.fake_backend import FakeBackend

class FileDelete(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='localcontrol-delete-')
        self.root=Path(self.tmp.name).resolve(); self.p=self.root/'p'; self.p.mkdir(); self.ro=self.root/'ro'; self.ro.mkdir()
        self.f=Facade(Policy({'p':Project(self.p,True),'ro':Project(self.ro,False)},self.root/'state'),FakeBackend())
    def tearDown(self): self.f.close(); self.tmp.cleanup()
    def call(self,tool='file_delete',project='p',**args): return asyncio.run(self.f.call(tool,project,args))
    def err(self,code,r): self.assertFalse(r['ok'],r); self.assertEqual(r['error']['code'],code,r)
    def make(self,name='x',text='one'):
        q=self.p/name; q.write_text(text); return q,hashlib.sha256(q.read_bytes()).hexdigest()
    def test_schema(self):
        self.assertIn('file_delete',SCHEMAS); _,props,required=SCHEMAS['file_delete']
        self.assertEqual(set(props),{'path','expected_sha256','request_id'}); self.assertEqual(required,['path','expected_sha256','request_id'])
    def test_success_and_replay(self):
        q,h=self.make(); a=self.call(path='x',expected_sha256=h,request_id='delete-001'); b=self.call(path='x',expected_sha256=h,request_id='delete-001')
        self.assertTrue(a['ok'],a); self.assertTrue(b['replayed']); self.assertFalse(q.exists()); self.assertEqual(a['data']['previous_sha256'],h)
    def test_stale_and_missing(self):
        q,h=self.make(); q.write_text('two'); self.err('CONFLICT',self.call(path='x',expected_sha256=h,request_id='delete-002')); self.assertTrue(q.exists())
        self.err('NOT_FOUND',self.call(path='missing',expected_sha256='0'*64,request_id='delete-003'))
    def test_absent_not_valid_precondition(self):
        q,_=self.make(); self.err('PRECONDITION_REQUIRED',self.call(path='x',expected_sha256='absent',request_id='delete-004')); self.assertTrue(q.exists())
    def test_directory_and_read_only(self):
        d=self.p/'d'; d.mkdir(); self.err('NOT_FILE',self.call(path='d',expected_sha256='0'*64,request_id='delete-005')); self.assertTrue(d.exists())
        q=self.ro/'x'; q.write_text('x'); h=hashlib.sha256(q.read_bytes()).hexdigest(); self.err('READ_ONLY',self.call(project='ro',path='x',expected_sha256=h,request_id='delete-006')); self.assertTrue(q.exists())
    def test_protected_and_hardlink(self):
        q=self.p/'.env'; q.write_text('secret'); h=hashlib.sha256(q.read_bytes()).hexdigest(); self.err('PROTECTED_PATH',self.call(path='.env',expected_sha256=h,request_id='delete-007')); self.assertTrue(q.exists())
        original=self.ro/'origin'; original.write_text('sentinel'); link=self.p/'link'; os.link(original,link); h=hashlib.sha256(original.read_bytes()).hexdigest(); self.err('HARDLINK_FORBIDDEN',self.call(path='link',expected_sha256=h,request_id='delete-008')); self.assertTrue(link.exists())
    def test_concurrent_same_request(self):
        q,h=self.make()
        async def run(): return await asyncio.gather(*[self.f.call('file_delete','p',{'path':'x','expected_sha256':h,'request_id':'delete-race'}) for _ in range(20)])
        r=asyncio.run(run()); self.assertTrue(all(x['ok'] for x in r),r); self.assertEqual(sum(not x.get('replayed',False) for x in r),1); self.assertFalse(q.exists())
if __name__=='__main__': unittest.main(verbosity=2)
