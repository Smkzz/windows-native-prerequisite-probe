"""Test double ONLY. Not a production filesystem implementation or upstream benchmark."""
from pathlib import Path
from localcontrol.errors import ControlError

class FakeBackend:
    def __init__(self):
        self.calls=[]
    async def call(self,project,tool,args):
        self.calls.append((project,tool,args.copy()))
        p=Path(args['path'])
        if tool=='read':
            text=p.read_bytes().decode('utf-8-sig')
            if 'range' in args:
                a,b=args['range']; text=''.join(text.splitlines(keepends=True)[a-1:b])
            return {'content':text,'truncated':False,'bytes_returned':len(text.encode()),'lines_returned':len(text.splitlines())}
        if tool=='write':
            if p.exists() and not args['overwrite']: raise ControlError('EEXIST','exists')
            created=not p.exists(); p.write_bytes(args['content'].encode('utf-8'))
            return {'bytes_written':p.stat().st_size,'created':created}
        if tool=='edit_file':
            text=p.read_bytes().decode(); e=args['edits'][0]
            if text.count(e['old_str'])!=e['expected_count']: raise ControlError('EUNIQUE','count mismatch')
            new=text.replace(e['old_str'],e['new_str'])
            if not args['dry_run']: p.write_bytes(new.encode())
            return {'dry_run':args['dry_run']}
        if tool=='list':
            return {'entries':[{'name':x.name,'path':str(x),'is_dir':x.is_dir(),'size':x.stat().st_size if x.is_file() else 0} for x in sorted(p.iterdir())]}
        raise AssertionError(tool)
