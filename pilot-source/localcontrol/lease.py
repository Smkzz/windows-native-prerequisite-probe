"""One daemon owns a state directory. Never infer ownership from persisted PIDs."""
import os
from pathlib import Path
from .errors import ControlError
from .policy import no_links

class InstanceLease:
    def __init__(self, root: Path):
        root.mkdir(parents=True,exist_ok=True)
        path=root/'owner.lock'
        no_links(path)
        self.fd=os.open(path, os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0), 0o600)
        try:
            if os.fstat(self.fd).st_size==0:
                os.write(self.fd,b'0')
            os.lseek(self.fd,0,os.SEEK_SET)
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(self.fd,msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            os.close(self.fd);self.fd=None
            raise ControlError('STATE_IN_USE','Another LocalControl instance owns this state directory')
    def close(self):
        if self.fd is not None:
            os.close(self.fd);self.fd=None
