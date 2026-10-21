import os,pytest
from localcontrol.v060.windows_move import _extended,WindowsMoveAdapter
from localcontrol.v060.core import Rejected

def test_extended_prefix_internal_only():assert _extended(r'C:\Projects\A')==r'\\?\C:\Projects\A'

def test_windows_adapter_refuses_non_windows():
    if os.name!='nt':
        with pytest.raises(Rejected) as e:WindowsMoveAdapter()
        assert e.value.code=='PLATFORM_UNSUPPORTED'
