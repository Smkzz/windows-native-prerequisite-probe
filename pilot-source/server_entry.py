"""Runner-only bootstrap for the unchanged LocalControl stdio server."""
import os
from pathlib import Path
import re
import site
import sys

def boot(config):
    config = Path(config)
    root = config.parent.parent
    if re.fullmatch(r"C:\\LocalControlRegressionMcp-[a-f0-9]{32}", str(root)) is None:
        raise RuntimeError("FIXED_RUNNER_ROOT_REQUIRED")
    if config != root / "control" / "mcp.json":
        raise RuntimeError("FIXED_CONFIG_REQUIRED")
    for path in (root, root / "venv" / "Lib" / "site-packages", Path(__file__).resolve()):
        for part in (path, *path.parents):
            if part.exists() and part.lstat().st_file_attributes & 0x400:
                raise RuntimeError("REPARSE_INPUT_REFUSED")
    site.addsitedir(str(root / "venv" / "Lib" / "site-packages"))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from localcontrol.server import main
    sys.argv = [str(Path(__file__)), "--config", str(config)]
    main()

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--config":
        raise RuntimeError("FIXED_SERVER_ARGUMENTS_REQUIRED")
    boot(sys.argv[2])
