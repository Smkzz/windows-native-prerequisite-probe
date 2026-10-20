"""Private job trampoline. No requested command runs before the parent owns us.

Byte-at-a-time handshake avoids stealing bytes intended for the command's stdin.
On Windows the parent associates this trampoline with an unnamed Job Object
BEFORE transmitting this handshake. Normal child processes inherit that job.
"""
import json
import os
import subprocess
import sys


def main():
    raw = bytearray()
    while len(raw) <= 131072:
        b = os.read(0, 1)
        if not b:
            return 125
        if b == b'\n':
            break
        raw.extend(b)
    else:
        return 125
    try:
        spec = json.loads(raw)
        # A console-less parent does not pass CREATE_NO_WINDOW to children.
        # Give the command a hidden console for ordinary descendants to inherit.
        # This controls desktop presentation, not privileges or sandbox isolation.
        options = {}
        if os.name == 'nt':
            startup = subprocess.STARTUPINFO()
            startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startup.wShowWindow = subprocess.SW_HIDE
            options = {'creationflags': subprocess.CREATE_NEW_CONSOLE,
                       'startupinfo': startup}
        child = subprocess.Popen(spec['argv'], cwd=spec['cwd'], env=spec['env'],
                                 stdin=0, stdout=1, stderr=2, shell=False, **options)
        code = child.wait()
        return code if 0 <= code <= 255 else 124
    except Exception:
        # Never echo a command, environment, credential, or arbitrary exception.
        os.write(2, b'LocalControl: requested executable failed to start\n')
        return 126


if __name__ == '__main__':
    sys.exit(main())
