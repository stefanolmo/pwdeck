"""Process hardening (Linux). Call `harden()` as early as possible, before any secret is loaded.

* ``prctl(PR_SET_DUMPABLE, 0)``: the kernel refuses ptrace / ``/proc/<pid>/mem`` access from other processes of the SAME user
  (processes running as root are not stopped) and never writes a core dump of this process.
* ``RLIMIT_CORE = 0``: belt and braces against core dumps.

Opt out for debugging with ``PWDECK_ALLOW_DUMP=1`` (gdb, py-spy, strace -p need it).
Not a protection against: root, a kernel exploit, code injected through the environment/launcher (LD_PRELOAD…) or a keylogger.
"""
from __future__ import annotations

import ctypes
import os
import sys

PR_SET_DUMPABLE = 4
PR_GET_DUMPABLE = 3


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def is_dumpable() -> bool | None:
    """True/False, or None if it cannot be determined (not Linux)."""
    if not sys.platform.startswith("linux"):
        return None
    r = _libc().prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)
    return None if r < 0 else bool(r)


def harden() -> dict:
    """Returns a report {'dumpable_disabled': bool, 'core_disabled': bool, 'skipped': str|None}."""
    rep = {"dumpable_disabled": False, "core_disabled": False, "skipped": None}
    if os.environ.get("PWDECK_ALLOW_DUMP"):
        rep["skipped"] = "PWDECK_ALLOW_DUMP is set"
        return rep
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        rep["core_disabled"] = True
    except (ImportError, ValueError, OSError):
        pass
    if sys.platform.startswith("linux"):
        try:
            if _libc().prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0:
                rep["dumpable_disabled"] = is_dumpable() is False
        except (OSError, AttributeError):
            pass
    else:
        rep["skipped"] = "PR_SET_DUMPABLE is Linux only"
    return rep
