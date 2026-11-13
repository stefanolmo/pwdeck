"""Process hardening (Linux). Call `harden()` as early as possible, before any secret is loaded.

* ``RLIMIT_CORE = 0``: no core dump of this process. Always applied.
* ``prctl(PR_SET_DUMPABLE, 0)``: the kernel refuses ptrace and ``/proc/<pid>/mem`` access from other processes of the SAME user.
  Side effect: ``/proc/<pid>/*`` becomes root-owned, and desktop components that inspect the calling process through it (xdg-desktop-portal
  and, through it, the Qt GNOME window decoration that reads the title-bar button layout) can no longer do so: the window then
  shows a title bar WITHOUT buttons. Because of that it is applied only when it adds real protection:

  ``PWDECK_HARDEN=auto`` (default)  apply it only if Yama's ``ptrace_scope`` is 0 (Ubuntu, Fedora… default to 1, which already stops
                                    unrelated processes from attaching to / reading the memory of yours) or unknown
  ``PWDECK_HARDEN=always``          apply it regardless
  ``PWDECK_HARDEN=never``           never (``PWDECK_ALLOW_DUMP=1`` is a legacy alias, also disables RLIMIT_CORE for debugging)

Not a protection against: root, a kernel exploit, code injected through the environment/launcher (LD_PRELOAD…) or a keylogger.
"""
from __future__ import annotations

import ctypes
import os
import sys

PR_SET_DUMPABLE = 4
PR_GET_DUMPABLE = 3
YAMA_FILE = "/proc/sys/kernel/yama/ptrace_scope"


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def is_dumpable() -> bool | None:
    """True/False, or None if it cannot be determined (not Linux)."""
    if not sys.platform.startswith("linux"):
        return None
    r = _libc().prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)
    return None if r < 0 else bool(r)


def ptrace_scope() -> int | None:
    """Yama ptrace_scope (0 classic, 1 restricted to descendants, 2 admin only, 3 none) or None if Yama is not present."""
    try:
        with open(os.environ.get("PWDECK_YAMA_FILE", YAMA_FILE)) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def harden() -> dict:
    """Returns {'core_disabled': bool, 'dumpable_disabled': bool, 'mode': str, 'note': str|None, 'failed': bool}."""
    rep = {"core_disabled": False, "dumpable_disabled": False, "mode": "auto", "note": None, "failed": False}
    mode = os.environ.get("PWDECK_HARDEN", "auto").lower()
    if os.environ.get("PWDECK_ALLOW_DUMP"):
        mode = "never"
        rep["note"] = "PWDECK_ALLOW_DUMP is set: hardening disabled"
    if mode not in ("auto", "always", "never"):
        mode = "auto"
    rep["mode"] = mode
    if not os.environ.get("PWDECK_ALLOW_DUMP"):
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            rep["core_disabled"] = True
        except (ImportError, ValueError, OSError):
            pass
    if not sys.platform.startswith("linux") or mode == "never":
        return rep
    scope = ptrace_scope()
    if mode == "auto" and scope is not None and scope >= 1:
        rep["note"] = f"PR_SET_DUMPABLE not needed: Yama ptrace_scope={scope} already blocks other processes"
        return rep
    try:
        if _libc().prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0:
            rep["dumpable_disabled"] = is_dumpable() is False
    except (OSError, AttributeError):
        pass
    rep["failed"] = not rep["dumpable_disabled"]
    return rep
