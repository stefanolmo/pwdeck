import os
import shutil
import subprocess
import sys
import time

import pytest
from PySide6.QtDBus import QDBusConnection, QDBusMessage
from PySide6.QtWidgets import QApplication

from pwdeck.sessionwatch import SessionWatcher
from tests.test_ui import app, qs, win  # noqa: F401  (fixtures)


def _run(code, env=None):
    e = dict(os.environ)
    e.pop("PWDECK_ALLOW_DUMP", None)
    e.update(env or {})
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=e, cwd=os.path.dirname(os.path.dirname(__file__)))


def _harden_state(env):
    r = _run("import resource; from pwdeck import hardening as h\n"
             "rep = h.harden()\n"
             "print(rep['dumpable_disabled'], rep['core_disabled'], h.is_dumpable(), resource.getrlimit(resource.RLIMIT_CORE)[0], rep['note'])", env)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
def test_harden_always_disables_dumps_and_core():
    out = _harden_state({"PWDECK_HARDEN": "always"})
    assert out.startswith("True True False 0")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
def test_harden_auto_skips_dumpable_when_yama_already_protects(tmp_path):
    f = tmp_path / "scope"
    f.write_text("1\n")
    out = _harden_state({"PWDECK_YAMA_FILE": str(f)})          # auto mode, Yama scope 1 (Ubuntu default)
    assert out.startswith("False True True 0") and "Yama ptrace_scope=1" in out     # still dumpable: desktop integration intact, no core dumps
    f.write_text("0\n")
    assert _harden_state({"PWDECK_YAMA_FILE": str(f)}).startswith("True True False 0")   # scope 0: nothing else protects us
    assert _harden_state({"PWDECK_YAMA_FILE": str(tmp_path / "missing")}).startswith("True True False 0")  # unknown: protect


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
def test_harden_never_and_legacy_opt_out():
    assert _harden_state({"PWDECK_HARDEN": "never"}).startswith("False True True 0")
    out = _harden_state({"PWDECK_ALLOW_DUMP": "1"})
    assert out.startswith("False False True") and "disabled" in out


@pytest.fixture
def private_bus():
    if not shutil.which("dbus-daemon"):
        pytest.skip("dbus-daemon not installed")
    p = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--print-address=1"], stdout=subprocess.PIPE, text=True)
    addr = p.stdout.readline().strip()
    conn = QDBusConnection.connectToBus(addr, "pwdeck-test")
    assert conn.isConnected()
    yield addr, conn
    QDBusConnection.disconnectFromBus("pwdeck-test")
    QDBusConnection.disconnectFromBus("pwdeck-emitter")
    p.terminate()
    p.wait()


def _emit(addr, path, iface_signal, *args):
    """Emit a signal from a second, properly registered bus connection (like logind / the lock screen would)."""
    iface, name = iface_signal.rsplit(".", 1)
    em = QDBusConnection.connectToBus(addr, "pwdeck-emitter")
    m = QDBusMessage.createSignal(path, iface, name)
    m.setArguments([a == "boolean:true" for a in args])
    assert em.send(m)


def _pump(app, cond, timeout=3.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_session_watcher_real_dbus_signals(app, private_bus):
    addr, conn = private_bus
    w = SessionWatcher(buses={"system": conn, "session": conn})
    assert len(w.connected) == 4
    got = []
    w.lockRequested.connect(got.append)
    _emit(addr, "/org/freedesktop/login1", "org.freedesktop.login1.Manager.PrepareForSleep", "boolean:false")   # resume: ignored
    _emit(addr, "/org/freedesktop/ScreenSaver", "org.freedesktop.ScreenSaver.ActiveChanged", "boolean:false")   # unlock: ignored
    _emit(addr, "/org/freedesktop/login1", "org.freedesktop.login1.Manager.PrepareForSleep", "boolean:true")
    assert _pump(app, lambda: got == ["suspend"])
    _emit(addr, "/org/freedesktop/login1/session/_32", "org.freedesktop.login1.Session.Lock")
    _emit(addr, "/org/freedesktop/ScreenSaver", "org.freedesktop.ScreenSaver.ActiveChanged", "boolean:true")
    _emit(addr, "/org/gnome/ScreenSaver", "org.gnome.ScreenSaver.ActiveChanged", "boolean:true")
    assert _pump(app, lambda: len(got) == 4)
    assert got == ["suspend", "session lock", "screen lock", "screen lock"]


def test_watcher_without_bus_is_harmless(app):
    class Dead:
        def isConnected(self):
            return False
    w = SessionWatcher(buses={"system": Dead(), "session": Dead()})
    assert w.connected == []


def test_window_locks_on_suspend_and_respects_setting(win, app, private_bus):          # noqa: F811
    addr, conn = private_bus
    w = SessionWatcher(buses={"system": conn, "session": conn})
    w.lockRequested.connect(win._system_lock)
    win.qs.setValue("lock_on_suspend", False)
    _emit(addr, "/org/freedesktop/login1", "org.freedesktop.login1.Manager.PrepareForSleep", "boolean:true")
    _pump(app, lambda: False, 0.4)
    assert win.vault is not None                                     # setting off: stays unlocked
    win.qs.setValue("lock_on_suspend", True)
    _emit(addr, "/org/freedesktop/login1", "org.freedesktop.login1.Manager.PrepareForSleep", "boolean:true")
    assert _pump(app, lambda: win.vault is None)
    assert win.stack.currentIndex() == 0 and win.list.topLevelItemCount() == 0


# ------------------------------------------------------------------ suspend inhibitor
@pytest.fixture
def fake_logind(private_bus):
    addr, conn = private_bus
    p = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "helpers", "fake_logind.py"), addr],
                         stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "ready"
    from PySide6.QtDBus import QDBusInterface
    iface = QDBusInterface("org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", conn)
    held = lambda: int(iface.call("Held").arguments()[0])          # noqa: E731
    yield addr, conn, held
    p.terminate()
    p.wait()


def test_inhibitor_lifecycle_locks_before_releasing(app, fake_logind):
    addr, conn, held = fake_logind
    w = SessionWatcher(buses={"system": conn, "session": conn})
    assert w.inhibiting and held() == 1                      # delay inhibitor taken at start
    seen = {}
    w.lockRequested.connect(lambda reason: seen.update(reason=reason, held_while_locking=held(), inhibiting=w.inhibiting))
    _emit(addr, "/org/freedesktop/login1", "org.freedesktop.login1.Manager.PrepareForSleep", "boolean:true")
    assert _pump(app, lambda: "reason" in seen and not w.inhibiting)
    assert seen == {"reason": "suspend", "held_while_locking": 1, "inhibiting": True}    # still held WHILE the vault locks
    _pump(app, lambda: False, 0.3)
    assert held() == 0                                       # released only afterwards: logind may now suspend
    _emit(addr, "/org/freedesktop/login1", "org.freedesktop.login1.Manager.PrepareForSleep", "boolean:false")
    assert _pump(app, lambda: w.inhibiting) and held() == 1  # resume: armed again
    w.close()
    _pump(app, lambda: False, 0.3)
    assert held() == 0 and not w.inhibiting


def test_inhibitor_released_even_if_lock_handler_raises(app, fake_logind):
    addr, conn, held = fake_logind
    w = SessionWatcher(buses={"system": conn, "session": conn})
    w.lockRequested.connect(lambda r: 1 / 0)
    w.dbusSleep(True)                                         # PySide prints the slot error but must not keep the system waiting
    assert not w.inhibiting
    w.close()


def test_inhibitor_injected_fd_is_closed(app):
    r, wfd = os.pipe()
    os.close(r)
    w = SessionWatcher(buses={"system": _Dead(), "session": _Dead()}, inhibit=lambda: wfd)
    assert not w.inhibiting                                   # no PrepareForSleep connection -> nothing taken
    w.take_inhibitor()
    assert w.inhibiting
    w.release_inhibitor()
    with pytest.raises(OSError):
        os.fstat(wfd)


class _Dead:
    def isConnected(self):
        return False
