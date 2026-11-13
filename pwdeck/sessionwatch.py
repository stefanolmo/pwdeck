"""Emits `lockRequested(reason)` when the desktop session locks or the machine goes to sleep.

Sources (all optional: whatever is not available on the running desktop is silently skipped):
  * systemd-logind (system bus)  ``Manager.PrepareForSleep(true)``  -> suspend / hibernate is about to start
  * systemd-logind (system bus)  ``Session.Lock``                    -> `loginctl lock-session`, many lock-screen tools
  * session bus ``org.freedesktop.ScreenSaver`` / ``org.gnome.ScreenSaver`` ``ActiveChanged(true)`` -> KDE / GNOME lock screen

Anyone able to emit these signals can only make the app LOCK, never unlock it.

Suspend race: logind announces ``PrepareForSleep(true)`` and only waits for processes holding a *delay inhibitor*
(``Manager.Inhibit("sleep", …, "delay")``, at most InhibitDelayMaxSec = 5 s by default). The watcher therefore keeps one
inhibitor file descriptor open, locks the vault when the signal arrives, and only THEN closes the descriptor so that the
machine can go to sleep with the vault already locked. After resume a new inhibitor is taken.
"""
from __future__ import annotations

import os

from PySide6.QtCore import QObject, Signal, Slot
from PySide6.QtDBus import QDBusConnection, QDBusInterface, QDBusMessage

SOURCES = [
    # (bus, interface, signal, slot)
    ("system", "org.freedesktop.login1.Manager", "PrepareForSleep", "1dbusSleep(bool)"),
    ("system", "org.freedesktop.login1.Session", "Lock", "1dbusLock()"),
    ("session", "org.freedesktop.ScreenSaver", "ActiveChanged", "1dbusActive(bool)"),
    ("session", "org.gnome.ScreenSaver", "ActiveChanged", "1dbusActive(bool)"),
]


def logind_inhibit(bus) -> int | None:
    """Takes a logind *delay* inhibitor for sleep. Returns an owned file descriptor (close it to release) or None."""
    if bus is None or not bus.isConnected():
        return None
    iface = QDBusInterface("org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", bus)
    if not iface.isValid():
        return None
    reply = iface.call("Inhibit", "sleep", "PW Deck", "Lock the vault before the system suspends", "delay")
    if reply.type() != QDBusMessage.ReplyMessage or not reply.arguments():
        return None
    try:
        return os.dup(reply.arguments()[0].fileDescriptor())      # our own copy; the message's one dies with `reply`
    except (AttributeError, OSError):
        return None


class SessionWatcher(QObject):
    lockRequested = Signal(str)

    def __init__(self, parent=None, buses: dict | None = None, inhibit=None):
        """`buses` / `inhibit` can be injected for tests; `inhibit()` must return an owned fd or None."""
        super().__init__(parent)
        buses = buses or {"system": QDBusConnection.systemBus(), "session": QDBusConnection.sessionBus()}
        self._inhibit = inhibit or (lambda: logind_inhibit(buses.get("system")))
        self._fd: int | None = None
        self.connected: list[str] = []
        for bus_name, iface, sig, slot in SOURCES:
            bus = buses.get(bus_name)
            if bus is not None and bus.isConnected() and bus.connect("", "", iface, sig, self, slot):
                self.connected.append(f"{bus_name}:{iface}.{sig}")
        if any(c.endswith("PrepareForSleep") for c in self.connected):
            self.take_inhibitor()

    @property
    def inhibiting(self) -> bool:
        return self._fd is not None

    def take_inhibitor(self) -> None:
        if self._fd is None:
            self._fd = self._inhibit()

    def release_inhibitor(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def close(self) -> None:
        self.release_inhibitor()

    @Slot(bool)
    def dbusSleep(self, going_to_sleep: bool) -> None:
        if going_to_sleep:
            try:
                self.lockRequested.emit("suspend")      # direct connection: the vault is locked when emit() returns
            finally:
                self.release_inhibitor()                 # now logind may suspend
        else:
            self.take_inhibitor()                        # resumed: be ready for the next suspend

    @Slot()
    def dbusLock(self) -> None:
        self.lockRequested.emit("session lock")

    @Slot(bool)
    def dbusActive(self, active: bool) -> None:
        if active:
            self.lockRequested.emit("screen lock")
