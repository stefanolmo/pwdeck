"""Emits `lockRequested(reason)` when the desktop session locks or the machine goes to sleep.

Sources (all optional: whatever is not available on the running desktop is silently skipped):
  * systemd-logind (system bus)  ``Manager.PrepareForSleep(true)``  -> suspend / hibernate is about to start
  * systemd-logind (system bus)  ``Session.Lock``                    -> `loginctl lock-session`, many lock-screen tools
  * session bus ``org.freedesktop.ScreenSaver`` / ``org.gnome.ScreenSaver`` ``ActiveChanged(true)`` -> KDE / GNOME lock screen

Anyone able to emit these signals can only make the app LOCK, never unlock it.
"""
from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot
from PySide6.QtDBus import QDBusConnection

SOURCES = [
    # (bus, interface, signal, slot)
    ("system", "org.freedesktop.login1.Manager", "PrepareForSleep", "1dbusSleep(bool)"),
    ("system", "org.freedesktop.login1.Session", "Lock", "1dbusLock()"),
    ("session", "org.freedesktop.ScreenSaver", "ActiveChanged", "1dbusActive(bool)"),
    ("session", "org.gnome.ScreenSaver", "ActiveChanged", "1dbusActive(bool)"),
]


class SessionWatcher(QObject):
    lockRequested = Signal(str)

    def __init__(self, parent=None, buses: dict | None = None):
        super().__init__(parent)
        buses = buses or {"system": QDBusConnection.systemBus(), "session": QDBusConnection.sessionBus()}
        self.connected: list[str] = []
        for bus_name, iface, sig, slot in SOURCES:
            bus = buses.get(bus_name)
            if bus is not None and bus.isConnected() and bus.connect("", "", iface, sig, self, slot):
                self.connected.append(f"{bus_name}:{iface}.{sig}")

    @Slot(bool)
    def dbusSleep(self, going_to_sleep: bool) -> None:
        if going_to_sleep:
            self.lockRequested.emit("suspend")

    @Slot()
    def dbusLock(self) -> None:
        self.lockRequested.emit("session lock")

    @Slot(bool)
    def dbusActive(self, active: bool) -> None:
        if active:
            self.lockRequested.emit("screen lock")
