"""Minimal fake systemd-logind for tests: `python fake_logind.py BUS_ADDRESS`. Implements Manager.Inhibit(...) -> unix fd
(the write end of a pipe), and remembers the read end so that the test can see when the client closes its copy."""
import os
import sys

from PySide6.QtCore import QCoreApplication, QObject, Slot
from PySide6.QtDBus import QDBusConnection, QDBusUnixFileDescriptor


class Manager(QObject):
    def __init__(self):
        super().__init__()
        self.reads = []

    @Slot(str, str, str, str, result=QDBusUnixFileDescriptor)
    def Inhibit(self, what, who, why, mode):
        r, w = os.pipe()
        self.reads.append(r)
        sys.stdout.write(f"inhibit {what} {mode}\n")
        sys.stdout.flush()
        fdobj = QDBusUnixFileDescriptor(w)
        os.close(w)                       # the QDBus object holds its own dup
        return fdobj

    @Slot(result=str)
    def Held(self):
        """How many inhibitors are still held by clients: a pipe whose write ends are all closed reads EOF."""
        import select
        n = 0
        for r in self.reads:
            ready, _, _ = select.select([r], [], [], 0)
            if not ready:                 # no EOF yet -> some writer is still open
                n += 1
        return str(n)


app = QCoreApplication([])
bus = QDBusConnection.connectToBus(sys.argv[1], "fake")
m = Manager()
assert bus.registerService("org.freedesktop.login1")
assert bus.registerObject("/org/freedesktop/login1", "org.freedesktop.login1.Manager", m, QDBusConnection.ExportAllSlots)
sys.stdout.write("ready\n")
sys.stdout.flush()
app.exec()
