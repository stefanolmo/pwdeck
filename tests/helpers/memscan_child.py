"""Child process for the memory-scan tests. Env: PWDECK_ROOT (code to import), VAULT, PWDECK_TEST_PW. Commands on stdin:
unlock | select N | reveal | hide | lock | quit   — each answers 'ok' when done. The child never knows the markers."""
import gc
import os
import sys
import tempfile

os.environ["QT_QPA_PLATFORM"] = "offscreen"
sys.path.insert(0, os.environ["PWDECK_ROOT"])
from PySide6.QtCore import QSettings  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from pwdeck import theme  # noqa: E402
from pwdeck.detail import FieldRow  # noqa: E402
from pwdeck.mainwindow import MainWindow  # noqa: E402
from pwdeck.vault import Vault  # noqa: E402

app = QApplication([])
app.setStyleSheet(theme.STYLESHEET)
qs = QSettings(os.path.join(tempfile.mkdtemp(), "s.ini"), QSettings.IniFormat)
qs.setValue("backup/auto", False)
qs.setValue("autolock_min", 0)
w = MainWindow(qs)
w.show()
print(os.getpid(), flush=True)
print("ready", flush=True)


def rows():
    wd = w.detail.scroll.widget()
    return [r for r in wd.findChildren(FieldRow) if r.secret] if wd else []


for line in sys.stdin:
    c = line.split()
    if c[0] == "unlock":
        w.set_vault(Vault.open(os.environ["VAULT"], os.environ["PWDECK_TEST_PW"]))
    elif c[0] == "select":
        w.list.setCurrentItem(w.list.topLevelItem(int(c[1])))
    elif c[0] == "reveal":
        for r in rows():
            r.eye.setChecked(True)
    elif c[0] == "hide":
        for r in rows():
            r.eye.setChecked(False)
    elif c[0] == "lock":
        w.lock()
    elif c[0] == "quit":
        break
    app.processEvents()
    gc.collect()
    print("ok", flush=True)
