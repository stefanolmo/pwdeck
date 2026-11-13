"""Regenerates the README images (offscreen, throw-away demo vault):  QT_QPA_PLATFORM=offscreen python3 docs/make_screenshots.py"""
import os
import sys
import tempfile
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from PySide6.QtCore import QSettings, Qt  # noqa: E402
from PySide6.QtGui import QColor, QPixmap  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from pwdeck import __version__, theme  # noqa: E402
from pwdeck.dialogs import AuditDialog, GeneratorDialog, ItemDialog  # noqa: E402
from pwdeck.mainwindow import MainWindow  # noqa: E402
from pwdeck.splash import SplashScreen  # noqa: E402
from pwdeck.vault import Item, Vault  # noqa: E402

app = QApplication([])
app.setStyleSheet(theme.STYLESHEET)


def pump(s):
    t = time.time()
    while time.time() - t < s:
        app.processEvents()
        time.sleep(0.01)


s = SplashScreen(__version__)
s.show()
s.set_time(2700)
pm = QPixmap(s.size())
pm.fill(QColor(0, 0, 0, 0))
s.render(pm)
pm.save(os.path.join(HERE, "splash.png"))
s.close()

tmp = tempfile.mkdtemp()
qs = QSettings(os.path.join(tmp, "s.ini"), QSettings.IniFormat)
qs.setValue("backup/auto", False)
v, _ = Vault.create(os.path.join(tmp, "demo.pwdeck"), "demo-password", kdf="fast")
now = time.time()
work, personal = v.add_folder("Work"), v.add_folder("Personal")
srv = v.add_folder("Servers", work)
D = [Item(name="GitHub", username="stefano", password="Zq9!vL2#xP7@rT4k", uris=["https://github.com/login"], totp="JBSWY3DPEHPK3PXP", folder_id=work, tags=["dev"], favorite=True,
          description="Personal access token stored in a custom field.", fields=[{"label": "Recovery codes", "value": "a1b2-c3d4", "hidden": True}]),
     Item(name="Production DB", username="admin", password="hunter2", uris=["postgres://db.internal"], folder_id=srv, tags=["prod"]),
     Item(name="Bastion", type="ssh", username="ops", uris=["ssh://bastion.example.org"], folder_id=srv, extra={"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n…", "passphrase": "p@ss"}),
     Item(name="Gmail", username="me@example.com", password="kP3$wQ8!zN1&mB6v", uris=["https://mail.google.com"], totp="otpauth://totp/Gmail?secret=GEZDGNBVGY3TQOJQ", folder_id=personal, favorite=True),
     Item(name="Visa Gold", type="card", extra={"holder": "S. CIURLEO", "number": "4111 1111 1111 1111", "expiry": "08/29", "cvv": "123"}, folder_id=personal),
     Item(name="Router admin", username="admin", password="admin", uris=["http://192.168.1.1"], folder_id=personal, pw_changed=now - 800 * 86400),
     Item(name="Wi-Fi home", type="note", description="SSID: casa\nWPA2: correct-horse-battery", folder_id=personal),
     Item(name="Netflix", username="me@example.com", password="kP3$wQ8!zN1&mB6v", uris=["https://netflix.com"], folder_id=personal)]
for i in D:
    v.add_item(i)
w = MainWindow(qs)
w.resize(1360, 820)
w.set_vault(v)
w.show()
w.search.setText("")
w.list.setCurrentItem(w.list.topLevelItem(0))
pump(0.5)
w.grab().save(os.path.join(HERE, "main.png"))
w.lock()
pump(0.2)
w.grab().save(os.path.join(HERE, "locked.png"))
v = Vault.open(os.path.join(tmp, "demo.pwdeck"), "demo-password")
w.set_vault(v)
d = ItemDialog(v, qs, v.get_item(v.items()[0].id), parent=w)
d.show()
pump(0.3)
d.grab().save(os.path.join(HERE, "editor.png"))
d.close()
a = AuditDialog(v.items(secrets=True), qs)
a.show()
pump(0.3)
a.grab().save(os.path.join(HERE, "audit.png"))
w._running = False
w.vault = None
v.close()
print("ok")
