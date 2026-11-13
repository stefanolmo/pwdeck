import os
import time

import pytest
from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QApplication, QMessageBox

from pwdeck import theme
from pwdeck.dialogs import AuditDialog, GeneratorDialog, ItemDialog
from pwdeck.mainwindow import MainWindow
from pwdeck.splash import SplashScreen
from pwdeck.startdialogs import CreateVaultDialog, UnlockDialog
from pwdeck.vault import Item, Vault


@pytest.fixture(scope="module")
def app():
    a = QApplication.instance() or QApplication([])
    a.setStyleSheet(theme.STYLESHEET)
    return a


@pytest.fixture
def qs(tmp_path):
    q = QSettings(str(tmp_path / "s.ini"), QSettings.IniFormat)
    q.setValue("backup/auto", False)
    return q


@pytest.fixture
def win(app, qs, vault, monkeypatch):
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.Yes))
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: QMessageBox.Yes))
    monkeypatch.setattr(QMessageBox, "information", staticmethod(lambda *a, **k: QMessageBox.Ok))
    f = vault.add_folder("Work")
    vault.add_item(Item(name="GitHub", username="mario", password="Zq9!vL2#xP7@rT4k", uris=["https://github.com"],
                        totp="JBSWY3DPEHPK3PXP", folder_id=f, tags=["dev"], favorite=True))
    vault.add_item(Item(name="Visa", type="card", extra={"number": "4111111111111111", "cvv": "123"}))
    vault.add_item(Item(name="Wifi", type="note", description="ssid: x"))
    w = MainWindow(qs)
    w.set_vault(vault)
    w.show()
    yield w
    w._running = False
    w.vault = None          # fixture `vault` closes it
    w.close()


def names(w):
    return [w.list.topLevelItem(i).text(0).lstrip("★ ") for i in range(w.list.topLevelItemCount())]


def test_sidebar_filters_and_search(win):
    assert sorted(names(win)) == ["GitHub", "Visa", "Wifi"]
    win.sidebar.setCurrentItem(win._nodes[("fav", None)])
    assert names(win) == ["GitHub"]
    win.sidebar.setCurrentItem(win._nodes[("type", "card")])
    assert names(win) == ["Visa"]
    fid = win.vault.folders()[0]["id"]
    win.sidebar.setCurrentItem(win._nodes[("folder", fid)])
    assert names(win) == ["GitHub"]
    win.sidebar.setCurrentItem(win._nodes[("all", None)])
    win.search.setText("mario dev")                       # all words must match, across fields
    assert names(win) == ["GitHub"]
    win.search.setText("ssid")                            # note bodies are not searched
    assert names(win) == []
    win.search.clear()


def test_copy_clears_only_own_value(win, app):
    win.qs.setValue("clipboard_s", 1)
    win.list.setCurrentItem(win.list.topLevelItem(0))
    it = win.current_item(full=True)
    win.copy_field("password")
    assert QApplication.clipboard().text() == it.password
    t0 = time.time()
    while QApplication.clipboard().text() and time.time() - t0 < 3:
        app.processEvents()
        time.sleep(0.02)
    assert QApplication.clipboard().text() == ""
    QApplication.clipboard().setText("something else")
    win.clip.copy("secret", "x")
    QApplication.clipboard().setText("user typed this")    # user copied something else meanwhile
    win.clip.clear()
    assert QApplication.clipboard().text() == "user typed this"


def test_lock_unlock_cycle(win, vpath):
    win.vault.save()
    win.lock()
    assert win.vault is None and win.stack.currentIndex() == 0 and win.list.topLevelItemCount() == 0
    assert not win.toolbar.isEnabled()
    d = UnlockDialog(win.qs, vpath)
    d.pw.setText("wrong")
    d._unlock()
    assert d.vault is None and "Wrong" in d.err.text()
    d.pw.setText("correct horse")
    d._unlock()
    assert d.vault is not None
    win.set_vault(d.vault)
    assert win.toolbar.isEnabled() and win.list.topLevelItemCount() == 3


def test_autolock(win):
    win.qs.setValue("autolock_min", 1)
    win._last_activity = time.time() - 61
    win._check_idle()
    assert win.vault is None


def test_item_dialog_create_edit_and_type_switch(win):
    d = ItemDialog(win.vault, win.qs, parent=win)
    d.name.setText("Server")
    d.widgets["username"].setText("root")
    d.widgets["password"].setText("pw-1")
    d.widgets["uris"].setPlainText("https://a.example\n\nhttps://b.example")
    d.widgets["totp"]._line.setText("not valid!")
    d._accept()
    assert d.result() == 0 and "TOTP" in d.err.text()
    d.widgets["totp"]._line.setText("JBSWY3DPEHPK3PXP")
    d.tags.setText("a, b ,")
    d.fav.setChecked(True)
    d.exp_on.setChecked(True)
    d._add_cf("pin", "1234", True)
    d._accept()
    it = d.item
    assert (it.name, it.username, it.password, it.uris, it.tags, it.favorite) == \
        ("Server", "root", "pw-1", ["https://a.example", "https://b.example"], ["a", "b"], True)
    assert it.fields == [{"label": "pin", "value": "1234", "hidden": True}] and it.expires > time.time()
    win.vault.add_item(it)
    # edit + switch to "card": password/totp are cleared, shared keys survive
    d2 = ItemDialog(win.vault, win.qs, win.vault.get_item(it.id), parent=win)
    d2.type_combo.setCurrentIndex(d2.type_combo.findData("card"))
    d2.widgets["number"].setText("4000")
    d2._accept()
    assert d2.result() == 1
    assert d2.item.type == "card" and d2.item.extra["number"] == "4000" and d2.item.password == "" and d2.item.totp == ""


def test_item_actions_and_trash(win):
    win.list.setCurrentItem(win.list.topLevelItem(0))
    iid = win.current_item().id
    win.delete_item()
    assert win.vault.get_item(iid).deleted and iid not in [win.list.topLevelItem(i).data(0, Qt.UserRole) for i in range(win.list.topLevelItemCount())]
    win.sidebar.setCurrentItem(win._nodes[("trash", None)])
    assert win.list.topLevelItemCount() == 1
    win.list.setCurrentItem(win.list.topLevelItem(0))
    win.restore_item()
    win.sidebar.setCurrentItem(win._nodes[("all", None)])
    assert win.list.topLevelItemCount() == 3


def test_detail_panel_decrypts_only_on_demand(win):
    win.search.setText("GitHub")
    win.list.setCurrentItem(win.list.topLevelItem(0))
    p = win.detail
    assert len(p.totp_widgets) == 1 and p.totp_widgets[0].current().isdigit()
    from pwdeck.detail import MASK, FieldRow
    calls = []
    orig = win.vault.reveal
    win.vault.reveal = lambda iid, key: (calls.append(key), orig(iid, key))[1]
    rows = p.scroll.widget().findChildren(FieldRow)
    pw = next(r for r in rows if r.secret and r.lbl.text() == MASK)
    assert pw.lbl.text() == MASK and "password" not in calls         # masked, and the password was not decrypted
    pw.eye.setChecked(True)
    assert pw.lbl.text() == "Zq9!vL2#xP7@rT4k" and calls == ["password"]
    pw.eye.setChecked(False)
    assert pw.lbl.text() == MASK


def test_audit_dialog(win, qs):
    win.vault.add_item(Item(name="r1", password="same-pw-123"))
    win.vault.add_item(Item(name="r2", password="same-pw-123"))
    win.vault.add_item(Item(name="weak", password="1234"))
    d = AuditDialog(win.vault.items(secrets=True), qs)
    assert {i.name for i, _ in d.report["reused"]} == {"r1", "r2"}
    assert "weak" in {i.name for i, _ in d.report["weak"]}
    assert d.tabs.tabText(1) == "Reused (2)"


def test_generator_dialog_persists(app, qs):
    d = GeneratorDialog(qs)
    d.spin.setValue(33)
    d.chk["symbols"].setChecked(False)
    assert len(d.password()) == 33 and d.password().isalnum()
    d2 = GeneratorDialog(qs)
    assert d2.spin.value() == 33 and not d2.chk["symbols"].isChecked()


def test_create_vault_dialog(app, qs, tmp_path, monkeypatch):
    from pwdeck import startdialogs
    monkeypatch.setattr(startdialogs.RecoveryKeyDialog, "exec", lambda self: 1)
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.Yes))
    d = CreateVaultDialog(qs)
    d.path.setText(str(tmp_path / "new.pwdeck"))
    d.pw.setText("longenough-1")
    d.pw2.setText("different")
    d._create()
    assert d.vault is None and "differ" in d.err.text()
    d.pw2.setText("longenough-1")
    d.kdf.setCurrentIndex(0)
    import pwdeck.crypto as c
    c.KDF_PRESETS["standard"] = c.KDF_PRESETS["fast"]            # keep the test fast
    d._create()
    assert d.vault is not None and d.result() == 1
    d.vault.close()
    Vault.open(str(tmp_path / "new.pwdeck"), "longenough-1").close()


def test_auto_backup_on_lock(win, tmp_path):
    win.qs.setValue("backup/auto", True)
    win.qs.setValue("backup/dir", str(tmp_path / "bk"))
    win.lock()
    import os
    assert len(os.listdir(tmp_path / "bk")) == 1


def test_splash_renders(app):
    s = SplashScreen("0.1.0")
    s.show()
    for t in (0, 500, 1500, 2900):
        s.set_time(t)
        s.grab()
    s.close()


def test_imports_need_only_declared_dependencies():
    """Regression: splash.py once imported numpy, which is not a dependency. Block every undeclared third-party package."""
    import subprocess
    import sys
    code = ("import sys\n"
            "for m in ('numpy', 'scipy', 'pyclipper', 'serial', 'svgelements', 'PIL'): sys.modules[m] = None\n"
            "import pwdeck.__main__, pwdeck.recover, pwdeck.backup, pwdeck.audit\n")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env={**__import__('os').environ, "QT_QPA_PLATFORM": "offscreen"})
    assert r.returncode == 0, r.stderr


def test_recovery_session_can_set_new_password_without_the_old_one(app, qs, tmp_path, monkeypatch):
    from pwdeck.dialogs import ChangePasswordDialog
    path = str(tmp_path / "r.pwdeck")
    v, rk = Vault.create(path, "forgotten", kdf="fast")
    v.close()
    v = Vault.open(path, recovery_key=rk)
    assert v.via_recovery
    d = ChangePasswordDialog(v)
    assert d.cur.isHidden()
    d.new.setText("brand new pass")
    d.new2.setText("brand new pass")
    d._ok()
    assert d.result() == 1                                   # accepted with NO current password
    d.apply()
    assert not v.via_recovery
    v.close()
    Vault.open(path, "brand new pass").close()
    Vault.open(path, recovery_key=rk).close()                # recovery key still valid
    # a normal session still has to prove the current password
    v = Vault.open(path, "brand new pass")
    d2 = ChangePasswordDialog(v)
    assert not d2.cur.isHidden()
    d2.new.setText("another pass 1")
    d2.new2.setText("another pass 1")
    d2.cur.setText("wrong")
    d2._ok()
    assert d2.result() == 0 and "current" in d2.err.text()
    v.close()


def test_main_window_offers_new_password_after_recovery_unlock(win, vpath, monkeypatch):
    rk = win.vault.recovery                                  # set by the `vault` fixture
    win.lock()
    asked = []
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: (asked.append(a[2]), QMessageBox.No)[1]))
    win.set_vault(Vault.open(vpath, recovery_key=rk))
    t0 = time.time()
    while not asked and time.time() - t0 < 2:
        QApplication.instance().processEvents()
    assert asked and "recovery key" in asked[0]
    win.vault.close()
    win.vault = None


def test_item_dialog_attachments_roundtrip(win, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QFileDialog
    f1 = tmp_path / "scan.pdf"
    f1.write_bytes(b"PDF-DATA")
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * (16 * 1024 * 1024 + 1))
    d = ItemDialog(win.vault, win.qs, parent=win)
    d.name.setText("Documents")
    monkeypatch.setattr(QFileDialog, "getOpenFileNames", staticmethod(lambda *a, **k: ([str(f1), str(big)], "")))
    d._add_att()
    assert d.att.count() == 1 and "larger than" in d.err.text()              # the oversized file was refused
    d._accept()
    win.vault.add_item(d.item)
    d.apply_attachments(win.vault, d.item.id)
    (att,) = win.vault.attachments(d.item.id)
    assert att["name"] == "scan.pdf" and win.vault.get_attachment(att["id"])[1] == b"PDF-DATA"
    # edit: remove it and save another copy via "Save as…"
    d2 = ItemDialog(win.vault, win.qs, win.vault.get_item(d.item.id), parent=win)
    assert d2.att.count() == 1
    out = tmp_path / "out.pdf"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(out), "")))
    d2.att.setCurrentRow(0)
    d2._save_att()
    assert out.read_bytes() == b"PDF-DATA" and oct(out.stat().st_mode & 0o777) == "0o600"
    d2._remove_att()
    d2._accept()
    d2.apply_attachments(win.vault, d2.item.id)
    assert win.vault.attachments(d.item.id) == []


def test_detail_panel_lists_attachments_and_duplicate_copies_them(win, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QFileDialog
    iid = win.vault.items()[0].id
    win.vault.add_attachment(iid, "a.txt", b"AAA")
    win.rebuild_sidebar()
    win.search.clear()
    for i in range(win.list.topLevelItemCount()):
        if win.list.topLevelItem(i).data(0, Qt.UserRole) == iid:
            win.list.setCurrentItem(win.list.topLevelItem(i))
    from PySide6.QtWidgets import QLabel
    assert any("a.txt" in l.text() for l in win.detail.scroll.widget().findChildren(QLabel))
    out = tmp_path / "saved.txt"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(out), "")))
    win.detail.saveAttachmentRequested.emit(win.vault.attachments(iid)[0]["id"], "a.txt")
    assert out.read_bytes() == b"AAA"
    win.duplicate_item()
    copy = next(i for i in win.vault.items() if i.name.endswith("(copy)"))
    (a,) = win.vault.attachments(copy.id)
    assert win.vault.get_attachment(a["id"]) == ("a.txt", b"AAA")


def test_generator_dialog_passphrase_mode_and_persistence(app, qs):
    d = GeneratorDialog(qs)
    d.mode.setCurrentIndex(d.mode.findData("words"))
    d.words.setValue(7)
    d.sep.setCurrentIndex(d.sep.findData("."))
    d.lang.setCurrentIndex(d.lang.findData("it"))
    d.cap.setChecked(True)
    pw = d.password()
    assert pw.count(".") == 6 and all(w[0].isupper() for w in pw.split("."))
    assert d.pass_box.isHidden() is False and d.char_box.isHidden() is True
    assert "Entropy" in d.note.text() and d.bar.bits > 80
    d2 = GeneratorDialog(qs)                                   # remembered
    assert d2.mode.currentData() == "words" and d2.words.value() == 7 and d2.sep.currentData() == "." and d2.lang.currentData() == "it"
    d2.mode.setCurrentIndex(d2.mode.findData("chars"))
    assert len(d2.password()) == d2.spin.value() and not d2.char_box.isHidden()


def test_kdbx_export_and_import_dialogs(win, tmp_path, monkeypatch):
    pytest.importorskip("pykeepass")
    from pwdeck.dialogs import KdbxExportDialog, KdbxImportDialog
    target = str(tmp_path / "e.kdbx")
    d = KdbxExportDialog(win.vault)
    d.path.setText(target)
    d.pw.setText("short")
    d._go()
    assert "8 characters" in d.err.text() and d.result() == 0
    d.pw.setText("export-password")
    d.pw2.setText("different-one")
    d._go()
    assert "differ" in d.err.text()
    d.pw2.setText("export-password")
    d._go()
    assert d.result() == 1 and d.count == 3 and os.path.exists(target)
    d2 = KdbxExportDialog(win.vault)
    d2.path.setText(target)
    d2.pw.setText("export-password")
    d2.pw2.setText("export-password")
    d2._go()
    assert "already exists" in d2.err.text()                         # never overwrites
    imp = KdbxImportDialog(target)
    imp.pw.setText("wrong")
    imp._go()
    assert "Wrong password" in imp.err.text() and imp.result() == 0
    imp.pw.setText("export-password")
    imp._go()
    assert imp.result() == 1 and {i.name for i in imp.items} == {"GitHub", "Visa", "Wifi"}


def test_main_window_import_kdbx_end_to_end(win, tmp_path, monkeypatch):
    pytest.importorskip("pykeepass")
    from PySide6.QtWidgets import QFileDialog
    from pwdeck import kdbx as kd
    from pwdeck.vault import Vault as V
    src, _ = V.create(str(tmp_path / "src.pwdeck"), "pw", kdf="fast")
    src.add_item(Item(name="From KeePass", username="kp", password="kp-pass"))
    kd.export_kdbx(src, str(tmp_path / "in.kdbx"), "kdbx-pw")
    src.close()
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(tmp_path / "in.kdbx"), "")))
    from pwdeck import mainwindow
    monkeypatch.setattr(mainwindow, "KdbxImportDialog", lambda path, parent: _FakeImport(path))
    win.import_file()
    assert any(i.name == "From KeePass" for i in win.vault.items())


class _FakeImport:
    """Stands in for the modal dialog: reads the file with the known password."""
    DialogCode = type("DC", (), {"Accepted": 1})

    def __init__(self, path):
        from pwdeck import kdbx as kd
        self.items, self.warnings = kd.import_kdbx(path, "kdbx-pw")

    def exec(self):
        return 1
