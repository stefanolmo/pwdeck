"""Main window: sidebar (types, folders, tags), item list, detail panel; lock screen; auto-lock; backups."""
from __future__ import annotations

import os
import time

from PySide6.QtCore import QEvent, QSettings, QSize, Qt, QTimer
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (QApplication, QFileDialog, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMainWindow,
                               QMenu, QMessageBox, QPushButton, QSplitter, QStackedWidget, QToolBar, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from . import __version__, backup, importers, theme
from .detail import TYPE_ICON, DetailPanel
from .dialogs import AuditDialog, GeneratorDialog, HistoryDialog, ItemDialog, SettingsDialog, fmt_ts
from .sessionwatch import SessionWatcher
from .startdialogs import UnlockDialog
from .theme import icon
from .itemtypes import TYPE_ORDER, type_label
from .vault import Item, Vault, VaultChangedError, auto_backup, default_backup_dir
from .widgets import SecureClipboard

APP_NAME = "PW Deck"


class MainWindow(QMainWindow):
    def __init__(self, qs: QSettings | None = None, vault_path: str | None = None):
        super().__init__()
        self.qs = qs or QSettings("pwdeck", "pwdeck")
        self.vault: Vault | None = None
        self.vault_path = vault_path or str(self.qs.value("last_vault", "") or "")
        self._running = True
        self._last_activity = time.time()
        self._filter = ("all", None)
        self.setWindowTitle(APP_NAME)
        self.resize(1320, 820)
        self.clip = SecureClipboard(int(self.qs.value("clipboard_s", 30)), self)
        self.clip.changed.connect(lambda m: self.statusBar().showMessage(m, 5000))
        self._build_ui()
        self._build_toolbar()
        self._build_menu()
        QApplication.instance().installEventFilter(self)
        self.watcher = SessionWatcher(self)
        self.watcher.lockRequested.connect(self._system_lock)
        self._idle = QTimer(self, interval=2000)
        self._idle.timeout.connect(self._check_idle)
        self._idle.start()
        self._set_locked_ui(True)

    # ------------------------------------------------------------------ UI construction
    def _build_ui(self) -> None:
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        # page 0: locked
        lp = QWidget()
        ll = QVBoxLayout(lp)
        ll.setAlignment(Qt.AlignCenter)
        ic = QLabel()
        ic.setPixmap(icon("lock", theme.ACCENT).pixmap(72, 72))
        ic.setAlignment(Qt.AlignCenter)
        ll.addWidget(ic)
        t = QLabel("Vault locked", objectName="h1")
        t.setAlignment(Qt.AlignCenter)
        ll.addWidget(t)
        self.locked_path = QLabel("", objectName="muted")
        self.locked_path.setAlignment(Qt.AlignCenter)
        ll.addWidget(self.locked_path)
        b = QPushButton("Unlock…")
        b.setObjectName("primary")
        b.setFixedWidth(180)
        b.clicked.connect(self.unlock_dialog)
        ll.addWidget(b, 0, Qt.AlignCenter)
        self.stack.addWidget(lp)
        # page 1: vault
        split = QSplitter()
        self.sidebar = QTreeWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setHeaderHidden(True)
        self.sidebar.setIndentation(14)
        self.sidebar.setIconSize(QSize(17, 17))
        self.sidebar.setMinimumWidth(190)
        self.sidebar.currentItemChanged.connect(self._sidebar_changed)
        self.sidebar.setContextMenuPolicy(Qt.CustomContextMenu)
        self.sidebar.customContextMenuRequested.connect(self._sidebar_menu)
        self.list = QTreeWidget()
        self.list.setColumnCount(4)
        self.list.setHeaderLabels(["Name", "Username", "URL", "Modified"])
        self.list.setRootIsDecorated(False)
        self.list.setAlternatingRowColors(True)
        self.list.setSortingEnabled(True)
        self.list.sortByColumn(0, Qt.AscendingOrder)      # Qt would otherwise start descending (Z→A)
        self.list.setIconSize(QSize(17, 17))
        self.list.setColumnWidth(0, 230)
        self.list.setColumnWidth(1, 150)
        self.list.setColumnWidth(2, 190)
        self.list.setColumnWidth(3, 130)
        self.list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list.customContextMenuRequested.connect(self._list_menu)
        self.list.currentItemChanged.connect(self._list_changed)
        self.list.itemDoubleClicked.connect(lambda *_: self.edit_item())
        self.detail = DetailPanel()
        self.detail.copyRequested.connect(self.copy_value)
        self.detail.editRequested.connect(self.edit_item)
        self.detail.deleteRequested.connect(self.delete_item)
        self.detail.restoreRequested.connect(self.restore_item)
        self.detail.favoriteToggled.connect(self.toggle_favorite)
        self.detail.historyRequested.connect(self.show_history)
        split.addWidget(self.sidebar)
        split.addWidget(self.list)
        split.addWidget(self.detail)
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 3)
        split.setStretchFactor(2, 2)
        split.setSizes([210, 640, 420])
        self.stack.addWidget(split)
        self.sb_path = QLabel("")
        self.sb_count = QLabel("")
        self.sb_saved = QLabel("")
        for w in (self.sb_path, self.sb_count, self.sb_saved):
            w.setObjectName("muted")
        self.statusBar().addPermanentWidget(self.sb_path, 1)
        self.statusBar().addPermanentWidget(self.sb_count)
        self.statusBar().addPermanentWidget(self.sb_saved)

    def _act(self, text: str, icon_name: str, slot, shortcut: str | None = None) -> QAction:
        a = QAction(icon(icon_name), text, self)
        a.triggered.connect(lambda *_: slot())
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
        self.addAction(a)
        return a

    def _build_toolbar(self) -> None:
        tb = QToolBar()
        tb.setMovable(False)
        tb.setIconSize(QSize(18, 18))
        tb.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.addToolBar(tb)
        self.act_new = self._act("New", "plus", self.new_item, "Ctrl+N")
        self.act_gen = self._act("Generator", "dice", self.open_generator, "Ctrl+G")
        self.act_audit = self._act("Audit", "shield", self.open_audit)
        self.act_backup = self._act("Backup", "backup", self.backup_menu_popup)
        self.act_import = self._act("Import", "import", self.import_file)
        self.act_export = self._act("Export", "export", self.export_menu_popup)
        self.act_settings = self._act("Settings", "gear", self.open_settings)
        self.act_lock = self._act("Lock", "lock", self.lock, "Ctrl+L")
        for a in (self.act_new, self.act_gen, self.act_audit):
            tb.addAction(a)
        tb.addSeparator()
        for a in (self.act_backup, self.act_import, self.act_export):
            tb.addAction(a)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search  (Ctrl+F)")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(280)
        self.search.addAction(icon("search", theme.MUTED), QLineEdit.LeadingPosition)
        self.search.textChanged.connect(lambda _t: self.refresh_list())
        sp = QWidget()
        sp.setObjectName("spacer")
        sp.setSizePolicy(sp.sizePolicy().horizontalPolicy().Expanding, sp.sizePolicy().verticalPolicy().Preferred)
        tb.addWidget(sp)
        tb.addWidget(self.search)
        tb.addAction(self.act_settings)
        tb.addAction(self.act_lock)
        self.toolbar = tb
        for key, slot in (("Ctrl+F", lambda: self.search.setFocus()), ("Ctrl+U", lambda: self.copy_field("username")),
                          ("Ctrl+P", lambda: self.copy_field("password")), ("Ctrl+T", lambda: self.copy_field("totp")),
                          ("Ctrl+E", self.edit_item), ("Del", self.delete_item)):
            a = QAction(self)
            a.setShortcut(QKeySequence(key))
            a.triggered.connect(lambda *_, s=slot: s() if self.vault else None)
            self.addAction(a)

    def _build_menu(self) -> None:
        mb = self.menuBar()
        m = mb.addMenu("&Vault")
        m.addAction(icon("unlock"), "&Unlock…", self.unlock_dialog)
        m.addAction(icon("lock"), "&Lock\tCtrl+L", self.lock)
        m.addSeparator()
        m.addAction(icon("close"), "&Quit\tCtrl+Q", self.close)
        v = mb.addMenu("V&iew")
        self.act_fs = v.addAction("&Full screen\tF11", self.toggle_fullscreen)
        v.addAction(icon("minimize"), "&Minimize", self.showMinimized)
        h = mb.addMenu("&Help")
        h.addAction("&About PW Deck", self.about)
        for key, slot in (("Ctrl+Q", self.close), ("F11", self.toggle_fullscreen)):
            a = QAction(self)
            a.setShortcut(QKeySequence(key))
            a.triggered.connect(lambda *_, s=slot: s())
            self.addAction(a)

    def toggle_fullscreen(self) -> None:
        self.showNormal() if self.isFullScreen() else self.showFullScreen()

    def about(self) -> None:
        QMessageBox.about(self, "About PW Deck", f"<b>PW Deck {__version__}</b><br>Local password manager, encrypted single-file vault.<br><br>"
                          "Not independently audited. Keep a copy of your vault, your keyfile and your recovery key somewhere safe.")

    # ------------------------------------------------------------------ lock / unlock
    def _set_locked_ui(self, locked: bool) -> None:
        self.toolbar.setEnabled(not locked)
        self.toolbar.setVisible(not locked)
        self.stack.setCurrentIndex(0 if locked else 1)
        if locked:
            self.locked_path.setText(self.vault_path or "No vault selected")
            self.setWindowTitle(APP_NAME + " — locked")
            self.sb_path.setText("")
            self.sb_count.setText("")
            self.sb_saved.setText("")

    def unlock_dialog(self) -> bool:
        if self.vault:
            return True
        d = UnlockDialog(self.qs, self.vault_path, self)
        if d.exec() != d.DialogCode.Accepted or d.vault is None:
            return False
        self.set_vault(d.vault)
        return True

    def set_vault(self, v: Vault) -> None:
        self.vault = v
        self.vault_path = v.path
        self.qs.setValue("last_vault", v.path)
        v.on_saved = self._on_saved
        self._set_locked_ui(False)
        self.setWindowTitle(f"{APP_NAME} — {os.path.basename(v.path)}")
        self.sb_path.setText(v.path)
        self._last_activity = time.time()
        self.search.clear()
        self.rebuild_sidebar()
        self._maybe_backup()
        if v.via_recovery:
            QTimer.singleShot(0, self._offer_new_password)

    def _offer_new_password(self) -> None:
        if self.vault and self.vault.via_recovery and QMessageBox.question(
                self, "Recovery key", "You unlocked the vault with the recovery key.\nSet a new master password now?") == QMessageBox.Yes:
            from .dialogs import ChangePasswordDialog
            d = ChangePasswordDialog(self.vault, self)
            if d.exec() == d.DialogCode.Accepted:
                self._do(d.apply)
                self.statusBar().showMessage("Master password changed; the recovery key is still valid.", 8000)

    def lock(self) -> None:
        if not self.vault:
            return
        self._maybe_backup()
        try:
            self.vault.close()
        except Exception as e:          # noqa: BLE001
            if QMessageBox.question(self, "Lock", f"The vault could not be saved:\n{e}\n\nLock anyway and lose the unsaved changes?") != QMessageBox.Yes:
                return
        self.vault = None                 # first: signals fired while the UI is cleared must not touch the closed database
        self.clip.clear()
        self.detail.clear()
        self.list.clear()
        self.sidebar.clear()
        self._set_locked_ui(True)

    def _on_saved(self, _path: str) -> None:
        self.sb_saved.setText("Saved " + time.strftime("%H:%M:%S"))

    def _check_idle(self) -> None:
        mins = int(self.qs.value("autolock_min", 5))
        if self.vault and mins > 0 and time.time() - self._last_activity > mins * 60:
            self.lock()

    def _system_lock(self, reason: str) -> None:
        if self.vault and str(self.qs.value("lock_on_suspend", True)).lower() in ("true", "1"):
            self.lock()
            self.statusBar().showMessage(f"Locked ({reason})", 8000)

    def eventFilter(self, obj, ev) -> bool:
        if ev.type() in (QEvent.MouseButtonPress, QEvent.KeyPress, QEvent.MouseMove, QEvent.Wheel):
            self._last_activity = time.time()
        return False

    def changeEvent(self, ev) -> None:
        if ev.type() == QEvent.WindowStateChange and self.isMinimized() and self.vault \
                and str(self.qs.value("lock_on_minimize", False)).lower() in ("true", "1"):
            QTimer.singleShot(0, self.lock)
        super().changeEvent(ev)

    def closeEvent(self, ev) -> None:
        self._running = False
        self.watcher.close()
        if self.vault:
            self.clip.clear()
            self._maybe_backup()
            try:
                self.vault.close()
            except Exception as e:      # noqa: BLE001
                if QMessageBox.question(self, "Save failed", f"Could not save the vault:\n{e}\n\nClose anyway?") != QMessageBox.Yes:
                    self._running = True
                    ev.ignore()
                    return
            self.vault = None
        super().closeEvent(ev)

    # ------------------------------------------------------------------ guarded vault writes
    def _do(self, fn, *a, **k):
        """Runs a vault mutation; handles external-modification conflicts and I/O errors."""
        try:
            return fn(*a, **k)
        except VaultChangedError:
            r = QMessageBox.question(self, "Vault changed on disk",
                                     "The vault file was modified by another program (sync client? another computer?) after it was loaded.\n\n"
                                     "Yes = overwrite it with this session's data\nNo = keep it untouched and save a copy elsewhere",
                                     QMessageBox.Yes | QMessageBox.No)
            if r == QMessageBox.Yes:
                self.vault.save(force=True)
            else:
                p, _ = QFileDialog.getSaveFileName(self, "Save a copy", "recovered.pwdeck", "PW Deck vault (*.pwdeck)")
                if p:
                    self.vault.copy_to(p)
        except OSError as e:
            QMessageBox.critical(self, "Cannot save", f"{e}\n\nYour changes are only in memory. Use Backup → Save a copy to keep them.")

    def _maybe_backup(self) -> None:
        if not self.vault or str(self.qs.value("backup/auto", True)).lower() not in ("true", "1"):
            return
        d = str(self.qs.value("backup/dir", "") or "") or default_backup_dir(self.vault.path)
        try:
            if self.vault.dirty:
                self.vault.save()
            made = auto_backup(self.vault, d, int(self.qs.value("backup/keep", 10)))
            if made:
                self.statusBar().showMessage("Backup: " + made, 6000)
        except Exception as e:          # noqa: BLE001
            self.statusBar().showMessage(f"Automatic backup failed: {e}", 10000)

    # ------------------------------------------------------------------ sidebar / list
    def rebuild_sidebar(self) -> None:
        v = self.vault
        if not v:
            return
        cur = self._filter
        self.sidebar.blockSignals(True)
        self.sidebar.clear()
        items = v.items()
        trash = v.items(trash=True)

        def node(parent, text, ic, key, val=None, count=None):
            n = QTreeWidgetItem(parent, [text + (f"   {count}" if count is not None else "")])
            n.setIcon(0, icon(ic))
            n.setData(0, Qt.UserRole, (key, val))
            return n

        def header(text):
            h = QTreeWidgetItem(self.sidebar, [text])
            h.setFlags(Qt.ItemIsEnabled)
            h.setForeground(0, Qt.gray)
            f = h.font(0)
            f.setPointSize(8)
            f.setBold(True)
            h.setFont(0, f)
            return h

        self._nodes = {}
        self._nodes[("all", None)] = node(self.sidebar, "All items", "grid", "all", None, len(items))
        self._nodes[("fav", None)] = node(self.sidebar, "Favorites", "star", "fav", None, sum(1 for i in items if i.favorite))
        h = header("TYPES")
        for t in TYPE_ORDER:
            c = sum(1 for i in items if i.type == t)
            if c:
                self._nodes[("type", t)] = node(h, type_label(t), TYPE_ICON[t], "type", t, c)
        h.setExpanded(True)
        h = header("FOLDERS")
        by_parent: dict = {}
        for f in v.folders():
            by_parent.setdefault(f["parent_id"], []).append(f)

        def add(parent_node, pid):
            for f in by_parent.get(pid, []):
                ids = v.folder_ids_under(f["id"])
                n = node(parent_node, f["name"], "folder", "folder", f["id"], sum(1 for i in items if i.folder_id in ids))
                self._nodes[("folder", f["id"])] = n
                add(n, f["id"])
                n.setExpanded(True)
        add(h, None)
        h.setExpanded(True)
        tags = v.all_tags()
        if tags:
            h = header("TAGS")
            for t in tags:
                self._nodes[("tag", t)] = node(h, t, "tag", "tag", t, sum(1 for i in items if t in i.tags))
            h.setExpanded(True)
        self._nodes[("trash", None)] = node(self.sidebar, "Trash", "trash", "trash", None, len(trash))
        self.sidebar.blockSignals(False)
        self.sidebar.setCurrentItem(self._nodes.get(cur, self._nodes[("all", None)]))
        self._filter = cur if cur in self._nodes else ("all", None)
        self.refresh_list()
        self.sb_count.setText(f"{len(items)} items")

    def _sidebar_changed(self, cur, _prev) -> None:
        if cur is not None and cur.data(0, Qt.UserRole):
            self._filter = tuple(cur.data(0, Qt.UserRole))
            self.refresh_list()

    def _visible_items(self) -> list[Item]:
        v = self.vault
        kind, val = self._filter
        items = v.items(trash=(kind == "trash"))
        if kind == "fav":
            items = [i for i in items if i.favorite]
        elif kind == "type":
            items = [i for i in items if i.type == val]
        elif kind == "folder":
            ids = v.folder_ids_under(val)
            items = [i for i in items if i.folder_id in ids]
        elif kind == "tag":
            items = [i for i in items if val in i.tags]
        q = self.search.text().strip().lower()
        if q:
            def hit(i: Item) -> bool:
                hay = [i.name, i.username, " ".join(i.uris), " ".join(i.tags), v.folder_path(i.folder_id), type_label(i.type)]
                return all(any(w in h.lower() for h in hay) for w in q.split())
            items = [i for i in items if hit(i)]
        return items

    def refresh_list(self, select_id: str | None = None) -> None:
        if not self.vault:
            return
        keep = select_id or (self.detail.item.id if self.detail.item else None)
        self.list.setSortingEnabled(False)
        self.list.clear()
        now = time.time()
        target = None
        for it in self._visible_items():
            row = QTreeWidgetItem([("★ " if it.favorite else "") + it.name, it.username, it.uri, fmt_ts(it.modified)])
            row.setIcon(0, icon(TYPE_ICON.get(it.type, "key"), theme.WARN if it.favorite else theme.TEXT))
            row.setData(0, Qt.UserRole, it.id)
            if it.expires and it.expires < now:
                for c in range(4):
                    row.setForeground(c, Qt.red)
            self.list.addTopLevelItem(row)
            if it.id == keep:
                target = row
        self.list.setSortingEnabled(True)
        if target is not None:
            self.list.setCurrentItem(target)
        else:
            self.detail.clear()
            if self.list.topLevelItemCount() and not self.search.text():
                pass
        self.sb_count.setText(f"{self.list.topLevelItemCount()} shown · {self.vault.stats()['items']} items")

    def _list_changed(self, cur, _prev) -> None:
        if cur is None or not self.vault:
            self.detail.show_item(None)
            return
        it = self.vault.get_item(cur.data(0, Qt.UserRole), full=False)
        iid = cur.data(0, Qt.UserRole)
        self.detail.show_item(it, self.vault.folder_path(it.folder_id) if it else "", lambda key: self.vault.reveal(iid, key))

    def current_item(self, full: bool = False) -> Item | None:
        """Light item by default (no secrets in memory); full=True only when editing/duplicating."""
        cur = self.list.currentItem()
        return self.vault.get_item(cur.data(0, Qt.UserRole), full=full) if cur and self.vault else None

    # ------------------------------------------------------------------ context menus
    def _list_menu(self, pos) -> None:
        it = self.current_item()
        if not it:
            return
        m = QMenu(self)
        if it.deleted:
            m.addAction("Restore", self.restore_item)
            m.addAction("Delete forever", self.delete_item)
        else:
            if it.username:
                m.addAction(icon("copy"), "Copy username\tCtrl+U", lambda: self.copy_field("username"))
            if "password" in it.has:
                m.addAction(icon("copy"), "Copy password\tCtrl+P", lambda: self.copy_field("password"))
            if "totp" in it.has:
                m.addAction(icon("clock"), "Copy TOTP code\tCtrl+T", lambda: self.copy_field("totp"))
            if it.uri:
                m.addAction(icon("globe"), "Open URL", self.open_url)
            m.addSeparator()
            m.addAction(icon("edit"), "Edit\tCtrl+E", self.edit_item)
            m.addAction("Duplicate", self.duplicate_item)
            fm = m.addMenu(icon("folder"), "Move to folder")
            fm.addAction("(no folder)", lambda: self._move(None))
            for f in sorted(self.vault.folders(), key=lambda f: self.vault.folder_path(f["id"]).lower()):
                fm.addAction(self.vault.folder_path(f["id"]), lambda fid=f["id"]: self._move(fid))
            m.addAction(icon("star"), "Remove from favorites" if it.favorite else "Add to favorites", self.toggle_favorite)
            m.addSeparator()
            m.addAction(icon("trash"), "Move to trash\tDel", self.delete_item)
        m.exec(self.list.viewport().mapToGlobal(pos))

    def _sidebar_menu(self, pos) -> None:
        n = self.sidebar.itemAt(pos)
        kind, val = (n.data(0, Qt.UserRole) or (None, None)) if n else (None, None)
        m = QMenu(self)
        if kind in ("folder", None):
            m.addAction("New folder", lambda: self.new_folder(None))
        if kind == "folder":
            m.addAction("New subfolder", lambda: self.new_folder(val))
            m.addAction("Rename", lambda: self.rename_folder(val))
            m.addAction("Delete folder (items are kept)", lambda: self.delete_folder(val))
        if kind == "trash":
            m.addAction("Empty trash", self.empty_trash)
        if not m.isEmpty():
            m.exec(self.sidebar.viewport().mapToGlobal(pos))

    # ------------------------------------------------------------------ actions
    def new_item(self) -> None:
        if not self.vault:
            return
        kind, val = self._filter
        d = ItemDialog(self.vault, self.qs, folder_id=val if kind == "folder" else None, parent=self)
        if kind == "type":
            d.type_combo.setCurrentIndex(d.type_combo.findData(val))
        if kind == "fav":
            d.fav.setChecked(True)
        if kind == "tag":
            d.tags.setText(val)
        if d.exec() == d.DialogCode.Accepted:
            self._do(self.vault.add_item, d.item)
            self.rebuild_sidebar()
            self.refresh_list(d.item.id)

    def edit_item(self) -> None:
        it = self.current_item(full=True)
        if not it or it.deleted:
            return
        d = ItemDialog(self.vault, self.qs, it, parent=self)
        if d.exec() == d.DialogCode.Accepted:
            self._do(self.vault.update_item, d.item)
            self.rebuild_sidebar()
            self.refresh_list(d.item.id)

    def duplicate_item(self) -> None:
        it = self.current_item(full=True)
        if it:
            import copy
            from .vault import new_id
            c = copy.deepcopy(it)
            c.id, c.name, c.created = new_id(), it.name + " (copy)", 0.0
            self._do(self.vault.add_item, c)
            self.rebuild_sidebar()
            self.refresh_list(c.id)

    def delete_item(self) -> None:
        it = self.current_item()
        if not it:
            return
        if it.deleted:
            if QMessageBox.question(self, "Delete forever", f"Permanently delete “{it.name}”? This cannot be undone.") != QMessageBox.Yes:
                return
            self._do(self.vault.purge_item, it.id)
        else:
            self._do(self.vault.trash_item, it.id)
        self.detail.clear()
        self.rebuild_sidebar()

    def restore_item(self) -> None:
        it = self.current_item()
        if it:
            self._do(self.vault.restore_item, it.id)
            self.detail.clear()
            self.rebuild_sidebar()

    def empty_trash(self) -> None:
        if QMessageBox.question(self, "Empty trash", "Permanently delete everything in the trash?") == QMessageBox.Yes:
            self._do(self.vault.empty_trash)
            self.rebuild_sidebar()

    def toggle_favorite(self) -> None:
        it = self.current_item()
        if it:
            self._do(self.vault.set_favorite, it.id, not it.favorite)
            self.rebuild_sidebar()
            self.refresh_list(it.id)
            self._list_changed(self.list.currentItem(), None)

    def _move(self, fid) -> None:
        it = self.current_item()
        if it:
            self._do(self.vault.move_item, it.id, fid)
            self.rebuild_sidebar()

    def show_history(self) -> None:
        it = self.current_item()
        if it:
            d = HistoryDialog(it, self.vault.history(it.id), self)
            d.copyRequested.connect(lambda text, label: self.clip.copy(text, label))
            d.exec()

    def new_folder(self, parent_id) -> None:
        name, ok = QInputDialog.getText(self, "New folder", "Name:")
        if ok and name.strip():
            self._do(self.vault.add_folder, name, parent_id)
            self.rebuild_sidebar()

    def rename_folder(self, fid) -> None:
        cur = next((f["name"] for f in self.vault.folders() if f["id"] == fid), "")
        name, ok = QInputDialog.getText(self, "Rename folder", "Name:", text=cur)
        if ok and name.strip():
            self._do(self.vault.rename_folder, fid, name)
            self.rebuild_sidebar()

    def delete_folder(self, fid) -> None:
        self._do(self.vault.delete_folder, fid)
        self._filter = ("all", None)
        self.rebuild_sidebar()

    # -- copy
    def copy_value(self, label: str, text: str, secret: bool, key: str = "") -> None:
        self.clip.seconds = int(self.qs.value("clipboard_s", 30))
        self.clip.copy(text, label, secret)
        if self.detail.item and self.vault and key in ("password", "totp"):
            self.vault.touch_used(self.detail.item.id)

    def copy_field(self, key: str) -> None:
        it = self.current_item()
        if not it:
            return
        if key == "username":
            if it.username:
                self.copy_value("Username", it.username, False, key)
            return
        if key not in it.has:
            return
        v = self.vault.reveal(it.id, key)
        if key == "totp":
            from . import totp
            try:
                self.copy_value("TOTP code", totp.parse(v).code(), True, "totp")
            except ValueError:
                self.statusBar().showMessage("Invalid TOTP secret", 4000)
            return
        self.copy_value(key.capitalize(), v, True, key)

    def open_url(self) -> None:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        from .detail import _safe_url
        it = self.current_item()
        u = _safe_url(it.uri) if it else None
        if u:
            QDesktopServices.openUrl(QUrl(u))

    # -- tools
    def open_generator(self) -> None:
        GeneratorDialog(self.qs, parent=self).exec()

    def open_audit(self) -> None:
        if not self.vault:
            return
        d = AuditDialog(self.vault.items(secrets=True), self.qs, self)   # the audit needs every password: decrypted only while it is open

        def goto(iid):
            d.accept()
            self._filter = ("all", None)
            self.sidebar.setCurrentItem(self._nodes[("all", None)])
            self.search.clear()
            self.refresh_list(iid)
        d.openItem.connect(goto)
        d.exec()

    def open_settings(self) -> None:
        if SettingsDialog(self.qs, self.vault, self).exec():
            self.clip.seconds = int(self.qs.value("clipboard_s", 30))

    # -- backup / import / export
    def backup_menu_popup(self) -> None:
        m = QMenu(self)
        m.addAction(icon("backup"), "Save a verified copy…", self.backup_copy)
        m.addAction(icon("shield"), "Emergency kit (zip with vault + recovery tool)…", self.backup_bundle)
        m.addAction(icon("open"), "Show automatic backups folder", self.show_backup_dir)
        m.exec(self.toolbar.mapToGlobal(self.toolbar.widgetForAction(self.act_backup).geometry().bottomLeft()))

    def backup_copy(self) -> None:
        if not self.vault:
            return
        name = time.strftime(os.path.splitext(os.path.basename(self.vault.path))[0] + "-%Y%m%d.pwdeck")
        p, _ = QFileDialog.getSaveFileName(self, "Save a copy of the vault", os.path.join(os.path.expanduser("~"), name), "PW Deck vault (*.pwdeck)")
        if p:
            try:
                n = self.vault.verify_file(self.vault.copy_to(p))
                QMessageBox.information(self, "Backup", f"Copy saved and verified ({n} items).\n\n{p}\n\n"
                                        "To restore it on any computer: install PW Deck, open this file and use the same master password.")
            except Exception as e:      # noqa: BLE001
                QMessageBox.critical(self, "Backup failed", str(e))

    def backup_bundle(self) -> None:
        if not self.vault:
            return
        p, _ = QFileDialog.getSaveFileName(self, "Emergency kit", os.path.join(os.path.expanduser("~"), "pwdeck-emergency-kit.zip"), "Zip (*.zip)")
        if p:
            try:
                backup.make_bundle(self.vault, p)
                QMessageBox.information(self, "Emergency kit", f"Saved:\n{p}\n\nIt contains the encrypted vault, the standalone recovery "
                                        "script and instructions. It does NOT contain your password or recovery key.")
            except Exception as e:      # noqa: BLE001
                QMessageBox.critical(self, "Backup failed", str(e))

    def show_backup_dir(self) -> None:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        d = str(self.qs.value("backup/dir", "") or "") or default_backup_dir(self.vault.path)
        os.makedirs(d, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(d))

    def import_file(self) -> None:
        if not self.vault:
            return
        p, _ = QFileDialog.getOpenFileName(self, "Import", "", "Password exports (*.csv *.json);;All files (*)")
        if not p:
            return
        try:
            items = importers.detect_and_parse(p)
        except Exception as e:          # noqa: BLE001
            QMessageBox.critical(self, "Import", f"Cannot import this file:\n{e}")
            return
        if QMessageBox.question(self, "Import", f"Found {len(items)} entries. Import them into this vault?\n"
                                "(exact duplicates are skipped)\n\nRemember to delete the exported file afterwards: it is not encrypted.") != QMessageBox.Yes:
            return
        res = self._do(importers.import_items, self.vault, items)
        if res:
            QMessageBox.information(self, "Import", f"Imported {res[0]}, skipped {res[1]} duplicates.")
        self.rebuild_sidebar()

    def export_menu_popup(self) -> None:
        m = QMenu(self)
        m.addAction("Export to CSV (plain text)…", lambda: self.export("csv"))
        m.addAction("Export to JSON (plain text)…", lambda: self.export("json"))
        m.exec(self.toolbar.mapToGlobal(self.toolbar.widgetForAction(self.act_export).geometry().bottomLeft()))

    def export(self, fmt: str) -> None:
        if not self.vault:
            return
        if QMessageBox.warning(self, "Unencrypted export", "The exported file will contain ALL your passwords in clear text. "
                               "Use it only to migrate to another program and delete it securely afterwards.\n\nContinue?",
                               QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        p, _ = QFileDialog.getSaveFileName(self, "Export", f"pwdeck-export.{fmt}", f"*.{fmt}")
        if p:
            try:
                importers.write_private(p, importers.export_csv(self.vault) if fmt == "csv" else importers.export_json(self.vault))
                self.statusBar().showMessage(f"Exported to {p} (file mode 600)", 8000)
            except OSError as e:
                QMessageBox.critical(self, "Export", str(e))
