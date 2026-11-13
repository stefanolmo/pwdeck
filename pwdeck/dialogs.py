"""Dialogs: generator, item editor, history, audit, settings, change password, recovery key."""
from __future__ import annotations

import time

from PySide6.QtCore import QDate, QSettings, Qt, QThread, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QListWidget, QListWidgetItem, QCheckBox, QComboBox, QDateEdit, QDialog, QDialogButtonBox, QFileDialog,
                               QFormLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
                               QPushButton, QSlider, QSpinBox, QTableWidget, QTableWidgetItem, QTabWidget, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from . import audit, generator, theme, totp
from .theme import icon
from .itemtypes import TYPE_ORDER, TYPES, type_fields, type_label
from .vault import MAX_ATTACHMENT, Item, Vault, VaultError
from .widgets import PasswordEdit, StrengthBar, mini_button


def fmt_ts(ts: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "—"


def fmt_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def load_gen_options(qs: QSettings) -> generator.GenOptions:
    o = generator.GenOptions()
    o.length = int(qs.value("gen/length", 20))
    for k in ("lower", "upper", "digits", "symbols", "avoid_ambiguous"):
        setattr(o, k, str(qs.value(f"gen/{k}", getattr(o, k))).lower() in ("true", "1"))
    return o


# ------------------------------------------------------------------------------------------ generator
class GeneratorDialog(QDialog):
    def __init__(self, qs: QSettings, use_button: bool = False, parent=None):
        super().__init__(parent)
        self.qs = qs
        self.setWindowTitle("Password generator")
        self.resize(480, 0)
        o = load_gen_options(qs)
        lay = QVBoxLayout(self)
        self.out = QLineEdit()
        self.out.setReadOnly(True)
        self.out.setStyleSheet(f"font-family:{theme.MONO}; font-size:17px; padding:8px;")
        lay.addWidget(self.out)
        self.bar = StrengthBar()
        lay.addWidget(self.bar)
        row = QHBoxLayout()
        row.addWidget(QLabel("Length"))
        self.slider = QSlider(Qt.Horizontal, minimum=8, maximum=128, value=o.length)
        self.spin = QSpinBox(minimum=8, maximum=128, value=o.length)
        self.slider.valueChanged.connect(self.spin.setValue)
        self.spin.valueChanged.connect(self.slider.setValue)
        row.addWidget(self.slider, 1)
        row.addWidget(self.spin)
        lay.addLayout(row)
        self.chk = {}
        for k, label in (("lower", "Lowercase a–z"), ("upper", "Uppercase A–Z"), ("digits", "Digits 0–9"),
                         ("symbols", "Symbols !@#$…"), ("avoid_ambiguous", "Avoid look-alike characters (I l 1 O 0 o)")):
            c = QCheckBox(label)
            c.setChecked(getattr(o, k))
            c.toggled.connect(self.regenerate)
            self.chk[k] = c
            lay.addWidget(c)
        self.spin.valueChanged.connect(self.regenerate)
        btns = QHBoxLayout()
        b_re = QPushButton("Regenerate")
        b_re.setIcon(icon("dice"))
        b_re.clicked.connect(self.regenerate)
        b_cp = QPushButton("Copy")
        b_cp.setIcon(icon("copy"))
        b_cp.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.out.text()))
        btns.addWidget(b_re)
        btns.addWidget(b_cp)
        btns.addStretch(1)
        b_close = QPushButton("Close")
        b_close.clicked.connect(self.reject)
        btns.addWidget(b_close)
        if use_button:
            b_use = QPushButton("Use this password")
            b_use.setObjectName("primary")
            b_use.clicked.connect(self.accept)
            btns.addWidget(b_use)
        lay.addLayout(btns)
        self.regenerate()

    def options(self) -> generator.GenOptions:
        return generator.GenOptions(length=self.spin.value(), **{k: c.isChecked() for k, c in self.chk.items()})

    def regenerate(self) -> None:
        try:
            self.out.setText(generator.generate(self.options()))
        except ValueError:
            self.out.setText("")
        self.bar.set_password(self.out.text())
        o = self.options()
        self.qs.setValue("gen/length", o.length)
        for k in self.chk:
            self.qs.setValue(f"gen/{k}", getattr(o, k))

    def password(self) -> str:
        return self.out.text()


# ------------------------------------------------------------------------------------------ item editor
class ItemDialog(QDialog):
    def __init__(self, vault: Vault, qs: QSettings, item: Item | None = None, folder_id: str | None = None, parent=None):
        super().__init__(parent)
        self.vault, self.qs = vault, qs
        self.item = item or Item(folder_id=folder_id)
        self.setWindowTitle("Edit item" if item else "New item")
        self.resize(580, 800)
        lay = QVBoxLayout(self)
        top = QFormLayout()
        self.type_combo = QComboBox()
        for t in TYPE_ORDER:
            self.type_combo.addItem(type_label(t), t)
        self.type_combo.setCurrentIndex(self.type_combo.findData(self.item.type))
        self.name = QLineEdit(self.item.name)
        self.name.setPlaceholderText("Name")
        self.folder = QComboBox()
        self.folder.addItem("(no folder)", None)
        for f in sorted(vault.folders(), key=lambda f: vault.folder_path(f["id"]).lower()):
            self.folder.addItem(vault.folder_path(f["id"]), f["id"])
        self.folder.setCurrentIndex(max(0, self.folder.findData(self.item.folder_id)))
        top.addRow("Type", self.type_combo)
        top.addRow("Name", self.name)
        top.addRow("Folder", self.folder)
        lay.addLayout(top)
        self.form = QFormLayout()
        self.form.setLabelAlignment(Qt.AlignTop | Qt.AlignRight)
        holder = QWidget()
        holder.setLayout(self.form)
        lay.addWidget(holder)
        self.widgets: dict[str, QWidget] = {}
        self.vals = {f.key: self.item.get(f.key) for t in TYPES for f in type_fields(t)}
        self._build_form()
        # tags / favorite / expiry
        meta = QFormLayout()
        self.tags = QLineEdit(", ".join(self.item.tags))
        self.tags.setPlaceholderText("comma separated")
        meta.addRow("Tags", self.tags)
        row = QHBoxLayout()
        self.exp_on = QCheckBox("Expires on")
        self.exp = QDateEdit(calendarPopup=True)
        self.exp.setDisplayFormat("yyyy-MM-dd")
        d = QDate.fromString(time.strftime("%Y-%m-%d", time.localtime(self.item.expires)), "yyyy-MM-dd") if self.item.expires \
            else QDate.currentDate().addYears(1)
        self.exp.setDate(d)
        self.exp_on.setChecked(bool(self.item.expires))
        self.exp.setEnabled(self.exp_on.isChecked())
        self.exp_on.toggled.connect(self.exp.setEnabled)
        self.fav = QCheckBox("Favorite")
        self.fav.setChecked(self.item.favorite)
        row.addWidget(self.exp_on)
        row.addWidget(self.exp)
        row.addStretch(1)
        row.addWidget(self.fav)
        meta.addRow("", row)
        lay.addLayout(meta)
        # custom fields
        lay.addWidget(QLabel("CUSTOM FIELDS", objectName="cardTitle"))
        self.cf = QTableWidget(0, 3)
        self.cf.setHorizontalHeaderLabels(["Label", "Value", "Hidden"])
        self.cf.verticalHeader().hide()
        self.cf.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.cf.setColumnWidth(0, 130)
        self.cf.setColumnWidth(2, 60)
        self.cf.setMaximumHeight(120)
        for f in self.item.fields:
            self._add_cf(f.get("label", ""), f.get("value", ""), f.get("hidden", False))
        lay.addWidget(self.cf)
        r = QHBoxLayout()
        b_add = QPushButton("＋ Field")
        b_add.clicked.connect(lambda: self._add_cf())
        b_del = QPushButton("Remove field")
        b_del.clicked.connect(lambda: self.cf.removeRow(self.cf.currentRow()) if self.cf.currentRow() >= 0 else None)
        r.addWidget(b_add)
        r.addWidget(b_del)
        r.addStretch(1)
        lay.addLayout(r)
        # attachments
        lay.addWidget(QLabel("ATTACHMENTS", objectName="cardTitle"))
        self.att = QListWidget()
        self.att.setMaximumHeight(92)
        self.att_existing = vault.attachments(self.item.id) if item else []
        self.att_pending: list[tuple[str, bytes]] = []
        self.att_removed: set[str] = set()
        lay.addWidget(self.att)
        ar = QHBoxLayout()
        b_aadd = QPushButton("＋ Attach file…")
        b_aadd.clicked.connect(self._add_att)
        b_asave = QPushButton("Save as…")
        b_asave.clicked.connect(self._save_att)
        b_adel = QPushButton("Remove")
        b_adel.clicked.connect(self._remove_att)
        for b in (b_aadd, b_asave, b_adel):
            ar.addWidget(b)
        ar.addStretch(1)
        lay.addLayout(ar)
        self._refresh_att()
        self.err = QLabel("")
        self.err.setStyleSheet(f"color:{theme.DANGER};")
        lay.addWidget(self.err)
        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.button(QDialogButtonBox.Save).setObjectName("primary")
        bb.accepted.connect(self._accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self._cur_type = self.item.type
        self.type_combo.currentIndexChanged.connect(self._type_changed)

    # -- attachments (applied to the vault only when the item is saved: see apply_attachments)
    def _refresh_att(self) -> None:
        self.att.clear()
        for a in self.att_existing:
            if a["id"] not in self.att_removed:
                it = QListWidgetItem(f"{a['name']}   ({fmt_size(a['size'])})")
                it.setData(Qt.UserRole, ("old", a["id"]))
                self.att.addItem(it)
        for i, (name, data) in enumerate(self.att_pending):
            it = QListWidgetItem(f"{name}   ({fmt_size(len(data))})  — new")
            it.setData(Qt.UserRole, ("new", i))
            self.att.addItem(it)

    def _add_att(self) -> None:
        import os
        paths, _ = QFileDialog.getOpenFileNames(self, "Attach files")
        for p in paths:
            try:
                if os.path.getsize(p) > MAX_ATTACHMENT:
                    self.err.setText(f"{os.path.basename(p)} is larger than {MAX_ATTACHMENT // (1 << 20)} MiB: not attached.")
                    continue
                with open(p, "rb") as f:
                    self.att_pending.append((os.path.basename(p), f.read()))
            except OSError as e:
                self.err.setText(str(e))
        self._refresh_att()

    def _selected_att(self):
        cur = self.att.currentItem()
        return cur.data(Qt.UserRole) if cur else None

    def _save_att(self) -> None:
        sel = self._selected_att()
        if not sel:
            return
        kind, ref = sel
        name, data = self.vault.get_attachment(ref) if kind == "old" else self.att_pending[ref]
        p, _ = QFileDialog.getSaveFileName(self, "Save attachment", name)
        if p:
            from .importers import write_private_bytes
            write_private_bytes(p, data)

    def _remove_att(self) -> None:
        sel = self._selected_att()
        if not sel:
            return
        kind, ref = sel
        if kind == "old":
            self.att_removed.add(ref)
        else:
            del self.att_pending[ref]
        self._refresh_att()

    def apply_attachments(self, vault: Vault, item_id: str) -> None:
        """Call after the item itself was saved: removes / adds the attachments chosen in the dialog."""
        for aid in self.att_removed:
            vault.delete_attachment(aid)
        with vault.batch():
            for name, data in self.att_pending:
                vault.add_attachment(item_id, name, data)
        self.att_removed, self.att_pending = set(), []

    # -- dynamic form
    def _add_cf(self, label="", value="", hidden=False):
        r = self.cf.rowCount()
        self.cf.insertRow(r)
        self.cf.setItem(r, 0, QTableWidgetItem(label))
        self.cf.setItem(r, 1, QTableWidgetItem(value))
        chk = QTableWidgetItem()
        chk.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
        chk.setCheckState(Qt.Checked if hidden else Qt.Unchecked)
        self.cf.setItem(r, 2, chk)
        self.cf.setCurrentCell(r, 0)

    def _read_widgets(self) -> None:
        for k, w in self.widgets.items():
            if isinstance(w, PasswordEdit):
                self.vals[k] = w.text()
            elif isinstance(w, QPlainTextEdit):
                t = w.toPlainText()
                self.vals[k] = [x.strip() for x in t.splitlines() if x.strip()] if k == "uris" else t
            elif isinstance(w, QLineEdit):
                self.vals[k] = w.text().strip() if k != "totp" else w.text().strip()
            elif isinstance(w, QWidget) and hasattr(w, "_line"):
                self.vals[k] = w._line.text().strip()

    def _build_form(self) -> None:
        while self.form.rowCount():
            self.form.removeRow(0)
        self.widgets = {}
        t = self.type_combo.currentData()
        for f in type_fields(t):
            v = self.vals.get(f.key, "")
            if f.kind == "secret":
                w = PasswordEdit(generate=(f.key == "password"), strength=(f.key == "password"))
                w.setText(v or "")
                if f.key == "password":
                    w.generateRequested.connect(lambda w=w: self._generate(w))
            elif f.kind in ("multi", "secretmulti"):
                w = QPlainTextEdit(v or "")
                w.setFixedHeight(80 if f.kind == "multi" else 110)
                if f.key in ("private_key", "public_key"):
                    w.setStyleSheet(f"font-family:{theme.MONO}; font-size:11px;")
            elif f.kind == "uris":
                w = QPlainTextEdit("\n".join(v or []))
                w.setFixedHeight(54)
                w.setPlaceholderText("one per line")
            elif f.kind == "totp":
                w = QWidget()
                hl = QHBoxLayout(w)
                hl.setContentsMargins(0, 0, 0, 0)
                line = QLineEdit(v or "")
                line.setPlaceholderText("Base32 secret or otpauth:// URI")
                line.setEchoMode(QLineEdit.Password)
                disp = QLabel("")
                disp.setStyleSheet(f"font-family:{theme.MONO}; color:{theme.ACCENT}; font-weight:700;")
                eye = mini_button("eye", "Show / hide", checkable=True)
                eye.toggled.connect(lambda on, l=line: l.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password))
                hl.addWidget(line, 1)
                hl.addWidget(disp)
                hl.addWidget(eye)
                w._line, w._disp = line, disp
                line.textChanged.connect(lambda _t, w=w: self._totp_preview(w))
                self._totp_preview(w)
            else:
                w = QLineEdit(v or "")
            self.widgets[f.key] = w
            self.form.addRow(f.label, w)

    def _totp_preview(self, w) -> None:
        txt = w._line.text().strip()
        if not txt:
            w._disp.setText("")
            return
        try:
            w._disp.setText(totp.parse(txt).code())
        except ValueError:
            w._disp.setText("invalid")

    def _type_changed(self) -> None:
        self._read_widgets()
        self._build_form()

    def _generate(self, w: PasswordEdit) -> None:
        d = GeneratorDialog(self.qs, use_button=True, parent=self)
        if d.exec() == QDialog.Accepted:
            w.setText(d.password())
            w.show_text(True)

    # -- result
    def _accept(self) -> None:
        self._read_widgets()
        if not self.name.text().strip():
            self.err.setText("The name is required.")
            return
        for t in (self.vals.get("totp"),):
            if t:
                try:
                    totp.parse(t)
                except ValueError:
                    self.err.setText("The TOTP secret is not valid (use a Base32 secret or an otpauth:// URI).")
                    return
        it = self.item
        it.type = self.type_combo.currentData()
        it.name = self.name.text().strip()
        it.folder_id = self.folder.currentData()
        keep = {f.key for f in type_fields(it.type)}
        for t in TYPES:
            for f in type_fields(t):
                if f.key in keep:
                    it.set(f.key, self.vals.get(f.key, [] if f.kind == "uris" else ""))
                elif f.key in it.extra:
                    it.extra.pop(f.key)               # drop data of fields the new type does not have
        for k in ("username", "password", "description", "totp"):
            if k not in keep:
                it.set(k, "")
        if "uris" not in keep:
            it.uris = []
        it.tags = [t.strip() for t in self.tags.text().split(",") if t.strip()]
        it.favorite = self.fav.isChecked()
        it.expires = time.mktime(self.exp.date().toPython().timetuple()) + 86399 if self.exp_on.isChecked() else None
        it.fields = []
        for r in range(self.cf.rowCount()):
            label = (self.cf.item(r, 0).text() if self.cf.item(r, 0) else "").strip()
            val = self.cf.item(r, 1).text() if self.cf.item(r, 1) else ""
            if label or val:
                it.fields.append({"label": label, "value": val, "hidden": self.cf.item(r, 2).checkState() == Qt.Checked})
        self.accept()


# ------------------------------------------------------------------------------------------ history
class HistoryDialog(QDialog):
    copyRequested = Signal(str, str)

    def __init__(self, item: Item, versions: list[dict], parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"History — {item.name}")
        self.resize(560, 380)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Previous values of the secret fields (newest first). Kept for the last 25 changes.", objectName="muted"))
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Valid until", "Field", "Value"])
        self.tree.setRootIsDecorated(False)
        self.versions = versions
        for v in versions:
            for k, val in v["data"].items():
                shown = val if isinstance(val, str) else f"{len(val)} custom field(s)"
                it = QTreeWidgetItem([fmt_ts(v["ts"]), k, "•" * 10 if k != "description" else shown[:60]])
                it.setData(2, Qt.UserRole, shown)
                self.tree.addTopLevelItem(it)
        self.tree.header().setSectionResizeMode(2, QHeaderView.Stretch)
        lay.addWidget(self.tree, 1)
        row = QHBoxLayout()
        b_show = QPushButton("Reveal")
        b_show.clicked.connect(self._reveal)
        b_copy = QPushButton("Copy")
        b_copy.clicked.connect(self._copy)
        b_close = QPushButton("Close")
        b_close.clicked.connect(self.accept)
        row.addWidget(b_show)
        row.addWidget(b_copy)
        row.addStretch(1)
        row.addWidget(b_close)
        lay.addLayout(row)
        if not versions:
            lay.insertWidget(1, QLabel("No previous versions."))

    def _reveal(self) -> None:
        it = self.tree.currentItem()
        if it:
            it.setText(2, it.data(2, Qt.UserRole))

    def _copy(self) -> None:
        it = self.tree.currentItem()
        if it:
            self.copyRequested.emit(it.data(2, Qt.UserRole), it.text(1))


# ------------------------------------------------------------------------------------------ audit
class _Hibp(QThread):
    done = Signal(list, str)

    def __init__(self, items: list[Item]):
        super().__init__()
        self.items = items

    def run(self) -> None:
        out, err, cache = [], "", {}
        try:
            for it in self.items:
                if it.password not in cache:
                    cache[it.password] = audit.hibp_count(it.password)
                if cache[it.password]:
                    out.append((it, f"seen {cache[it.password]:,} times in breaches"))
        except OSError as e:
            err = str(e)
        self.done.emit(out, err)


class AuditDialog(QDialog):
    openItem = Signal(str)
    TABS = [("weak", "Weak"), ("reused", "Reused"), ("old", "Old"), ("expired", "Expired"), ("no2fa", "No TOTP"), ("pwned", "Breached")]

    def __init__(self, items: list[Item], qs: QSettings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Security audit")
        self.resize(640, 520)
        self.items = items
        age = int(qs.value("audit/max_age_days", 365))
        self.report = audit.analyze(items, age)
        self.report["pwned"] = []
        lay = QVBoxLayout(self)
        self.summary = QLabel()
        self.summary.setObjectName("h1")
        lay.addWidget(self.summary)
        lay.addWidget(QLabel(f"Weak = estimated < 45 bit · Old = password unchanged for over {age} days · "
                             "“No TOTP” is only a hint for login items with a URL.", objectName="muted"))
        self.tabs = QTabWidget()
        self.trees: dict[str, QTreeWidget] = {}
        for key, label in self.TABS:
            t = QTreeWidget()
            t.setHeaderLabels(["Item", "Detail"])
            t.setRootIsDecorated(False)
            t.header().setSectionResizeMode(0, QHeaderView.Stretch)
            t.itemDoubleClicked.connect(lambda ti, *_: self.openItem.emit(ti.data(0, Qt.UserRole)))
            self.trees[key] = t
            self.tabs.addTab(t, label)
        lay.addWidget(self.tabs, 1)
        row = QHBoxLayout()
        self.b_hibp = QPushButton("Check breaches online…")
        self.b_hibp.setToolTip("Sends only the first 5 characters of each password's SHA-1 hash to api.pwnedpasswords.com")
        self.b_hibp.clicked.connect(self._hibp)
        self.status = QLabel("", objectName="muted")
        b_close = QPushButton("Close")
        b_close.clicked.connect(self.accept)
        row.addWidget(self.b_hibp)
        row.addWidget(self.status, 1)
        row.addWidget(b_close)
        lay.addLayout(row)
        self._fill()

    def _fill(self) -> None:
        for i, (key, label) in enumerate(self.TABS):
            t = self.trees[key]
            t.clear()
            for it, detail in self.report[key]:
                ti = QTreeWidgetItem([it.name, detail])
                ti.setData(0, Qt.UserRole, it.id)
                t.addTopLevelItem(ti)
            self.tabs.setTabText(i, f"{label} ({len(self.report[key])})")
        sc = audit.score(self.items, self.report)
        self.summary.setText(f"Vault health: {sc}%")
        col = theme.OK if sc >= 80 else theme.WARN if sc >= 50 else theme.DANGER
        self.summary.setStyleSheet(f"color:{col};")

    def _hibp(self) -> None:
        if QMessageBox.question(self, "Check breaches", "Each password is hashed (SHA-1) locally and only the first 5 hex characters "
                                "are sent to api.pwnedpasswords.com. Continue?") != QMessageBox.Yes:
            return
        self.b_hibp.setEnabled(False)
        self.status.setText("Checking…")
        self._th = _Hibp([i for i in self.items if i.password])
        self._th.done.connect(self._hibp_done)
        self._th.start()

    def done(self, r: int) -> None:
        th = getattr(self, "_th", None)
        if th is not None and th.isRunning():
            th.wait(10000)              # never destroy a running QThread
        super().done(r)

    def _hibp_done(self, found: list, err: str) -> None:
        self.report["pwned"] = found
        self._fill()
        self.b_hibp.setEnabled(True)
        self.status.setText(f"Network error: {err}" if err else f"Done: {len(found)} breached password(s)")
        if found:
            self.tabs.setCurrentIndex(len(self.TABS) - 1)


# ------------------------------------------------------------------------------------------ keys
class RecoveryKeyDialog(QDialog):
    def __init__(self, key: str, vault_path: str, parent=None):
        super().__init__(parent)
        self.key = key
        self.setWindowTitle("Recovery key")
        self.setModal(True)
        self.resize(520, 0)
        lay = QVBoxLayout(self)
        t = QLabel("Save your recovery key", objectName="h1")
        lay.addWidget(t)
        lay.addWidget(QLabel("If you forget the master password, this key is the ONLY way to open the vault.\n"
                             "Print it or write it down and keep it somewhere safe and separate from the vault file "
                             "(not in the same cloud folder). It is shown only now.", wordWrap=True))
        box = QLabel(key)
        box.setAlignment(Qt.AlignCenter)
        box.setTextInteractionFlags(Qt.TextSelectableByMouse)
        box.setStyleSheet(f"font-family:{theme.MONO}; font-size:19px; font-weight:700; color:{theme.ACCENT};"
                          f"background:#0b0f14; border:1px solid {theme.BORDER}; border-radius:8px; padding:16px;")
        lay.addWidget(box)
        row = QHBoxLayout()
        b_cp = QPushButton("Copy")
        b_cp.clicked.connect(lambda: QGuiApplication.clipboard().setText(key))
        b_sv = QPushButton("Save as text file…")
        b_sv.clicked.connect(self._save)
        row.addWidget(b_cp)
        row.addWidget(b_sv)
        row.addStretch(1)
        lay.addLayout(row)
        self.ok = QCheckBox("I have stored the recovery key in a safe place")
        lay.addWidget(self.ok)
        bb = QDialogButtonBox(QDialogButtonBox.Ok)
        self.btn = bb.button(QDialogButtonBox.Ok)
        self.btn.setEnabled(False)
        self.btn.setObjectName("primary")
        self.ok.toggled.connect(self.btn.setEnabled)
        bb.accepted.connect(self.accept)
        lay.addWidget(bb)
        self._vp = vault_path

    def _save(self) -> None:
        p, _ = QFileDialog.getSaveFileName(self, "Save recovery key", "pwdeck-recovery-key.txt", "Text (*.txt)")
        if p:
            with open(p, "w") as f:
                f.write(f"PW Deck recovery key\nVault: {self._vp}\nCreated: {fmt_ts(time.time())}\n\n{self.key}\n\n"
                        "Keep this sheet away from the vault file. Anyone with this key and the vault file can read all passwords.\n")

    def reject(self) -> None:           # must be acknowledged: Esc does nothing until the box is ticked
        if self.ok.isChecked():
            super().reject()


class ChangePasswordDialog(QDialog):
    def __init__(self, vault: Vault, parent=None):
        super().__init__(parent)
        self.vault = vault
        self.keyfile: bytes | None = None
        self.setWindowTitle("Change master password")
        self.resize(460, 0)
        lay = QVBoxLayout(self)
        f = QFormLayout()
        self.cur = PasswordEdit()
        self.new = PasswordEdit(strength=True)
        self.new2 = PasswordEdit()
        f.addRow("Current password", self.cur)
        if vault.via_recovery:        # unlocked with the recovery key: the old password is exactly what was lost
            self.cur.hide()
            f.labelForField(self.cur).hide()
            lay.insertWidget(0, QLabel("You unlocked the vault with the recovery key.\nChoose a new master password; the recovery key stays valid.",
                                       wordWrap=True))
        f.addRow("New password", self.new)
        f.addRow("Repeat", self.new2)
        lay.addLayout(f)
        self.kf_info = QLabel("")
        self.cur_kf = None
        if vault.uses_keyfile and not vault.via_recovery:
            b = QPushButton("Select the current keyfile…")
            b.clicked.connect(self._pick_cur_kf)
            lay.addWidget(b)
        self.chk_kf = QCheckBox("Protect the new password with a keyfile")
        lay.addWidget(self.chk_kf)
        b2 = QPushButton("Choose or create the new keyfile…")
        b2.clicked.connect(self._pick_new_kf)
        lay.addWidget(b2)
        lay.addWidget(self.kf_info)
        self.err = QLabel("")
        self.err.setStyleSheet(f"color:{theme.DANGER};")
        lay.addWidget(self.err)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _pick_cur_kf(self) -> None:
        p, _ = QFileDialog.getOpenFileName(self, "Current keyfile")
        if p:
            self.cur_kf = open(p, "rb").read()

    def _pick_new_kf(self) -> None:
        self.keyfile = pick_or_create_keyfile(self)
        if self.keyfile:
            self.chk_kf.setChecked(True)
            self.kf_info.setText("Keyfile ready. Keep a copy somewhere safe: without it the vault cannot be opened.")

    def _ok(self) -> None:
        if not self.vault.via_recovery and not self.vault.verify_password(self.cur.text(), self.cur_kf):
            self.err.setText("The current password (or keyfile) is wrong.")
        elif len(self.new.text()) < 8:
            self.err.setText("The new password must be at least 8 characters.")
        elif self.new.text() != self.new2.text():
            self.err.setText("The two new passwords differ.")
        elif self.chk_kf.isChecked() and self.keyfile is None:
            self.err.setText("Choose or create the keyfile first.")
        else:
            self.accept()

    def apply(self) -> None:
        self.vault.change_password(self.new.text(), self.keyfile if self.chk_kf.isChecked() else None)


def pick_or_create_keyfile(parent) -> bytes | None:
    """Asks the user to create a new random keyfile or pick an existing one. Returns its bytes."""
    import os
    box = QMessageBox(parent)
    box.setWindowTitle("Keyfile")
    box.setText("Create a new random keyfile, or use an existing file?")
    b_new = box.addButton("Create new…", QMessageBox.AcceptRole)
    b_old = box.addButton("Use existing file…", QMessageBox.AcceptRole)
    box.addButton(QMessageBox.Cancel)
    box.exec()
    if box.clickedButton() is b_new:
        p, _ = QFileDialog.getSaveFileName(parent, "Save keyfile", "pwdeck.key")
        if not p:
            return None
        data = os.urandom(128)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return data
    if box.clickedButton() is b_old:
        p, _ = QFileDialog.getOpenFileName(parent, "Select keyfile")
        return open(p, "rb").read() if p else None
    return None


class KdfDialog(QDialog):
    """Shows the vault's key derivation and re-derives the password slot with a stronger setting (e.g. scrypt -> Argon2id)."""

    def __init__(self, vault: Vault, parent=None):
        super().__init__(parent)
        self.vault = vault
        self.cur_kf: bytes | None = None
        self.setWindowTitle("Key derivation")
        self.resize(480, 0)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"Current: <b>{vault.kdf_info}</b>", wordWrap=True))
        lay.addWidget(QLabel("Re-deriving the key needs your master password. The vault content is not re-encrypted; the recovery key stays valid.",
                             objectName="muted", wordWrap=True))
        f = QFormLayout()
        self.combo = QComboBox()
        self.combo.addItem("Standard — Argon2id, 256 MiB", "standard")
        self.combo.addItem("High — Argon2id, 512 MiB", "high")
        f.addRow("New setting", self.combo)
        self.pw = PasswordEdit()
        f.addRow("Master password", self.pw)
        lay.addLayout(f)
        if vault.uses_keyfile:
            b = QPushButton("Select the keyfile…")
            b.setIcon(icon("key"))
            b.clicked.connect(self._pick)
            lay.addWidget(b)
        self.err = QLabel("")
        self.err.setStyleSheet(f"color:{theme.DANGER};")
        lay.addWidget(self.err)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _pick(self) -> None:
        p, _ = QFileDialog.getOpenFileName(self, "Keyfile")
        if p:
            self.cur_kf = open(p, "rb").read()

    def _ok(self) -> None:
        if not self.vault.verify_password(self.pw.text(), self.cur_kf):
            self.err.setText("Wrong password (or keyfile).")
            return
        try:
            self.vault.change_password(self.pw.text(), self.cur_kf, self.combo.currentData())
        except Exception as e:      # noqa: BLE001
            self.err.setText(str(e))
            return
        self.accept()


# ------------------------------------------------------------------------------------------ settings
class SettingsDialog(QDialog):
    def __init__(self, qs: QSettings, vault: Vault | None, parent=None):
        super().__init__(parent)
        self.qs, self.vault = qs, vault
        self.setWindowTitle("Settings")
        self.resize(520, 0)
        lay = QVBoxLayout(self)
        f = QFormLayout()
        self.autolock = QSpinBox(minimum=0, maximum=480, value=int(qs.value("autolock_min", 5)), suffix=" min")
        self.autolock.setSpecialValueText("never")
        self.lock_min = QCheckBox("Lock when the window is minimized")
        self.lock_min.setChecked(str(qs.value("lock_on_minimize", False)).lower() in ("true", "1"))
        self.lock_susp = QCheckBox("Lock when the screen is locked or the PC suspends")
        self.lock_susp.setChecked(str(qs.value("lock_on_suspend", True)).lower() in ("true", "1"))
        self.clip = QSpinBox(minimum=0, maximum=600, value=int(qs.value("clipboard_s", 30)), suffix=" s")
        self.clip.setSpecialValueText("never")
        self.age = QSpinBox(minimum=30, maximum=3650, value=int(qs.value("audit/max_age_days", 365)), suffix=" days")
        f.addRow("Auto-lock after", self.autolock)
        f.addRow("", self.lock_min)
        f.addRow("", self.lock_susp)
        f.addRow("Clear clipboard after", self.clip)
        f.addRow("Password considered old after", self.age)
        lay.addLayout(f)
        g = QWidget()
        gl = QFormLayout(g)
        gl.setContentsMargins(0, 8, 0, 0)
        self.bk_on = QCheckBox("Automatic backups (at most one per hour, when the vault is opened/closed)")
        self.bk_on.setChecked(str(qs.value("backup/auto", True)).lower() in ("true", "1"))
        self.bk_dir = QLineEdit(str(qs.value("backup/dir", "")))
        self.bk_dir.setPlaceholderText("default: 'backups' folder next to the vault")
        b = QPushButton("…")
        b.setFixedWidth(34)
        b.clicked.connect(self._pick_dir)
        r = QHBoxLayout()
        r.addWidget(self.bk_dir, 1)
        r.addWidget(b)
        self.bk_keep = QSpinBox(minimum=1, maximum=200, value=int(qs.value("backup/keep", 10)))
        gl.addRow(self.bk_on)
        gl.addRow("Backup folder", r)
        gl.addRow("Backups to keep", self.bk_keep)
        lay.addWidget(g)
        lay.addWidget(QLabel("Tip: point the backup folder to a different disk, a USB stick or a synced folder — the files are "
                             "already encrypted.", objectName="muted", wordWrap=True))
        if vault:
            row = QHBoxLayout()
            b1 = QPushButton("Change master password…")
            b1.setIcon(icon("key"))
            b1.clicked.connect(self._chpw)
            b3 = QPushButton("Key derivation…" + ("  (upgrade available)" if vault.kdf_is_legacy else ""))
            b3.setIcon(icon("gear"))
            b3.clicked.connect(self._kdf)
            b2 = QPushButton("New recovery key…")
            b2.setIcon(icon("shield"))
            b2.clicked.connect(self._newrk)
            row.addWidget(b1)
            row.addWidget(b2)
            lay.addLayout(row)
            lay.addWidget(b3)
        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._save)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _pick_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Backup folder")
        if d:
            self.bk_dir.setText(d)

    def _chpw(self) -> None:
        d = ChangePasswordDialog(self.vault, self)
        if d.exec() == QDialog.Accepted:
            d.apply()
            QMessageBox.information(self, "Master password", "Master password changed. The recovery key is still valid.")

    def _kdf(self) -> None:
        d = KdfDialog(self.vault, self)
        if d.exec() == QDialog.Accepted:
            QMessageBox.information(self, "Key derivation", f"Done. Now: {self.vault.kdf_info}")

    def _newrk(self) -> None:
        if QMessageBox.question(self, "New recovery key", "The old recovery key will stop working. Continue?") == QMessageBox.Yes:
            RecoveryKeyDialog(self.vault.new_recovery_key(), self.vault.path, self).exec()

    def _save(self) -> None:
        q = self.qs
        q.setValue("autolock_min", self.autolock.value())
        q.setValue("lock_on_minimize", self.lock_min.isChecked())
        q.setValue("lock_on_suspend", self.lock_susp.isChecked())
        q.setValue("clipboard_s", self.clip.value())
        q.setValue("audit/max_age_days", self.age.value())
        q.setValue("backup/auto", self.bk_on.isChecked())
        q.setValue("backup/dir", self.bk_dir.text().strip())
        q.setValue("backup/keep", self.bk_keep.value())
        self.accept()
