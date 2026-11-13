"""Unlock and create-vault dialogs."""
from __future__ import annotations

import os

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QVBoxLayout)

from . import crypto, generator, theme
from .dialogs import RecoveryKeyDialog, pick_or_create_keyfile
from .theme import icon
from .vault import (CorruptVaultError, NotAVaultError, Vault, VaultError, VaultLockedError, WrongPasswordError)
from .widgets import PasswordEdit

VAULT_FILTER = "PW Deck vault (*.pwdeck);;All files (*)"


class UnlockDialog(QDialog):
    """Result in `.vault` (an open Vault) after exec() == Accepted."""

    def __init__(self, qs: QSettings, path: str | None = None, parent=None):
        super().__init__(parent)
        self.qs = qs
        self.vault: Vault | None = None
        self.path = path if path and os.path.exists(path) else None
        self.keyfile_path = str(qs.value("keyfile_path", "") or "")
        self.setWindowTitle("Unlock vault")
        self.setModal(True)
        self.resize(480, 0)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Unlock vault", objectName="h1"))
        self.path_lbl = QLabel()
        self.path_lbl.setObjectName("muted")
        self.path_lbl.setWordWrap(True)
        lay.addWidget(self.path_lbl)
        self.pw = PasswordEdit()
        self.pw.edit.setPlaceholderText("Master password")
        self.pw.edit.returnPressed.connect(self._unlock)
        lay.addWidget(self.pw)
        self.rk = QLineEdit()
        self.rk.setPlaceholderText("Recovery key  XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX")
        self.rk.setStyleSheet(f"font-family:{theme.MONO};")
        self.rk.returnPressed.connect(self._unlock)
        self.rk.hide()
        lay.addWidget(self.rk)
        self.kf_btn = QPushButton("Select keyfile…")
        self.kf_btn.setIcon(icon("key"))
        self.kf_btn.clicked.connect(self._pick_kf)
        lay.addWidget(self.kf_btn)
        self.use_rk = QCheckBox("I forgot the password: use the recovery key")
        self.use_rk.toggled.connect(self._toggle_rk)
        lay.addWidget(self.use_rk)
        self.err = QLabel("")
        self.err.setWordWrap(True)
        self.err.setStyleSheet(f"color:{theme.DANGER};")
        lay.addWidget(self.err)
        row = QHBoxLayout()
        b_open = QPushButton("Open other…")
        b_open.setIcon(icon("open"))
        b_open.clicked.connect(self._open_other)
        b_new = QPushButton("New vault…")
        b_new.setIcon(icon("plus"))
        b_new.clicked.connect(self._new)
        b_quit = QPushButton("Cancel")
        b_quit.clicked.connect(self.reject)
        self.b_ok = QPushButton("Unlock")
        self.b_ok.setObjectName("primary")
        self.b_ok.setDefault(True)
        self.b_ok.clicked.connect(self._unlock)
        row.addWidget(b_open)
        row.addWidget(b_new)
        row.addStretch(1)
        row.addWidget(b_quit)
        row.addWidget(self.b_ok)
        lay.addLayout(row)
        self._refresh()

    def _refresh(self) -> None:
        need_kf = False
        if self.path:
            self.path_lbl.setText(self.path)
            try:
                need_kf = Vault.peek(self.path)["keyfile"]
            except (OSError, VaultError):
                pass
        else:
            self.path_lbl.setText("No vault selected: open an existing file or create a new one.")
        self.b_ok.setEnabled(bool(self.path))
        self.kf_btn.setVisible(need_kf and not self.use_rk.isChecked())
        self.kf_btn.setText(f"Keyfile: {os.path.basename(self.keyfile_path)}" if self.keyfile_path else "Select keyfile…")

    def _toggle_rk(self, on: bool) -> None:
        self.rk.setVisible(on)
        self.pw.setVisible(not on)
        self._refresh()
        (self.rk if on else self.pw.edit).setFocus()

    def _pick_kf(self) -> None:
        p, _ = QFileDialog.getOpenFileName(self, "Keyfile", os.path.dirname(self.keyfile_path) if self.keyfile_path else "")
        if p:
            self.keyfile_path = p
            self.qs.setValue("keyfile_path", p)
            self._refresh()

    def _open_other(self) -> None:
        p, _ = QFileDialog.getOpenFileName(self, "Open vault", os.path.dirname(self.path or ""), VAULT_FILTER)
        if p:
            self.path = p
            self.err.setText("")
            self._refresh()

    def _new(self) -> None:
        d = CreateVaultDialog(self.qs, self)
        if d.exec() == QDialog.Accepted:
            self.vault = d.vault
            self.accept()

    def _unlock(self) -> None:
        if not self.path:
            return
        QGuiApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            kf = None
            if Vault.peek(self.path)["keyfile"] and not self.use_rk.isChecked():
                if not self.keyfile_path or not os.path.exists(self.keyfile_path):
                    self.err.setText("This vault needs its keyfile: select it first.")
                    return
                kf = open(self.keyfile_path, "rb").read()
            if self.use_rk.isChecked():
                self.vault = Vault.open(self.path, recovery_key=self.rk.text())
            else:
                self.vault = Vault.open(self.path, self.pw.text(), kf)
            self.accept()
        except WrongPasswordError:
            self.err.setText("Wrong recovery key." if self.use_rk.isChecked() else "Wrong password or keyfile.")
            self.pw.edit.selectAll()
        except (NotAVaultError, CorruptVaultError, VaultLockedError) as e:
            self.err.setText(str(e))
        except OSError as e:
            self.err.setText(f"Cannot read the file: {e}")
        finally:
            QGuiApplication.restoreOverrideCursor()


class CreateVaultDialog(QDialog):
    def __init__(self, qs: QSettings, parent=None):
        super().__init__(parent)
        self.qs = qs
        self.vault: Vault | None = None
        self.keyfile: bytes | None = None
        self.setWindowTitle("New vault")
        self.setModal(True)
        self.resize(500, 0)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Create a new vault", objectName="h1"))
        lay.addWidget(QLabel("One encrypted file: copy it anywhere to back it up or move it to another computer.", objectName="muted", wordWrap=True))
        f = QFormLayout()
        row = QHBoxLayout()
        self.path = QLineEdit(os.path.join(os.path.expanduser("~"), "passwords.pwdeck"))
        b = QPushButton("…")
        b.setFixedWidth(34)
        b.clicked.connect(self._pick)
        row.addWidget(self.path, 1)
        row.addWidget(b)
        f.addRow("File", row)
        self.pw = PasswordEdit(strength=True)
        self.pw2 = PasswordEdit()
        f.addRow("Master password", self.pw)
        f.addRow("Repeat", self.pw2)
        self.kdf = QComboBox()
        self.kdf.addItem("Standard (128 MiB, ~0.5 s)", "standard")
        self.kdf.addItem("High (256 MiB, ~1 s) — slower to brute-force", "high")
        f.addRow("Key derivation", self.kdf)
        lay.addLayout(f)
        self.use_kf = QCheckBox("Also require a keyfile (second factor: a file you keep separately)")
        self.use_kf.toggled.connect(self._kf_toggled)
        lay.addWidget(self.use_kf)
        self.kf_lbl = QLabel("", objectName="muted")
        lay.addWidget(self.kf_lbl)
        self.err = QLabel("")
        self.err.setWordWrap(True)
        self.err.setStyleSheet(f"color:{theme.DANGER};")
        lay.addWidget(self.err)
        r = QHBoxLayout()
        r.addStretch(1)
        c = QPushButton("Cancel")
        c.clicked.connect(self.reject)
        self.ok = QPushButton("Create vault")
        self.ok.setObjectName("primary")
        self.ok.clicked.connect(self._create)
        r.addWidget(c)
        r.addWidget(self.ok)
        lay.addLayout(r)

    def _pick(self) -> None:
        p, _ = QFileDialog.getSaveFileName(self, "New vault", self.path.text(), VAULT_FILTER)
        if p:
            self.path.setText(p if p.endswith(".pwdeck") else p + ".pwdeck")

    def _kf_toggled(self, on: bool) -> None:
        if on:
            self.keyfile = pick_or_create_keyfile(self)
            if self.keyfile is None:
                self.use_kf.blockSignals(True)
                self.use_kf.setChecked(False)
                self.use_kf.blockSignals(False)
            else:
                self.kf_lbl.setText("Keyfile ready. Store a copy separately: without it the vault cannot be opened.")
        else:
            self.keyfile = None
            self.kf_lbl.setText("")

    def _create(self) -> None:
        path = self.path.text().strip()
        if not path:
            self.err.setText("Choose where to save the vault.")
        elif os.path.exists(path):
            self.err.setText("That file already exists: choose another name.")
        elif not os.path.isdir(os.path.dirname(os.path.abspath(path))):
            self.err.setText("The folder does not exist.")
        elif len(self.pw.text()) < 8:
            self.err.setText("The master password must be at least 8 characters.")
        elif self.pw.text() != self.pw2.text():
            self.err.setText("The two passwords differ.")
        else:
            if generator.estimate(self.pw.text())[0] < 45 and QMessageBox.question(
                    self, "Weak password", "This master password looks weak. Anyone who gets the vault file can try to guess it "
                    "offline. Use it anyway?") != QMessageBox.Yes:
                return
            QGuiApplication.setOverrideCursor(Qt.WaitCursor)
            try:
                self.vault, rk = Vault.create(path, self.pw.text(), self.keyfile if self.use_kf.isChecked() else None,
                                              self.kdf.currentData())
            except (OSError, VaultError) as e:
                self.err.setText(str(e))
                return
            finally:
                QGuiApplication.restoreOverrideCursor()
            RecoveryKeyDialog(rk, path, self).exec()
            self.accept()
