"""Right-hand panel: shows one item with copy / reveal buttons and a live TOTP code."""
from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget)

from . import theme, totp
from .dialogs import fmt_ts
from .theme import icon
from .types import type_fields, type_label
from .vault import Item
from .widgets import Card, TotpDisplay, mini_button

TYPE_ICON = {"password": "key", "totp": "clock", "note": "note", "card": "card", "ssh": "terminal", "custom": "grid"}


def _safe_url(u: str) -> str | None:
    u = u.strip()
    if "://" not in u and "." in u and " " not in u:
        u = "https://" + u
    return u if u.lower().startswith(("http://", "https://", "ssh://", "ftp://", "ftps://", "sftp://")) else None


MASK = "•" * 12


class FieldRow(QWidget):
    """One labelled value. Secret rows never hold the value: `getter()` decrypts it only when the user reveals or copies it,
    and hiding drops the text again (fixed-width mask, so the length is not leaked either)."""

    def __init__(self, label: str, getter, secret: bool, emit, key: str, mono: bool = False, parent=None):
        super().__init__(parent)
        self.getter, self.secret, self.shown = getter, secret, False
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 2, 0, 2)
        col = QVBoxLayout()
        col.setSpacing(1)
        cap = QLabel(label.upper())
        cap.setObjectName("cardTitle")
        self.lbl = QLabel()
        self.lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbl.setWordWrap(True)
        self.lbl.setStyleSheet(f"font-family:{theme.MONO}; font-size:13px;" if (secret or mono) else "font-size:13px;")
        col.addWidget(cap)
        col.addWidget(self.lbl)
        lay.addLayout(col, 1)
        if secret:
            self.eye = mini_button("eye", "Show / hide", checkable=True)
            self.eye.toggled.connect(self._toggle)
            lay.addWidget(self.eye, 0, Qt.AlignTop)
        cp = mini_button("copy", "Copy")
        cp.clicked.connect(lambda: emit(label, self.getter(), secret, key))
        lay.addWidget(cp, 0, Qt.AlignTop)
        self._render()

    def _toggle(self, on: bool) -> None:
        self.shown = on
        self.eye.setIcon(icon("eyeoff" if on else "eye"))
        self._render()

    def _render(self) -> None:
        self.lbl.setText(self.getter() if (self.shown or not self.secret) else MASK)


class DetailPanel(QWidget):
    copyRequested = Signal(str, str, bool, str)      # label, text, secret, key
    editRequested = Signal()
    deleteRequested = Signal()
    restoreRequested = Signal()
    favoriteToggled = Signal()
    historyRequested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.item: Item | None = None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.empty = QLabel("Select an item")
        self.empty.setAlignment(Qt.AlignCenter)
        self.empty.setObjectName("muted")
        outer.addWidget(self.empty)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.scroll.hide()
        outer.addWidget(self.scroll)
        self.totp_widgets: list[TotpDisplay] = []
        self._timer = QTimer(self, interval=1000)
        self._timer.timeout.connect(lambda: [w.refresh() for w in self.totp_widgets])
        self._timer.start()

    def clear(self) -> None:
        self.item = None
        self.totp_widgets = []
        self.scroll.hide()
        self.empty.show()
        w = self.scroll.takeWidget()
        if w:
            w.deleteLater()

    def show_item(self, it: Item | None, folder: str = "", reveal=None) -> None:
        """`it` is a light item (no secret values); `reveal(key)` decrypts a single value on demand."""
        self.clear()
        if it is None:
            return
        self.item = it
        self.empty.hide()
        root = QWidget()
        lay = QVBoxLayout(root)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(12)
        head = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icon(TYPE_ICON.get(it.type, "key"), theme.ACCENT).pixmap(30, 30))
        title = QVBoxLayout()
        title.setSpacing(0)
        name = QLabel(it.name)
        name.setObjectName("h1")
        name.setWordWrap(True)
        title.addWidget(name)
        sub = QLabel(type_label(it.type) + (f" · {folder}" if folder else ""))
        sub.setObjectName("muted")
        title.addWidget(sub)
        head.addWidget(ic)
        head.addLayout(title, 1)
        lay.addLayout(head)
        row = QHBoxLayout()
        if it.deleted:
            b = QPushButton("Restore")
            b.setIcon(icon("restore"))
            b.clicked.connect(self.restoreRequested)
            row.addWidget(b)
            b = QPushButton("Delete forever")
            b.setObjectName("danger")
            b.setIcon(icon("trash"))
            b.clicked.connect(self.deleteRequested)
            row.addWidget(b)
        else:
            b = QPushButton("Edit")
            b.setIcon(icon("edit"))
            b.clicked.connect(self.editRequested)
            row.addWidget(b)
            self.fav_btn = mini_button("starfill" if it.favorite else "star", "Favorite", theme.WARN if it.favorite else theme.TEXT)
            self.fav_btn.clicked.connect(self.favoriteToggled)
            row.addWidget(self.fav_btn)
            b = mini_button("history", "History of changes")
            b.clicked.connect(self.historyRequested)
            row.addWidget(b)
            b = mini_button("trash", "Move to trash", theme.DANGER)
            b.clicked.connect(self.deleteRequested)
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)

        card = Card()
        any_row = False
        for f in type_fields(it.type):
            key = f.key
            if f.kind == "uris":
                for u in it.uris:
                    any_row = True
                    card.body.addWidget(self._uri_row(f.label, u))
            elif key == "username":
                if it.username:
                    any_row = True
                    card.body.addWidget(FieldRow(f.label, lambda v=it.username: v, False, self._emit, key, mono=True))
            elif key in it.has:
                any_row = True
                if f.kind == "totp":
                    card.body.addWidget(self._totp_row(f.label, reveal(key)))
                elif f.kind in ("secret", "secretmulti") or key == "description":     # descriptions often hold recovery codes
                    card.body.addWidget(FieldRow(f.label, lambda k=key: reveal(k), True, self._emit, key))
                else:                                           # description, holder, expiry, public key…: shown when selected
                    card.body.addWidget(FieldRow(f.label, (lambda v: lambda: v)(reveal(key)), False, self._emit, key, mono=(key == "number")))
        for i, cf in enumerate(it.fields):
            if f"field:{i}" in it.has:
                any_row = True
                k = f"field:{i}"
                if cf.get("hidden"):
                    card.body.addWidget(FieldRow(cf.get("label") or "Field", lambda k=k: reveal(k), True, self._emit, "custom"))
                else:
                    card.body.addWidget(FieldRow(cf.get("label") or "Field", (lambda v: lambda: v)(reveal(k)), False, self._emit, "custom"))
        if not any_row:
            card.body.addWidget(QLabel("(empty)", objectName="muted"))
        lay.addWidget(card)

        meta = []
        if it.tags:
            meta.append("Tags: " + ", ".join(it.tags))
        if it.expires:
            import time
            expired = it.expires < time.time()
            meta.append(("⚠ EXPIRED " if expired else "Expires ") + fmt_ts(it.expires)[:10])
        meta.append(f"Modified {fmt_ts(it.modified)} · Created {fmt_ts(it.created)}")
        if "password" in it.has:
            meta.append(f"Password changed {fmt_ts(it.pw_changed)[:10]}")
        m = QLabel("\n".join(meta))
        m.setObjectName("muted")
        m.setWordWrap(True)
        lay.addWidget(m)
        lay.addStretch(1)
        self.scroll.setWidget(root)
        self.scroll.show()

    def _emit(self, label, value, secret, key) -> None:
        self.copyRequested.emit(label, value, secret, key)

    def _uri_row(self, label: str, uri: str) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 2, 0, 2)
        col = QVBoxLayout()
        col.setSpacing(1)
        col.addWidget(QLabel(label.upper(), objectName="cardTitle"))
        l = QLabel(uri)
        l.setWordWrap(True)
        l.setTextInteractionFlags(Qt.TextSelectableByMouse)
        col.addWidget(l)
        lay.addLayout(col, 1)
        url = _safe_url(uri)
        if url:
            b = mini_button("globe", "Open in browser")
            b.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(url)))
            lay.addWidget(b, 0, Qt.AlignTop)
        cp = mini_button("copy", "Copy")
        cp.clicked.connect(lambda: self._emit(label, uri, False, "uri"))
        lay.addWidget(cp, 0, Qt.AlignTop)
        return w

    def _totp_row(self, label: str, value: str) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 2, 0, 2)
        col = QVBoxLayout()
        col.setSpacing(1)
        col.addWidget(QLabel(label.upper(), objectName="cardTitle"))
        d = TotpDisplay()
        try:
            d.set_totp(totp.parse(value))
        except ValueError:
            d.set_totp(None)
        self.totp_widgets.append(d)
        col.addWidget(d)
        lay.addLayout(col, 1)
        cp = mini_button("copy", "Copy the current code")
        cp.clicked.connect(lambda: d.current() and self._emit("TOTP code", d.current(), True, "totp"))
        lay.addWidget(cp, 0, Qt.AlignTop)
        return w
