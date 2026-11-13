"""Reusable widgets: card, strength bar, password field, secure clipboard, TOTP display."""
from __future__ import annotations

from PySide6.QtCore import QMimeData, QObject, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QGuiApplication, QPainter
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QLineEdit, QToolButton, QVBoxLayout, QWidget)

from . import generator, theme
from .theme import icon

STRENGTH_COLORS = ["#f87171", "#fb923c", "#fbbf24", "#a3e635", "#34d399"]


class Card(QFrame):
    def __init__(self, title: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(14, 12, 14, 14)
        self._lay.setSpacing(10)
        if title:
            t = QLabel(title.upper())
            t.setObjectName("cardTitle")
            self._lay.addWidget(t)
        self.body = QVBoxLayout()
        self.body.setSpacing(8)
        self._lay.addLayout(self.body)


def mini_button(name: str, tip: str = "", color: str = theme.TEXT, checkable: bool = False) -> QToolButton:
    b = QToolButton()
    b.setObjectName("mini")
    b.setIcon(icon(name, color))
    b.setIconSize(QSize(17, 17))
    b.setToolTip(tip)
    b.setCheckable(checkable)
    b.setCursor(Qt.PointingHandCursor)
    b.setFocusPolicy(Qt.NoFocus)
    return b


class StrengthBar(QWidget):
    """Five segments + label (e.g. 'Good · 71 bits')."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(18)
        self.bits, self.score, self._empty = 0.0, 0, True

    def set_password(self, pw: str) -> None:
        self._empty = not pw
        self.bits, self.score = generator.estimate(pw)
        self.update()

    def paintEvent(self, _ev) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w = self.width() - 150
        seg = (w - 4 * 4) / 5
        for i in range(5):
            on = not self._empty and i <= self.score
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(STRENGTH_COLORS[self.score]) if on else QColor("#243040"))
            p.drawRoundedRect(QRectF(i * (seg + 4), 5, seg, 6), 3, 3)
        p.setPen(QColor(theme.MUTED))
        txt = "" if self._empty else f"{generator.LABELS[self.score]} · {int(self.bits)} bit"
        p.drawText(QRectF(w + 10, 0, 140, 16), Qt.AlignVCenter | Qt.AlignLeft, txt)


class PasswordEdit(QWidget):
    """Hidden-by-default line edit with show/hide, optional generate button and strength bar."""
    textChanged = Signal(str)
    generateRequested = Signal()

    def __init__(self, generate: bool = False, strength: bool = False, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)
        row = QHBoxLayout()
        row.setSpacing(4)
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.Password)
        self.edit.setStyleSheet(f"font-family:{theme.MONO};")
        row.addWidget(self.edit, 1)
        self.eye = mini_button("eye", "Show / hide", checkable=True)
        self.eye.toggled.connect(lambda on: (self.edit.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password),
                                             self.eye.setIcon(icon("eyeoff" if on else "eye"))))
        row.addWidget(self.eye)
        if generate:
            g = mini_button("dice", "Generate a password", theme.ACCENT)
            g.clicked.connect(self.generateRequested)
            row.addWidget(g)
        lay.addLayout(row)
        self.bar = StrengthBar() if strength else None
        if self.bar:
            lay.addWidget(self.bar)
        self.edit.textChanged.connect(self._changed)

    def _changed(self, t: str) -> None:
        if self.bar:
            self.bar.set_password(t)
        self.textChanged.emit(t)

    def text(self) -> str:
        return self.edit.text()

    def setText(self, t: str) -> None:
        self.edit.setText(t)

    def show_text(self, on: bool = True) -> None:
        self.eye.setChecked(on)


class SecureClipboard(QObject):
    """Copies a secret and wipes it after `seconds` — but only if the clipboard still holds our value."""
    changed = Signal(str)            # status message

    def __init__(self, seconds: int = 30, parent=None):
        super().__init__(parent)
        self.seconds = seconds
        self._value: str | None = None
        self._timer = QTimer(self, singleShot=True)
        self._timer.timeout.connect(self.clear)

    def copy(self, text: str, label: str = "", secret: bool = True) -> None:
        cb = QGuiApplication.clipboard()
        md = QMimeData()
        md.setText(text)
        if secret:
            md.setData("x-kde-passwordManagerHint", b"secret")      # asks Klipper & co. not to store it in the history
        cb.setMimeData(md)
        self._value = text
        if secret and self.seconds > 0:
            self._timer.start(self.seconds * 1000)
            self.changed.emit(f"{label or 'Value'} copied — the clipboard is cleared in {self.seconds} s")
        else:
            self._timer.stop()
            self.changed.emit(f"{label or 'Value'} copied")

    def clear(self) -> None:
        cb = QGuiApplication.clipboard()
        if self._value is not None and cb.text() == self._value:
            cb.clear()
            self.changed.emit("Clipboard cleared")
        self._value = None
        self._timer.stop()


class TotpDisplay(QWidget):
    """Live code with a countdown bar, e.g. '482 913'. Call refresh() every second."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.t = None
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.code = QLabel("—")
        self.code.setStyleSheet(f"font-family:{theme.MONO}; font-size:22px; font-weight:700; color:{theme.ACCENT};")
        self.left = QLabel("")
        self.left.setObjectName("muted")
        self.left.setFixedWidth(34)
        self.left.setAlignment(Qt.AlignCenter)
        lay.addWidget(self.code)
        lay.addStretch(1)
        lay.addWidget(self.left)

    def set_totp(self, t) -> None:
        self.t = t
        self.refresh()

    def current(self) -> str:
        return self.t.code() if self.t else ""

    def refresh(self) -> None:
        if not self.t:
            self.code.setText("invalid secret")
            self.left.setText("")
            return
        c = self.t.code()
        half = len(c) // 2
        self.code.setText(f"{c[:half]} {c[half:]}")
        rem = self.t.remaining()
        self.left.setText(f"{int(rem) + 1}s")
        warn = rem < 5
        self.left.setStyleSheet(f"color:{theme.WARN if warn else theme.MUTED}; font-weight:700;")
