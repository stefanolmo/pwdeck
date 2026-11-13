"""Dark theme (same palette as CNC Deck) and procedurally drawn vector icons."""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

BG = "#0e1217"
PANEL = "#141a21"
CARD = "#1a222c"
CARD_HI = "#222c38"
BORDER = "#2a3544"
TEXT = "#d9e1ea"
MUTED = "#7f8d9f"
ACCENT = "#2dd4bf"
ACCENT_DIM = "#14766b"
OK = "#34d399"
RUN = "#4aa8ff"
WARN = "#fbbf24"
DANGER = "#f87171"
MONO = "'JetBrains Mono','Ubuntu Mono','DejaVu Sans Mono','Liberation Mono',monospace"


STYLESHEET = f"""
* {{ font-size: 13px; }}
QWidget {{ background: {BG}; color: {TEXT}; }}
QMainWindow, QDialog {{ background: {BG}; }}
QToolTip {{ background: {CARD_HI}; color: {TEXT}; border: 1px solid {BORDER}; padding: 4px; }}
QFrame#card {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 10px; }}
QFrame#card QWidget {{ background: transparent; }}
QLabel#cardTitle {{ color: {MUTED}; font-size: 11px; font-weight: 700; letter-spacing: 1.5px; }}
QLabel#muted {{ color: {MUTED}; }}
QLabel#mono {{ font-family: {MONO}; }}
QPushButton, QToolButton {{
    background: {CARD_HI}; border: 1px solid {BORDER}; border-radius: 7px; padding: 6px 12px; color: {TEXT};
}}
QPushButton:hover, QToolButton:hover {{ background: #2c3847; border-color: #3c4b5f; }}
QPushButton:pressed, QToolButton:pressed {{ background: {ACCENT_DIM}; border-color: {ACCENT}; }}
QPushButton:disabled, QToolButton:disabled {{ color: #4d5866; background: #171e26; border-color: #202a36; }}
QPushButton#primary {{ background: {ACCENT}; color: #04211d; border: none; font-weight: 700; }}
QPushButton#primary:hover {{ background: #5eead4; }}
QPushButton#primary:disabled {{ background: #1c3a37; color: #4b7a74; }}
QPushButton#danger {{ background: #5b1f24; border-color: #8f3038; }}
QPushButton#danger:hover {{ background: #7a2a31; }}
QPushButton:checked, QToolButton:checked {{ background: {ACCENT_DIM}; border-color: {ACCENT}; }}
QToolButton#run {{ background: #14532d; border-color: #1f7a45; }}
QToolButton#run:hover {{ background: #1a6b3b; }}
QToolButton#run:disabled {{ background: #17221d; border-color: #1f2d26; }}
QToolButton#stopb {{ background: #5b1f24; border-color: #8f3038; }}
QToolButton#stopb:hover {{ background: #7a2a31; }}
QToolButton#stopb:disabled {{ background: #231a1c; border-color: #31232a; }}
QToolButton#jog {{ padding: 0; border-radius: 9px; background: #232e3b; }}
QToolButton#jog:pressed {{ background: {ACCENT}; }}
QComboBox, QLineEdit, QDoubleSpinBox, QSpinBox {{
    background: #10161d; border: 1px solid {BORDER}; border-radius: 6px; padding: 4px 8px;
    selection-background-color: {ACCENT_DIM};
}}
QComboBox:focus, QLineEdit:focus, QDoubleSpinBox:focus, QSpinBox:focus {{ border-color: {ACCENT}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{ background: {CARD}; border: 1px solid {BORDER}; selection-background-color: {ACCENT_DIM}; outline: 0; }}
QSlider::groove:horizontal {{ height: 4px; background: {BORDER}; border-radius: 2px; }}
QSlider::sub-page:horizontal {{ background: {ACCENT}; border-radius: 2px; }}
QSlider::handle:horizontal {{ background: {TEXT}; width: 14px; height: 14px; margin: -5px 0; border-radius: 7px; }}
QPlainTextEdit, QTextEdit, QTableWidget {{
    background: #0b0f14; border: 1px solid {BORDER}; border-radius: 8px;
    font-family: {MONO}; font-size: 12px; selection-background-color: {ACCENT_DIM};
}}
QListWidget {{ background: #0b0f14; border: 1px solid {BORDER}; border-radius: 8px; padding: 3px; outline: 0; }}
QListWidget::item {{ padding: 4px 6px; border-radius: 5px; }}
QListWidget::item:selected {{ background: {ACCENT_DIM}; color: {TEXT}; }}
QListWidget::item:hover {{ background: #18212b; }}
QListWidget::indicator {{ width: 15px; height: 15px; border-radius: 4px; border: 1px solid {BORDER}; background: #10161d; }}
QListWidget::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 8px; top: -1px; }}
QTabBar::tab {{ background: transparent; color: {MUTED}; padding: 7px 16px; border: none; border-bottom: 2px solid transparent; }}
QTabBar::tab:selected {{ color: {TEXT}; border-bottom: 2px solid {ACCENT}; }}
QTabBar::tab:hover {{ color: {TEXT}; }}
QHeaderView::section {{ background: {CARD}; color: {MUTED}; border: none; border-bottom: 1px solid {BORDER}; padding: 5px; }}
QTableWidget {{ gridline-color: #1c2530; alternate-background-color: #0e141a; }}
QProgressBar {{ background: #10161d; border: 1px solid {BORDER}; border-radius: 6px; text-align: center; height: 16px; color: {TEXT}; }}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 5px; }}
QStatusBar {{ background: {PANEL}; border-top: 1px solid {BORDER}; }}
QStatusBar::item {{ border: none; }}
QToolBar {{ background: {PANEL}; border: none; border-bottom: 1px solid {BORDER}; spacing: 6px; padding: 6px 8px; }}
QToolBar QToolButton {{ padding: 6px 10px; }}
QScrollBar:vertical {{ background: transparent; width: 10px; }}
QScrollBar::handle:vertical {{ background: #2c3847; border-radius: 5px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: #3d4d60; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; }}
QScrollBar::handle:horizontal {{ background: #2c3847; border-radius: 5px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 4px; border: 1px solid {BORDER}; background: #10161d; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
QMenu {{ background: {CARD}; border: 1px solid {BORDER}; padding: 4px; }}
QMenu::item {{ padding: 6px 22px; border-radius: 4px; }}
QMenu::item:selected {{ background: {ACCENT_DIM}; }}
QSplitter::handle {{ background: {BG}; }}
QMessageBox {{ background: {CARD}; }}

QTreeWidget, QTreeView {{ background: #0b0f14; border: 1px solid {BORDER}; border-radius: 8px; padding: 3px; outline: 0; alternate-background-color: #0e141a; }}
QTreeWidget::item {{ padding: 5px 4px; border-radius: 5px; }}
QTreeWidget::item:selected {{ background: {ACCENT_DIM}; color: {TEXT}; }}
QTreeWidget::item:hover:!selected {{ background: #18212b; }}
QTreeWidget#sidebar {{ background: {PANEL}; border: none; border-right: 1px solid {BORDER}; border-radius: 0; font-size: 13px; }}
QDateEdit {{ background: #10161d; border: 1px solid {BORDER}; border-radius: 6px; padding: 4px 8px; }}
QDialogButtonBox QPushButton {{ min-width: 80px; }}
QGroupBox {{ border: 1px solid {BORDER}; border-radius: 8px; margin-top: 12px; padding-top: 10px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; color: {MUTED}; padding: 0 4px; }}
QLabel#h1 {{ font-size: 22px; font-weight: 800; }}
QLabel#badge {{ color: {ACCENT}; background: rgba(45,212,191,38); border: 1px solid {ACCENT_DIM}; border-radius: 9px; padding: 1px 8px; font-size: 11px; font-weight: 700; }}
QPushButton#ghost {{ background: transparent; border: none; padding: 4px 8px; color: {MUTED}; }}
QPushButton#ghost:hover {{ color: {TEXT}; background: {CARD_HI}; }}
QMenuBar {{ background: {PANEL}; border-bottom: 1px solid {BORDER}; padding: 1px 4px; }}
QMenuBar::item {{ padding: 5px 10px; border-radius: 5px; background: transparent; }}
QMenuBar::item:selected {{ background: {CARD_HI}; }}
QToolBar QWidget#spacer {{ background: transparent; }}
QToolButton#mini {{ padding: 3px 6px; border-radius: 6px; background: transparent; border: 1px solid transparent; }}
QToolButton#mini:hover {{ background: {CARD_HI}; border-color: {BORDER}; }}
QToolButton#mini:pressed {{ background: {ACCENT_DIM}; }}
"""


def _icon(draw, color: str = TEXT, size: int = 64) -> QIcon:
    icon = QIcon()
    for col, mode in ((color, QIcon.Normal), ("#4d5866", QIcon.Disabled)):
        pm = QPixmap(size, size)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing)
        p.scale(size / 24, size / 24)
        pen = QPen(QColor(col), 2.2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        p.setPen(pen)
        p.setBrush(Qt.NoBrush)
        draw(p, QColor(col))
        p.end()
        icon.addPixmap(pm, mode)
    return icon


def _poly(p, pts, close=False, fill=None):
    path = QPainterPath(QPointF(*pts[0]))
    for pt in pts[1:]:
        path.lineTo(*pt)
    if close:
        path.closeSubpath()
    if fill is not None:
        p.fillPath(path, fill)
    else:
        p.drawPath(path)


def _rr(p, x, y, w, h, r=2):
    p.drawRoundedRect(QRectF(x, y, w, h), r, r)


def _lock(p, c): _rr(p, 5, 11, 14, 10, 2.5); p.drawArc(QRectF(8, 3, 8, 10), 0, 180 * 16); p.drawLine(QPointF(8, 8), QPointF(8, 11)); p.drawLine(QPointF(16, 8), QPointF(16, 11)); p.setBrush(c); p.drawEllipse(QPointF(12, 15.5), 1.3, 1.3)
def _unlock(p, c): _rr(p, 5, 11, 14, 10, 2.5); p.drawArc(QRectF(8, 3, 8, 10), 0, 180 * 16); p.drawLine(QPointF(16, 8), QPointF(16, 6.5)); p.drawLine(QPointF(8, 8), QPointF(8, 11))
def _key(p, c): p.drawEllipse(QPointF(8, 12), 4.2, 4.2); _poly(p, [(12, 12), (21, 12)]); _poly(p, [(18, 12), (18, 15.5)]); _poly(p, [(21, 12), (21, 14.5)])
def _plus(p, c): _poly(p, [(12, 5), (12, 19)]); _poly(p, [(5, 12), (19, 12)])
def _trash(p, c): _poly(p, [(4.5, 7), (19.5, 7)]); _poly(p, [(9, 7), (9, 4.5), (15, 4.5), (15, 7)]); _poly(p, [(6.5, 7), (7.5, 20), (16.5, 20), (17.5, 7)]); _poly(p, [(10.5, 10.5), (10.5, 16.5)]); _poly(p, [(13.5, 10.5), (13.5, 16.5)])
def _star(p, c): _poly(p, [(12, 3.5), (14.6, 9.2), (20.8, 9.8), (16.2, 14), (17.5, 20.2), (12, 17), (6.5, 20.2), (7.8, 14), (3.2, 9.8), (9.4, 9.2)], True)
def _starfill(p, c): _poly(p, [(12, 3.5), (14.6, 9.2), (20.8, 9.8), (16.2, 14), (17.5, 20.2), (12, 17), (6.5, 20.2), (7.8, 14), (3.2, 9.8), (9.4, 9.2)], True, c); _star(p, c)
def _folder(p, c): _poly(p, [(3, 7), (3, 19), (21, 19), (21, 9), (11, 9), (9, 6), (3, 6), (3, 7)])
def _copy(p, c): _rr(p, 8.5, 8.5, 11, 11, 2); _poly(p, [(15.5, 8.5), (15.5, 6), (5.5, 6), (5.5, 16), (8.5, 16)])
def _eye(p, c): p.drawArc(QRectF(2.5, 6, 19, 12), 0, 180 * 16); p.drawArc(QRectF(2.5, 6, 19, 12), 180 * 16, 180 * 16); p.drawEllipse(QPointF(12, 12), 3, 3)
def _eyeoff(p, c): _eye(p, c); _poly(p, [(4, 20), (20, 4)])
def _edit(p, c): _poly(p, [(4, 20), (4, 16), (15.5, 4.5), (19.5, 8.5), (8, 20), (4, 20)]); _poly(p, [(13, 7), (17, 11)])
def _search(p, c): p.drawEllipse(QPointF(10.5, 10.5), 6, 6); _poly(p, [(15, 15), (20.5, 20.5)])
def _shield(p, c): _poly(p, [(12, 3), (19.5, 6), (19.5, 12), (12, 21), (4.5, 12), (4.5, 6)], True); _poly(p, [(8.5, 11.5), (11, 14), (15.5, 9)])
def _backup(p, c): _poly(p, [(12, 3.5), (12, 15)]); _poly(p, [(7.5, 10.5), (12, 15), (16.5, 10.5)]); _poly(p, [(4, 15), (4, 20), (20, 20), (20, 15)])
def _restore(p, c): _poly(p, [(12, 20.5), (12, 9)]); _poly(p, [(7.5, 13.5), (12, 9), (16.5, 13.5)]); _poly(p, [(4, 9), (4, 4), (20, 4), (20, 9)])
def _dice(p, c):
    _rr(p, 4, 4, 16, 16, 3.5); p.setBrush(c)
    for x, y in ((8.5, 8.5), (15.5, 8.5), (12, 12), (8.5, 15.5), (15.5, 15.5)):
        p.drawEllipse(QPointF(x, y), 1.1, 1.1)
def _globe(p, c): p.drawEllipse(QPointF(12, 12), 8.5, 8.5); p.drawEllipse(QPointF(12, 12), 3.6, 8.5); _poly(p, [(3.5, 12), (20.5, 12)])
def _note(p, c): _poly(p, [(6, 3.5), (15, 3.5), (19, 7.5), (19, 20.5), (6, 20.5)], True); _poly(p, [(9, 11), (16, 11)]); _poly(p, [(9, 14.5), (16, 14.5)])
def _card(p, c): _rr(p, 3, 6, 18, 12, 2.5); _poly(p, [(3, 10), (21, 10)]); _poly(p, [(6, 15), (10, 15)])
def _clock(p, c): p.drawEllipse(QPointF(12, 12), 8.5, 8.5); _poly(p, [(12, 7), (12, 12), (15.5, 14)])
def _tag(p, c): _poly(p, [(3.5, 12), (12, 3.5), (20.5, 3.5), (20.5, 12), (12, 20.5)], True); p.setBrush(c); p.drawEllipse(QPointF(16, 8), 1.3, 1.3)
def _gear(p, c):
    import math
    p.drawEllipse(QPointF(12, 12), 3, 3)
    for i in range(8):
        a = i * math.pi / 4
        p.drawLine(QPointF(12 + 6.5 * math.cos(a), 12 + 6.5 * math.sin(a)), QPointF(12 + 9 * math.cos(a), 12 + 9 * math.sin(a)))
    p.drawEllipse(QPointF(12, 12), 6.5, 6.5)
def _import(p, c): _poly(p, [(12, 3.5), (12, 15)]); _poly(p, [(7.5, 10.5), (12, 15), (16.5, 10.5)]); _poly(p, [(4, 18), (20, 18)])
def _export(p, c): _poly(p, [(12, 15), (12, 3.5)]); _poly(p, [(7.5, 8), (12, 3.5), (16.5, 8)]); _poly(p, [(4, 18), (20, 18)])
def _history(p, c): p.drawArc(QRectF(4, 4, 16, 16), 30 * 16, 300 * 16); _poly(p, [(12, 8), (12, 12), (15, 13.5)]); _poly(p, [(17.5, 1.5), (20, 7), (14.5, 7.5)], True, c)
def _terminal(p, c): _rr(p, 3, 5, 18, 14, 2.5); _poly(p, [(7, 10), (10, 12.5), (7, 15)]); _poly(p, [(12, 15), (16, 15)])
def _grid(p, c): [_rr(p, x, y, 6.5, 6.5, 1.5) for x in (4, 13.5) for y in (4, 13.5)]
def _warn(p, c): _poly(p, [(12, 4), (21, 19.5), (3, 19.5)], True); _poly(p, [(12, 10), (12, 14.5)]); p.setBrush(c); p.drawEllipse(QPointF(12, 17), 0.6, 0.6)
def _check(p, c): _poly(p, [(4, 12.5), (9.5, 18), (20, 6)])
def _open(p, c): _poly(p, [(3, 7), (3, 19), (19, 19), (21, 11), (8, 11), (6, 19)]); _poly(p, [(3, 7), (9, 7), (11, 9), (18, 9), (18, 11)])
def _link(p, c): _poly(p, [(10, 14), (14, 10)]); _poly(p, [(11, 7), (13, 5), (19, 11), (17, 13)]); _poly(p, [(13, 17), (11, 19), (5, 13), (7, 11)])
def _minimize(p, c): _poly(p, [(6, 17), (18, 17)])
def _maximize(p, c): _rr(p, 5.5, 5.5, 13, 13, 2)
def _restore(p, c): _rr(p, 5.5, 8.5, 10, 10, 2); _poly(p, [(9, 8.5), (9, 5.5), (18.5, 5.5), (18.5, 15), (15.5, 15)])
def _close(p, c): _poly(p, [(6, 6), (18, 18)]); _poly(p, [(18, 6), (6, 18)])
def _lockfill(p, c): _lock(p, c)


_NAMES = ("lock unlock key plus trash star starfill folder copy eye eyeoff edit search shield backup restore dice globe note "
          "card clock tag gear import export history terminal grid warn check open link minimize maximize close").split()
_FUNCS = {n: globals()["_" + n] for n in _NAMES}


def icon(name: str, color: str = TEXT) -> QIcon:
    return _icon(_FUNCS[name], color)
