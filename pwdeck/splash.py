"""Animated splash screen in the style of CNC Deck: a safe drawn in a few lines; its dial turns and clicks into place."""
from __future__ import annotations

import math

from PySide6.QtCore import QElapsedTimer, QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen, QRadialGradient
from PySide6.QtWidgets import QApplication, QWidget

from . import theme

W, H = 780, 440
CREDITS = "Stefano Ciurleo & Claude Code - 2026"
STOPS = ["#ff7a45", "#ffc53d", "#4ade80", "#38bdf8"]


def _lerp(a: QColor, b: QColor, t: float) -> QColor:
    return QColor(int(a.red() + (b.red() - a.red()) * t), int(a.green() + (b.green() - a.green()) * t),
                  int(a.blue() + (b.blue() - a.blue()) * t))


def depth_color(t: float) -> QColor:
    cols = [QColor(c) for c in STOPS]
    t = min(max(t, 0.0), 1.0) * (len(cols) - 1)
    i = min(int(t), len(cols) - 2)
    return _lerp(cols[i], cols[i + 1], t - i)


def _ease(x: float) -> float:
    x = min(max(x, 0.0), 1.0)
    return x * x * (3 - 2 * x)


class SplashScreen(QWidget):
    finished = Signal()

    def __init__(self, version: str, duration_ms: int = 3000, parent=None):
        super().__init__(parent)
        self.version, self.duration, self.t = version, duration_ms, 0.0
        self.setWindowFlags(Qt.SplashScreen | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(W, H)
        self._clock = QElapsedTimer()
        self._tick = QTimer(self, interval=16)
        self._tick.timeout.connect(self._advance)
        yaw, pitch = math.radians(-35), math.radians(55)
        cz, sz, cx, sx = math.cos(yaw), math.sin(yaw), math.cos(pitch), math.sin(pitch)
        rx = ((1, 0, 0), (0, cx, sx), (0, -sx, cx))
        rz = ((cz, -sz, 0), (sz, cz, 0), (0, 0, 1))
        self._rot = tuple(tuple(sum(rx[i][k] * rz[k][j] for k in range(3)) for j in range(3)) for i in range(3))   # rx @ rz

    def _proj(self, pts, origin) -> list[tuple[float, float]]:
        """Isometric-ish projection of (x, y, z) points to screen coordinates."""
        r = self._rot
        return [(origin[0] + r[0][0] * x + r[0][1] * y + r[0][2] * z, origin[1] - (r[1][0] * x + r[1][1] * y + r[1][2] * z))
                for x, y, z in pts]

    def start(self) -> None:
        scr = QApplication.primaryScreen()
        if scr is not None:
            g = scr.availableGeometry()
            self.move(g.center().x() - W // 2, g.center().y() - H // 2)
        self.show()
        self.raise_()
        self._clock.start()
        self._tick.start()

    def _advance(self) -> None:
        self.t = float(self._clock.elapsed())
        if self.t >= self.duration:
            self._tick.stop()
            self.close()
            self.finished.emit()
            return
        self.update()

    def set_time(self, ms: float) -> None:
        self.t = ms
        self.update()

    def paintEvent(self, _ev) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        k = self.t / max(self.duration, 1)
        p.setOpacity(max(0.0, min(_ease(self.t / 350.0), 1.0 - _ease((self.t - (self.duration - 300)) / 300.0))))
        self._card(p)
        self._grid(p)
        self._paint_art(p, k)
        self._text(p)
        self._progress(p, k)
        p.end()

    def _card(self, p: QPainter) -> None:
        path = QPainterPath()
        path.addRoundedRect(QRectF(8, 8, W - 16, H - 16), 22, 22)
        glow = QRadialGradient(QPointF(W * 0.68, H * 0.45), W * 0.62)
        glow.setColorAt(0, QColor(45, 212, 191, 38))
        glow.setColorAt(1, QColor(45, 212, 191, 0))
        g = QLinearGradient(0, 0, 0, H)
        g.setColorAt(0, QColor("#141b24"))
        g.setColorAt(1, QColor("#0a0e13"))
        p.fillPath(path, g)
        p.fillPath(path, QBrush(glow))
        p.setPen(QPen(QColor(theme.BORDER), 1.5))
        p.drawPath(path)
        p.setClipPath(path)

    def _grid(self, p: QPainter) -> None:
        origin = (W * 0.66, H * 0.58)
        p.setPen(QPen(QColor(255, 255, 255, 16), 1))
        span, step = 220, 22
        for v in range(-span, span + 1, step):
            a = self._proj([(v, -span, -45.0), (v, span, -45.0)], origin)
            b = self._proj([(-span, v, -45.0), (span, v, -45.0)], origin)
            p.drawLine(QPointF(*a[0]), QPointF(*a[1]))
            p.drawLine(QPointF(*b[0]), QPointF(*b[1]))
        fade = QLinearGradient(0, 0, W * 0.55, 0)
        fade.setColorAt(0, QColor("#0e1319"))
        fade.setColorAt(1, QColor(14, 19, 25, 0))
        p.fillRect(QRectF(0, 0, W * 0.55, H), fade)

    # ------------------------------------------------------------------ the safe (kept deliberately minimal)
    def _paint_art(self, p: QPainter, k: float) -> None:
        cx, cy = W * 0.70, H * 0.50
        box = QRectF(cx - 92, cy - 104, 184, 208)
        top, bottom = box.top(), box.bottom()

        def col(y: float, alpha: int = 255) -> QColor:          # cool at the top, warm at the bottom
            c = depth_color(1.0 - (y - top) / (bottom - top))
            c.setAlpha(alpha)
            return c

        # 1) the outline draws itself
        path = QPainterPath()
        path.addRoundedRect(box, 22, 22)
        n = 160
        pts = [path.pointAtPercent(i / n) for i in range(n + 1)]
        for i in range(1, int(n * _ease(k / 0.35)) + 1):
            p.setPen(QPen(col(pts[i].y()), 3.0, Qt.SolidLine, Qt.RoundCap))
            p.drawLine(pts[i - 1], pts[i])

        # 2) what makes it a safe and not a clock: the door, two hinges, a spoked handle next to the combination dial, feet
        fade = _ease((k - 0.25) / 0.12)
        if fade <= 0:
            return
        done = _ease((k - 0.82) / 0.10)                         # 4) click: everything lights up
        accent = QColor(theme.ACCENT)
        edge = accent if done > 0.5 else QColor(255, 255, 255, 150)
        p.setOpacity(p.opacity() * fade)
        door = box.adjusted(16, 16, -16, -16)
        p.setPen(QPen(QColor(255, 255, 255, 70), 1.8))
        p.setBrush(Qt.NoBrush)
        p.drawRoundedRect(door, 12, 12)
        p.setBrush(QColor(14, 19, 25))
        for hy in (door.top() + 34, door.bottom() - 34):        # hinges
            p.drawRoundedRect(QRectF(door.left() - 5, hy - 11, 10, 22), 3, 3)
        for fx in (box.left() + 22, box.right() - 44):          # feet
            p.drawRoundedRect(QRectF(fx, box.bottom() + 3, 22, 8), 3, 3)
        cy = box.center().y()
        # 3) the dial turns one full turn, a little back, and settles under the fixed index mark
        dial = QPointF(door.left() + 54, cy)
        r = 36.0
        angle = 360 * _ease((k - 0.30) / 0.38) - 40 * _ease((k - 0.68) / 0.10)
        if done > 0:
            glow = QRadialGradient(dial, r * 1.9)
            glow.setColorAt(0, QColor(45, 212, 191, int(100 * done)))
            glow.setColorAt(1, QColor(45, 212, 191, 0))
            p.setPen(Qt.NoPen)
            p.setBrush(QBrush(glow))
            p.drawEllipse(dial, r * 1.9, r * 1.9)
        p.setPen(QPen(edge, 2.4))
        p.setBrush(Qt.NoBrush)
        p.drawEllipse(dial, r, r)
        p.save()
        p.translate(dial)
        p.rotate(angle)
        p.setPen(QPen(QColor(255, 255, 255, 170), 1.8, Qt.SolidLine, Qt.RoundCap))
        for i in range(20):
            p.save()
            p.rotate(i * 18)
            p.drawLine(QPointF(0, -r + 5), QPointF(0, -r + (14 if i % 5 == 0 else 9)))
            p.restore()
        p.setPen(QPen(edge, 2.0))
        p.setBrush(QColor(22, 31, 41))
        p.drawEllipse(QPointF(0, 0), 15, 15)                     # knob
        p.setPen(Qt.NoPen)
        p.setBrush(accent)
        p.drawEllipse(QPointF(0, -8), 2.6, 2.6)                  # a dot on the knob, not a hand
        p.restore()
        p.setPen(Qt.NoPen)
        p.setBrush(accent)
        p.drawPolygon([QPointF(dial.x() - 6, dial.y() - r - 12), QPointF(dial.x() + 6, dial.y() - r - 12), QPointF(dial.x(), dial.y() - r - 2)])
        # handle: three spokes, turns at the click
        hc = QPointF(door.right() - 31, cy)
        p.save()
        p.translate(hc)
        p.rotate(60 * done)
        p.setPen(QPen(accent if done > 0.5 else QColor("#e5e7eb"), 4.5, Qt.SolidLine, Qt.RoundCap))
        for th in (0, 120, 240):
            p.save()
            p.rotate(th)
            p.drawLine(QPointF(0, 0), QPointF(0, -26))
            p.restore()
        p.setPen(QPen(QColor("#04211d"), 2))
        p.setBrush(accent if done > 0.5 else QColor("#e5e7eb"))
        p.drawEllipse(QPointF(0, 0), 8, 8)
        p.restore()
        p.setOpacity(1.0)

    def _text(self, p: QPainter) -> None:
        x = 58
        f = QFont("sans", 46, QFont.Black)
        f.setLetterSpacing(QFont.AbsoluteSpacing, 1.5)
        p.setFont(f)
        p.setPen(QColor("#f1f5f9"))
        p.drawText(QPointF(x, H * 0.47), "PW")
        w = p.fontMetrics().horizontalAdvance("PW ")
        p.setPen(QColor(theme.ACCENT))
        p.drawText(QPointF(x + w, H * 0.47), "Deck")
        p.setPen(Qt.NoPen)
        g = QLinearGradient(x, 0, x + 230, 0)
        g.setColorAt(0, QColor(theme.ACCENT))
        g.setColorAt(1, QColor(45, 212, 191, 0))
        p.setBrush(QBrush(g))
        p.drawRoundedRect(QRectF(x, H * 0.47 + 16, 230, 3), 1.5, 1.5)
        p.setFont(QFont("sans", 11))
        p.setPen(QColor(theme.MUTED))
        p.drawText(QPointF(x + 2, H * 0.47 + 50), CREDITS)
        p.setFont(QFont("sans", 10, QFont.DemiBold))
        p.setPen(QColor(theme.ACCENT))
        p.drawText(QPointF(x + 2, H * 0.47 + 76), f"Version {self.version}")
        p.setFont(QFont("sans", 8))
        p.setPen(QColor(255, 255, 255, 70))
        p.drawText(QPointF(x + 2, H - 38), "Local password manager  ·  encrypted SQLite vault in a single file")

    def _progress(self, p: QPainter, k: float) -> None:
        x0, x1, y = 58.0, W - 58.0, H - 24.0
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(255, 255, 255, 18))
        p.drawRoundedRect(QRectF(x0, y, x1 - x0, 3), 1.5, 1.5)
        g = QLinearGradient(x0, 0, x1, 0)
        g.setColorAt(0, QColor(theme.ACCENT))
        g.setColorAt(1, QColor("#38bdf8"))
        p.setBrush(QBrush(g))
        p.drawRoundedRect(QRectF(x0, y, (x1 - x0) * min(k, 1.0), 3), 1.5, 1.5)
