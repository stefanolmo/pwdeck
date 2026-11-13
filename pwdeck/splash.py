"""Animated splash screen in the style of CNC Deck: a vault (safe) drawn in line art; its combination dial spins, the bolts retract
and the door swings open on a teal glow."""
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

    # ------------------------------------------------------------------ the safe
    def _paint_art(self, p: QPainter, k: float) -> None:
        cx, cy = W * 0.70, H * 0.52
        fw, fh = 196, 222
        front = QRectF(cx - fw / 2 - 12, cy - fh / 2 + 6, fw, fh)
        dx, dy = 28.0, -24.0                                   # oblique depth (the safe's top and right sides)
        top, bottom = front.top(), front.bottom()

        def col(y: float, alpha: int = 255) -> QColor:          # cool at the top, warm at the bottom (like the old toolpaths)
            c = depth_color(1.0 - (y - top) / (bottom - top))
            c.setAlpha(alpha)
            return c

        # soft floor shadow and glow
        sh = QRadialGradient(QPointF(front.center().x() + 10, bottom + 16), 150)
        sh.setColorAt(0, QColor(0, 0, 0, 120))
        sh.setColorAt(1, QColor(0, 0, 0, 0))
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(sh))
        p.drawEllipse(QPointF(front.center().x() + 10, bottom + 16), 150, 26)

        k_outline = _ease(k / 0.32)
        k_depth = _ease((k - 0.10) / 0.28)
        k_door = _ease((k - 0.24) / 0.10)
        # depth faces: translucent fill + thin edges drawn in progressively
        if k_depth > 0:
            p.setOpacity(p.opacity() * 1.0)
            tl, tr, br = front.topLeft(), front.topRight(), front.bottomRight()
            off = QPointF(dx, dy)
            for poly in ([tl, tr, tr + off, tl + off], [tr, br, br + off, tr + off]):
                p.setPen(Qt.NoPen)
                p.setBrush(QColor(255, 255, 255, int(11 * k_depth)))
                p.drawPolygon(poly)
            edges = [(tl, tl + off), (tr, tr + off), (br, br + off), (tl + off, tr + off), (tr + off, br + off)]
            for a_, b_ in edges:
                e = a_ + (b_ - a_) * k_depth
                p.setPen(QPen(col(a_.y(), 120), 1.6, Qt.SolidLine, Qt.RoundCap))
                p.drawLine(a_, e)
            # feet
            for fx in (front.left() + 20, front.right() - 44):
                p.setPen(QPen(col(bottom, int(150 * k_depth)), 1.6))
                p.setBrush(QColor(14, 19, 25, int(200 * k_depth)))
                p.drawRoundedRect(QRectF(fx, bottom + 2, 24, 9 * k_depth), 3, 3)

        # door geometry
        D = front.adjusted(15, 15, -15, -15)
        f_open = _ease((k - 0.80) / 0.17)
        ang = math.radians(74) * f_open
        hx, hy = D.left(), D.center().y()
        fx_ = hx + D.width() * math.cos(ang)
        fac = 1.0 + 0.10 * math.sin(ang)
        hh = D.height() / 2

        # interior (visible through the opening)
        if f_open > 0:
            glow = QRadialGradient(D.center() + QPointF(14, 0), D.width() * 0.75)
            glow.setColorAt(0, QColor(45, 212, 191, int(190 * f_open)))
            glow.setColorAt(0.55, QColor(20, 90, 100, int(110 * f_open)))
            glow.setColorAt(1, QColor(10, 20, 28, int(230 * f_open)))
            p.setPen(Qt.NoPen)
            p.setBrush(QBrush(glow))
            p.drawRoundedRect(D, 10, 10)
            p.setOpacity(p.opacity() * f_open)
            # a key and two documents resting inside
            kc = D.center() + QPointF(26, -8)
            p.setPen(QPen(QColor("#e5e7eb"), 3.2, Qt.SolidLine, Qt.RoundCap))
            p.setBrush(Qt.NoBrush)
            p.drawEllipse(kc + QPointF(-22, 0), 11, 11)
            p.drawLine(kc + QPointF(-11, 0), kc + QPointF(30, 0))
            p.drawLine(kc + QPointF(18, 0), kc + QPointF(18, 11))
            p.drawLine(kc + QPointF(28, 0), kc + QPointF(28, 8))
            p.setPen(QPen(QColor(255, 255, 255, 90), 1.4))
            p.setBrush(QColor(255, 255, 255, 18))
            p.drawRoundedRect(QRectF(D.left() + 44, D.bottom() - 52, 70, 12), 3, 3)
            p.drawRoundedRect(QRectF(D.left() + 52, D.bottom() - 38, 70, 12), 3, 3)
            p.setOpacity(p.opacity() / f_open)

        # front frame outline, drawn in progressively
        path = QPainterPath()
        path.addRoundedRect(front, 18, 18)
        n = 180
        pts = [path.pointAtPercent(i / n) for i in range(n + 1)]
        upto = int(n * k_outline)
        for i in range(1, upto + 1):
            p.setPen(QPen(col(pts[i].y()), 2.6, Qt.SolidLine, Qt.RoundCap))
            p.drawLine(pts[i - 1], pts[i])
        if k_door <= 0:
            return

        # bolts (they live in the gap between door and frame) retract when the combination is right
        un = _ease((k - 0.70) / 0.08)
        retract = _ease((k - 0.72) / 0.08)
        p.setOpacity(p.opacity() * k_door)
        if f_open < 0.35:
            for by in (-66, -6, 54):
                bx = D.right() - 12 * retract + 2
                p.setPen(QPen(QColor(255, 255, 255, 110), 1.4))
                p.setBrush(QColor(60, 74, 94, 230))
                p.drawRoundedRect(QRectF(bx, hy + by - 9, 17, 18), 3, 3)

        # the door
        grad = QLinearGradient(hx, D.top(), hx, D.bottom())
        grad.setColorAt(0, QColor("#1a232e"))
        grad.setColorAt(1, QColor("#0f161d"))
        p.setBrush(QBrush(grad))
        edge = QLinearGradient(0, D.top(), 0, D.bottom())
        edge.setColorAt(0, depth_color(1.0))
        edge.setColorAt(1, depth_color(0.1))
        p.setPen(QPen(QBrush(edge), 2.0, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        if f_open < 0.001:
            p.drawRoundedRect(D, 10, 10)
        else:
            p.drawPolygon([QPointF(hx, D.top()), QPointF(fx_, hy - hh * fac), QPointF(fx_, hy + hh * fac), QPointF(hx, D.bottom())])
        if fx_ - hx < 8:
            p.setOpacity(1.0)
            return

        # door furniture, squeezed horizontally as the door swings
        p.save()
        p.translate(hx, hy)
        p.scale(math.cos(ang), 1.0)
        dw = D.width()
        dial_c = QPointF(dw * 0.40, -6)
        ring_r = 47
        p.setPen(QPen(QColor(255, 255, 255, 40), 1.4))
        p.setBrush(QColor(8, 12, 16, 230))
        p.drawEllipse(dial_c, ring_r + 7, ring_r + 7)
        # dial angle: spin, back, forth (entering the combination)
        a_dial = 540 * _ease((k - 0.30) / 0.20) - 230 * _ease((k - 0.50) / 0.10) + 150 * _ease((k - 0.60) / 0.08)
        p.save()
        p.translate(dial_c)
        p.rotate(a_dial)
        ticks = 50
        for i in range(ticks):
            th = i * 360 / ticks
            screen = (th + a_dial + 90) % 360                  # 0 = straight up after the +90 shift below
            near = abs(((screen - 0 + 180) % 360) - 180) < 360 / ticks / 2
            long = i % 5 == 0
            ln = 11 if long else 6
            p.setPen(QPen(QColor(45, 212, 191) if near and un < 1 else QColor(255, 255, 255, 190 if long else 110), 2.0 if long else 1.2, Qt.SolidLine, Qt.RoundCap))
            p.save()
            p.rotate(th)
            p.drawLine(QPointF(0, -ring_r + 1), QPointF(0, -ring_r + 1 + ln))
            p.restore()
        p.setPen(QPen(QColor(255, 255, 255, 60), 1.4))
        p.setBrush(QColor(22, 31, 41))
        p.drawEllipse(QPointF(0, 0), 25, 25)
        p.setPen(QPen(QColor(theme.ACCENT), 3, Qt.SolidLine, Qt.RoundCap))
        p.drawLine(QPointF(0, -4), QPointF(0, -19))              # the knob's own marker
        p.restore()
        # fixed pointer above the dial
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(theme.ACCENT))
        p.drawPolygon([QPointF(dial_c.x() - 6, dial_c.y() - ring_r - 15), QPointF(dial_c.x() + 6, dial_c.y() - ring_r - 15), QPointF(dial_c.x(), dial_c.y() - ring_r - 4)])
        # handle: three spokes
        hc = QPointF(dw * 0.83, -6)
        p.save()
        p.translate(hc)
        p.rotate(90 * _ease((k - 0.70) / 0.10))
        p.setPen(QPen(QColor("#e5e7eb"), 4, Qt.SolidLine, Qt.RoundCap))
        for th in (0, 120, 240):
            p.save()
            p.rotate(th)
            p.drawLine(QPointF(0, 0), QPointF(0, -27))
            p.restore()
        p.setPen(QPen(QColor("#04211d"), 2))
        p.setBrush(QColor(theme.ACCENT))
        p.drawEllipse(QPointF(0, 0), 8, 8)
        p.restore()
        # status LED: orange while locked, teal once unlocked
        led = QColor(255, 122, 69)
        t = QColor(theme.ACCENT)
        led = QColor(int(led.red() + (t.red() - led.red()) * un), int(led.green() + (t.green() - led.green()) * un),
                     int(led.blue() + (t.blue() - led.blue()) * un))
        lc = QPointF(dw * 0.83, -hh + 16)
        halo = QRadialGradient(lc, 14)
        halo.setColorAt(0, QColor(led.red(), led.green(), led.blue(), 170))
        halo.setColorAt(1, QColor(led.red(), led.green(), led.blue(), 0))
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(halo))
        p.drawEllipse(lc, 14, 14)
        p.setBrush(led)
        p.drawEllipse(lc, 4.5, 4.5)
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
