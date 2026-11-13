import argparse
import os
import signal
import sys

from PySide6.QtCore import QSettings
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import QApplication

from . import __version__, theme
from .hardening import harden
from .mainwindow import APP_NAME, MainWindow
from .splash import SplashScreen


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pwdeck", description="Local password manager with an encrypted single-file vault")
    ap.add_argument("vault", nargs="?", help="vault file to open (default: the last one used)")
    ap.add_argument("--no-splash", action="store_true", help="do not show the splash screen (or PWDECK_NO_SPLASH=1)")
    ap.add_argument("--version", action="version", version=f"pwdeck {__version__}")
    args = ap.parse_args(argv)
    rep = harden()                      # before Qt and before any secret exists in memory
    if rep["failed"]:
        print("pwdeck: warning: could not disable memory dumps (PR_SET_DUMPABLE)", file=sys.stderr)

    app = QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    app.setDesktopFileName("pwdeck")
    icon_path = os.path.join(os.path.dirname(__file__), "pwdeck.svg")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    app.setStyleSheet(theme.STYLESHEET)
    f = QFont(app.font())
    f.setPointSize(10)
    app.setFont(f)
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    w = MainWindow(QSettings("pwdeck", "pwdeck"), os.path.abspath(args.vault) if args.vault else None)

    def go() -> None:
        w.show()
        w.raise_()
        if not w.unlock_dialog():       # cancelled: stay on the lock screen (Unlock… button) rather than quitting
            pass

    if args.no_splash or os.environ.get("PWDECK_NO_SPLASH"):
        go()
    else:
        splash = SplashScreen(__version__)
        splash.start()
        app.processEvents()
        splash.finished.connect(go)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
