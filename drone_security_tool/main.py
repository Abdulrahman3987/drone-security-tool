"""
Entry point for the Drone Security Assessment Tool.
"""
from __future__ import annotations

import sys
import site
from pathlib import Path

user_site = site.getusersitepackages()
if user_site and user_site not in sys.path:
    sys.path.insert(0, user_site)

try:
    from PyQt5.QtWidgets import QApplication
except ModuleNotFoundError as exc:
    if exc.name != "PyQt5":
        raise
    raise SystemExit(
        "PyQt5 is not installed for this Python interpreter.\n"
        "Run this from C:\\Users\\mddm7\\Desktop\\GPtool:\n"
        "  python -m pip install -r drone_security_tool\\requirements.txt\n"
        "Then start the app with:\n"
        "  python main.py"
    ) from exc

from gui.main_window import MainWindow


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
