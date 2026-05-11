
from __future__ import annotations

import site
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
APP_DIR = ROOT / "drone_security_tool"

user_site = site.getusersitepackages()
for path in (str(APP_DIR), user_site):
    if path and path not in sys.path:
        sys.path.insert(0, path)

from drone_security_tool.main import main


if __name__ == "__main__":
    main()
