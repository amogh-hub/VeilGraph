from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

if DIST.exists():
    shutil.rmtree(DIST)
DIST.mkdir(parents=True)

subprocess.run(["tsc", "-p", str(ROOT / "tsconfig.json")], check=True)
shutil.copy2(ROOT / "manifest.json", DIST / "manifest.json")
sidepanel = DIST / "sidepanel"
sidepanel.mkdir(parents=True, exist_ok=True)
shutil.copy2(ROOT / "public" / "sidepanel.html", sidepanel / "index.html")
shutil.copy2(ROOT / "public" / "styles.css", sidepanel / "styles.css")
print(DIST)
