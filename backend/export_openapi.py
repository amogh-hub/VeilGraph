from __future__ import annotations

import json
from pathlib import Path

from main import app

Path("openapi.json").write_text(json.dumps(app.openapi(), indent=2), encoding="utf-8")
print("Wrote backend/openapi.json")
