#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHROME_DIST = ROOT / "dist"
FIREFOX_DIST = ROOT / "dist-firefox"

if not CHROME_DIST.is_dir():
    raise SystemExit("Chrome dist is missing. Run npm run build first.")

if FIREFOX_DIST.exists():
    shutil.rmtree(FIREFOX_DIST)
shutil.copytree(CHROME_DIST, FIREFOX_DIST)

manifest_path = FIREFOX_DIST / "manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

manifest.pop("minimum_chrome_version", None)
manifest["permissions"] = [
    permission
    for permission in manifest.get("permissions", [])
    if permission != "sidePanel"
]
manifest.pop("side_panel", None)

action = dict(manifest.get("action", {}))
action["default_popup"] = "sidepanel/index.html"
action["default_title"] = "Open VeilGraph"
manifest["action"] = action

hosts = list(manifest.get("host_permissions", []))
for required in (
    "http://127.0.0.1:8000/*",
    "http://127.0.0.1:8001/*",
    "http://127.0.0.1:8002/*",
):
    if required not in hosts:
        hosts.append(required)
manifest["host_permissions"] = hosts

# Firefox currently uses MV3 background scripts/event pages rather than
# extension service workers. The compiled serviceWorker.js is an ES module, so
# load the same security core as a module background script.
manifest["background"] = {
    "scripts": ["background/serviceWorker.js"],
    "type": "module",
}

manifest["browser_specific_settings"] = {
    "gecko": {
        "id": "veilgraph-sih26171@local.invalid",
        "strict_min_version": "128.0",
        "data_collection_permissions": {
            "required": ["websiteContent"],
        },
    }
}

manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
(FIREFOX_DIST / "FIREFOX_VALIDATION.txt").write_text(
    "VeilGraph SIH26171 Firefox package.\n"
    "Load manifest.json as a Temporary Add-on from about:debugging.\n"
    "The extension UI is exposed as the toolbar popup instead of Chrome sidePanel.\n",
    encoding="utf-8",
)
print(FIREFOX_DIST)
