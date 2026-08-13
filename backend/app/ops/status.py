from __future__ import annotations

import os
import platform
import resource
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.database import db
from app.ops.metrics import runtime_metrics


def _rss_mib() -> float:
    value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    # macOS reports bytes; Linux reports KiB.
    return round(value / (1024 * 1024) if platform.system() == "Darwin" else value / 1024, 2)


def database_quick_check() -> dict[str, Any]:
    try:
        row = db.fetchone("PRAGMA quick_check")
        if not row:
            return {"ok": False, "detail": "no result"}
        value = str(next(iter(row.values())))
        return {"ok": value.lower() == "ok", "detail": value}
    except Exception as exc:
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}


def runtime_status(admission: dict[str, Any]) -> dict[str, Any]:
    workspace = Path(settings.workspace_root)
    return {
        "product": settings.app_name,
        "version": settings.version,
        "deployment": {
            "offline_mode": settings.offline_mode,
            "bind": f"{settings.bind_host}:{settings.bind_port}",
            "external_model_calls": False,
            "online_require_https": settings.online_require_https,
            "trust_proxy_headers": settings.trust_proxy_headers,
            "trusted_proxy_network_count": len(settings.trusted_proxy_networks),
        },
        "process": {
            "pid": os.getpid(),
            "python": platform.python_version(),
            "platform": platform.system(),
            "max_rss_mib": _rss_mib(),
        },
        "database": database_quick_check(),
        "workspace": {
            "root_exists": workspace.exists(),
            "root_mode": oct(workspace.stat().st_mode & 0o777) if workspace.exists() else None,
        },
        "admission": admission,
        "metrics": runtime_metrics.snapshot(),
    }
