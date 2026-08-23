from __future__ import annotations

import math
import re
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass
from typing import Any

from app.core.config import settings

_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,36}\b")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{24,64}\b")


def normalize_metric_path(path: str) -> str:
    """Remove high-cardinality identifiers before a request path becomes a metric label."""
    value = _UUID_RE.sub("{id}", path)
    value = _HEX_RE.sub("{id}", value)
    return value[:180]


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(quantile * len(ordered)) - 1))
    return float(ordered[index])


@dataclass(frozen=True)
class RequestToken:
    started: float
    metric_path: str


class RuntimeMetrics:
    """PII-free in-memory operational metrics.

    Only normalized route labels, status classes and durations are retained. Request
    bodies, query strings, filenames, entity values and job identifiers are never
    stored by this collector.
    """

    def __init__(self, *, window: int = 2048):
        self._lock = threading.RLock()
        self._durations_ms: deque[float] = deque(maxlen=max(64, int(window)))
        self._requests = 0
        self._errors = 0
        self._active = 0
        self._max_active = 0
        self._routes: Counter[str] = Counter()
        self._statuses: Counter[str] = Counter()
        self._admission_rejections = 0

    def begin(self, path: str) -> RequestToken:
        metric_path = normalize_metric_path(path)
        with self._lock:
            self._active += 1
            self._max_active = max(self._max_active, self._active)
        return RequestToken(time.perf_counter(), metric_path)

    def end(self, token: RequestToken, status_code: int) -> float:
        elapsed_ms = (time.perf_counter() - token.started) * 1000.0
        with self._lock:
            self._active = max(0, self._active - 1)
            self._requests += 1
            if status_code >= 500:
                self._errors += 1
            self._routes[token.metric_path] += 1
            self._statuses[f"{status_code // 100}xx"] += 1
            self._durations_ms.append(elapsed_ms)
        return elapsed_ms

    def admission_rejected(self) -> None:
        with self._lock:
            self._admission_rejections += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            values = list(self._durations_ms)
            return {
                "requests_total": self._requests,
                "errors_5xx_total": self._errors,
                "active_requests": self._active,
                "max_active_requests": self._max_active,
                "admission_rejections_total": self._admission_rejections,
                "latency_ms": {
                    "p50": round(percentile(values, 0.50), 3),
                    "p95": round(percentile(values, 0.95), 3),
                    "max": round(max(values), 3) if values else 0.0,
                    "samples": len(values),
                    "window_capacity": self._durations_ms.maxlen,
                },
                "status_classes": dict(sorted(self._statuses.items())),
                "routes": dict(self._routes.most_common(20)),
                "privacy": {
                    "stores_request_bodies": False,
                    "stores_query_strings": False,
                    "stores_job_ids": False,
                },
            }


runtime_metrics = RuntimeMetrics(window=settings.ops_metrics_window)
