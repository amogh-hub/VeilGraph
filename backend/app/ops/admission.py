from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager


_HEAVY_SUFFIXES = ("/analyse", "/transform", "/verify")


class AdmissionRejected(RuntimeError):
    pass


def is_heavy_request(method: str, path: str) -> bool:
    if method.upper() != "POST":
        return False
    if path.endswith(_HEAVY_SUFFIXES):
        return True
    # Upload parsing can be CPU/RAM intensive for large documents.
    return path.endswith("/files") and "/jobs/" in path


class AdmissionController:
    def __init__(self, limit: int, queue_timeout_seconds: float):
        self.limit = max(1, int(limit))
        self.queue_timeout_seconds = max(0.05, float(queue_timeout_seconds))
        self._semaphore = asyncio.Semaphore(self.limit)
        self._active = 0
        self._max_active = 0
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def slot(self):
        try:
            await asyncio.wait_for(self._semaphore.acquire(), timeout=self.queue_timeout_seconds)
        except TimeoutError as exc:
            raise AdmissionRejected("VeilGraph heavy-operation concurrency limit reached") from exc
        async with self._lock:
            self._active += 1
            self._max_active = max(self._max_active, self._active)
        try:
            yield
        finally:
            async with self._lock:
                self._active = max(0, self._active - 1)
            self._semaphore.release()

    def snapshot(self) -> dict[str, int | float]:
        return {
            "limit": self.limit,
            "active": self._active,
            "max_active": self._max_active,
            "queue_timeout_seconds": self.queue_timeout_seconds,
        }
