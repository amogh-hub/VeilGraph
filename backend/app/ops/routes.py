from __future__ import annotations

from fastapi import APIRouter

from app.ops.status import runtime_status

router = APIRouter(prefix="/api/v1/ops", tags=["operations"])
_admission_snapshot = lambda: {"configured": False}


def bind_admission_snapshot(fn):
    global _admission_snapshot
    _admission_snapshot = fn


@router.get("/status")
def operations_status():
    return runtime_status(_admission_snapshot())
