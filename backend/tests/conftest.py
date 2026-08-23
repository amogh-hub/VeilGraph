from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.database import db
from main import app


@pytest.fixture(autouse=True)
def clean_state():
    with db.connection() as conn:
        conn.execute("DELETE FROM destruction_receipts")
        conn.execute("DELETE FROM mentions")
        conn.execute("DELETE FROM canonical_entities")
        conn.execute("DELETE FROM outputs")
        conn.execute("DELETE FROM files")
        conn.execute("DELETE FROM jobs")
    shutil.rmtree(settings.workspace_root, ignore_errors=True)
    settings.workspace_root.mkdir(parents=True, exist_ok=True)
    yield
    shutil.rmtree(settings.workspace_root, ignore_errors=True)


@pytest.fixture
def client():
    # Tests do not need application lifespan startup; avoiding the context
    # manager also prevents native OCR/OpenCV teardown deadlocks on some CI
    # runners after mixed vision and ASGI tests.
    return TestClient(app)
