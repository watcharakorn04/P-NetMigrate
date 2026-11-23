"""Every test gets its own throw-away SQLite file — the real netmigrate.db is never touched.

The file is created lazily (only by tests that actually reach the database).
"""

from __future__ import annotations

import pytest

from app.db import Database
from app.deps import get_db
from app.main import app
from app.services import deploy_service


@pytest.fixture
def db(tmp_path) -> Database:
    return Database(tmp_path / "test.db")


@pytest.fixture(autouse=True)
def _isolated_db(request, monkeypatch):
    holder: dict[str, Database] = {}

    def lazy_db() -> Database:
        if "db" not in holder:
            holder["db"] = request.getfixturevalue("db")
        return holder["db"]

    app.dependency_overrides[get_db] = lazy_db
    monkeypatch.setattr(deploy_service, "SIM_DELAY", 0.0)
    yield
    app.dependency_overrides.pop(get_db, None)
