"""Pytest fixtures: isolated SQLite DB + HTTP client + onboarding helper."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# repo root on sys.path + isolated DB *before* app imports
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

_TMPDIR = tempfile.mkdtemp(prefix="scqr-test-")
os.environ["SCQR_DB_PATH"] = str(Path(_TMPDIR) / "test.db")
os.environ["SCQR_DATA_DIR"] = _TMPDIR
os.environ["SCQR_QR_DIR"] = str(Path(_TMPDIR) / "qr")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.app import service  # noqa: E402
from backend.app.db import Base, engine, init_db  # noqa: E402
from backend.app.main import app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _db():
    init_db()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    from backend.app.db import SessionLocal

    service.clear_key_cache()
    with TestClient(app) as c:
        yield c
    service.clear_key_cache()
    SessionLocal().close()


def onboard(client: TestClient, name: str = "TestCo", email: str = "admin@test.co",
            template: str = "pharma-classic") -> dict:
    r = client.post(
        "/api/v1/onboarding/company",
        json={
            "company_name": name,
            "admin": {"email": email, "password": "correct-horse-battery", "name": "Admin"},
            "template": template,
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def make_user(client: TestClient, token: str, cid: str, role: str, email: str) -> str:
    r = client.post(
        "/api/v1/auth/users",
        json={"email": email, "password": "some-passphrase-1", "name": role, "role": role},
        headers=auth(token),
    )
    assert r.status_code == 201, r.text
    r = client.post("/api/v1/auth/login", json={"email": email, "password": "some-passphrase-1"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]
