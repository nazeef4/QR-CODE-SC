"""FastAPI application entry-point.

Run:  uvicorn backend.app.main:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import APP_NAME, BASE_DIR
from .db import init_db
from .routers import auth, company, entities, onboarding, scans

FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(
    title=APP_NAME,
    version="0.1.0",
    description=(
        "Cryptographically secured QR-based supply chain traceability: "
        "configurable hierarchies, Ed25519-signed payloads and relationships, "
        "clone-detection telemetry, hash-chained audit."
    ),
    openapi_url="/api/v1/openapi.json",
    docs_url="/api/v1/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(onboarding.router)
app.include_router(auth.router)
app.include_router(company.router)
app.include_router(entities.router)
app.include_router(scans.router)


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": APP_NAME}


# --------------------------------------------------------------------------- #
# Static frontend
# --------------------------------------------------------------------------- #
@app.get("/", include_in_schema=False)
def index_page():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/admin", include_in_schema=False)
def admin_page():
    return FileResponse(FRONTEND_DIR / "admin.html")


if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
