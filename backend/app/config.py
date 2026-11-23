"""Central configuration for the SCQR traceability platform.

All secrets come from environment variables in production. The defaults here
exist so the reference implementation runs out of the box for evaluation.
"""
from __future__ import annotations

import os
from pathlib import Path

# Repository root (…/QR-CODE-SC)
BASE_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = Path(os.getenv("SCQR_DATA_DIR", BASE_DIR / "data"))
DB_PATH = Path(os.getenv("SCQR_DB_PATH", DATA_DIR / "trace.db"))
DATABASE_URL = f"sqlite:///{DB_PATH}"

# Master key used to wrap organisation private keys at rest (AES-256-GCM).
# Production deployments must supply this from a KMS/HSM-backed secret store.
MASTER_KEY = os.getenv("SCQR_MASTER_KEY", "scqr-dev-master-key-do-not-use-in-prod")

# HMAC secret for session JWTs.
JWT_SECRET = os.getenv("SCQR_JWT_SECRET", "scqr-dev-jwt-secret-do-not-use-in-prod")
JWT_TTL_SECONDS = int(os.getenv("SCQR_JWT_TTL_SECONDS", str(12 * 3600)))

# Where rendered QR PNGs are cached (demo/print pipeline).
QR_DIR = Path(os.getenv("SCQR_QR_DIR", DATA_DIR / "qr"))

# Basic per-IP budget for the public scan endpoint (requests per window).
SCAN_RATE_LIMIT = int(os.getenv("SCQR_SCAN_RATE_LIMIT", "120"))
SCAN_RATE_WINDOW_SECONDS = int(os.getenv("SCQR_SCAN_RATE_WINDOW", "60"))

# Clone-detection heuristics (documented in docs/04-anti-counterfeiting.md)
MAX_PLAUSIBLE_GROUND_SPEED_KMH = float(os.getenv("SCQR_MAX_SPEED_KMH", "900"))
VELOCITY_WINDOW_SECONDS = int(os.getenv("SCQR_VELOCITY_WINDOW", "3600"))
VELOCITY_MAX_SCANS = int(os.getenv("SCQR_VELOCITY_MAX", "5"))

APP_NAME = "SCQR — Cryptographically Secured QR Traceability"


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    QR_DIR.mkdir(parents=True, exist_ok=True)
