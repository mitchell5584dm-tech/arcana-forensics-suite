#!/usr/bin/env python3
"""
Arcana Forensics - License Delivery Backend
Handles Stripe webhook verification, license generation, and email delivery.

Environment variables required:
    STRIPE_SECRET_KEY        - Stripe API secret key
    STRIPE_WEBHOOK_SECRET   - Stripe webhook signing secret
    RESEND_API_KEY           - Resend email API key
    LICENSE_SIGNING_KEY      - Random secret for signing license tokens (generate with: python3 -c "import secrets; print(secrets.token_hex(32))")
    FROM_EMAIL               - Verified sender email (e.g., licenses@arcana-forensics.com)

Deploy:
    pip install flask stripe requests gunicorn
    gunicorn app:app --bind 0.0.0.0:\$PORT
"""

import os
import json
import time
import hmac
import hashlib
import secrets
import sqlite3
import html
import re
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

import requests
from flask import Flask, request, jsonify, send_from_directory, abort

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("arcana")

app = Flask(__name__)

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
LICENSE_SIGNING_KEY = os.getenv("LICENSE_SIGNING_KEY", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", "licenses@arcana-forensics.com")
SITE_URL = os.getenv("SITE_URL", "https://arcana-forensics.com")
DB_PATH = os.getenv("DB_PATH", "licenses.db")

# Rate limiting (in-memory, per IP)
RATE_LIMIT_WINDOW = 3600  # 1 hour
RATE_LIMIT_MAX_EMAILS = 5  # Max license emails per IP per hour
_email_rate: dict = {}

# ---------------------------------------------------------------------------
# DATABASE
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_code TEXT UNIQUE NOT NULL,
            license_signature TEXT NOT NULL,
            customer_email TEXT NOT NULL,
            stripe_transaction_id TEXT,
            purchase_date TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            machine_fingerprint TEXT,
            activated_date TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            license_code TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_licenses_code ON licenses(license_code);
        CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(customer_email);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    """)
    conn.commit()
    conn.close()

def log_event(event_type: str, license_code: str = "", details: str = "", ip: str = ""):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (event_type, license_code, details, ip_address, timestamp) VALUES (?, ?, ?, ?, ?)",
        (event_type, license_code, details, ip, datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# LICENSE GENERATION (SIGNED TOKENS)
# ---------------------------------------------------------------------------

def generate_license_code() -> str:
    """Generate a human-readable license code."""
    raw = secrets.token_bytes(16)
    hex_code = raw.hex().upper()
    # Format: ARCF-XXXX-XXXX-XXXX-XXXX
    return f"ARCF-{hex_code[0:4]}-{hex_code[4:8]}-{hex_code[8:12]}-{hex_code[12:16]}"

def sign_license(code: str, email: str, txn_id: str) -> str:
    """Create HMAC-SHA256 signature for the license."""
    if not LICENSE_SIGNING_KEY:
        log.warning("LICENSE_SIGNING_KEY not set - licenses will be unsigned")
        return ""
    payload = f"{code}:{email}:{txn_id}"
    sig = hmac.new(
        LICENSE_SIGNING_KEY.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return sig

def verify_license(code: str, email: str, txn_id: str, signature: str) -> bool:
    """Verify a license signature."""
    if not LICENSE_SIGNING_KEY or not signature:
        return False
    expected = sign_license(code, email, txn_id)
    return hmac.compare_digest(expected, signature)

# ---------------------------------------------------------------------------
# STRIPE WEBHOOK VERIFICATION
# ---------------------------------------------------------------------------

def verify_stripe_signature(payload: bytes, signature_header: str) -> bool:
    """Verify Stripe webhook signature."""
    if not STRIPE_WEBHOOK_SECRET:
        log.error("STRIPE_WEBHOOK_SECRET not configured")
        return False

    try:
        elements = signature_header.split(",")
        sig_dict = {}
        for elem in elements:
            k, v = elem.split("=", 1)
            sig_dict[k] = v

        timestamp = int(sig_dict.get("t", 0))
        signature = sig_dict.get("v1", "")

        # Reject if older than 5 minutes
        current
