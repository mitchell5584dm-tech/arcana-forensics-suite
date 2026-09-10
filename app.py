#!/usr/bin/env python3
"""
Arcana Forensics - License Delivery Backend
Handles Stripe webhook verification, license generation, and email delivery.

Environment variables required:
    STRIPE_SECRET_KEY        - Stripe API secret key
    STRIPE_WEBHOOK_SECRET   - Stripe webhook signing secret
    RESEND_API_KEY           - Resend email API key
    LICENSE_SIGNING_KEY      - Random secret for signing license tokens
    FROM_EMAIL               - Verified sender email
    SITE_URL                 - Public site URL

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

RATE_LIMIT_WINDOW = 3600
RATE_LIMIT_MAX_EMAILS = 5
_email_rate: dict = {}

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

        CREATE TABLE IF NOT EXISTS audit_log
