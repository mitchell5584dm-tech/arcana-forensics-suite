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
    gunicorn app:app --bind 0.0.0.0:$PORT
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
        current_time = int(time.time())
        if current_time - timestamp > 300:
            log.warning(f"Webhook timestamp too old: {current_time - timestamp}s")
            return False

        signed_payload = f"{timestamp}.{payload.decode('utf-8')}"
        expected_sig = hmac.new(
            STRIPE_WEBHOOK_SECRET.encode("utf-8"),
            signed_payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected_sig, signature)
    except Exception as e:
        log.error(f"Stripe signature verification failed: {e}")
        return False

# ---------------------------------------------------------------------------
# EMAIL DELIVERY
# ---------------------------------------------------------------------------

def is_valid_email(email: str) -> bool:
    """Basic email validation."""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

def check_rate_limit(ip: str) -> bool:
    """Check if IP has exceeded email rate limit."""
    current = time.time()
    if ip not in _email_rate:
        _email_rate[ip] = []
    # Clean old entries
    _email_rate[ip] = [t for t in _email_rate[ip] if current - t < RATE_LIMIT_WINDOW]
    if len(_email_rate[ip]) >= RATE_LIMIT_MAX_EMAILS:
        return False
    _email_rate[ip].append(current)
    return True

def send_license_email(to_email: str, license_code: str, signature: str) -> Tuple[bool, str]:
    """Send license code via Resend API with proper escaping."""
    if not RESEND_API_KEY:
        log.error("RESEND_API_KEY not configured")
        return False, "Email service not configured"

    if not is_valid_email(to_email):
        return False, "Invalid email address"

    safe_code = html.escape(license_code)
    safe_sig = html.escape(signature[:16])

    email_html = f"""
    <!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #1a1a1a;">Arcana Forensics - License Active</h1>
    <p>Thank you for your purchase.</p>
    <div style="background: #f4f4f4; padding: 16px; border-radius: 8px; margin: 20px 0;">
        <p style="margin: 0 0 8px 0;"><strong>License Code:</strong></p>
        <p style="font-family: monospace; font-size: 1.1rem; background: #fff; padding: 8px; border-radius: 4px;">{safe_code}</p>
        <p style="margin: 8px 0 0 0; font-size: 0.85rem; color: #666;">Verification prefix: {safe_sig}</p>
    </div>
    <p><strong>Activation:</strong></p>
    <code style="display: block; background: #f4f4f4; padding: 12px; border-radius: 4px; font-size: 0.9rem;">python3 credential_auditor.py --license {safe_code} --input creds.txt</code>
    <p style="margin-top: 20px;">Save this email. Your license is stored offline and verified locally.</p>
    <hr style="border: none; border-top: 1px solid #ddd; margin: 24px 0;">
    <p style="font-size: 0.8rem; color: #666;">Arcana Forensics<br>
    <a href="{html.escape(SITE_URL)}">{html.escape(SITE_URL)}</a><br>
    This license was generated and signed offline. No third-party telemetry involved.</p>
</body>
</html>
    """

    try:
        r = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "from": f"Arcana Forensics <{FROM_EMAIL}>",
                "to": [to_email],
                "subject": f"Your Arcana Forensics License: {safe_code}",
                "html": email_html,
            },
            timeout=15,
        )
        if r.status_code == 200:
            log.info(f"License email sent to {to_email}")
            return True, "Sent"
        else:
            log.error(f"Resend API error: {r.status_code} - {r.text[:200]}")
            return False, "Email delivery failed"
    except requests.Timeout:
        log.error("Resend API timeout")
        return False, "Email service timeout"
    except requests.ConnectionError:
        log.error("Resend API connection error")
        return False, "Email service unreachable"
    except Exception as e:
        log.error(f"Unexpected email error: {e}")
        return False, "Email delivery error"

# ---------------------------------------------------------------------------
# STRIPE WEBHOOK HANDLER
# ---------------------------------------------------------------------------

@app.route("/webhook/stripe", methods=["POST"])
def stripe_webhook():
    """Handle Stripe webhook events with signature verification."""
    payload = request.get_data()
    signature_header = request.headers.get("Stripe-Signature", "")

    if not signature_header:
        log.warning("Webhook received without Stripe-Signature header")
        abort(400)

    if not verify_stripe_signature(payload, signature_header):
        log.warning("Stripe webhook signature verification failed")
        abort(401)

    try:
        event = json.loads(payload)
    except json.JSONDecodeError:
        log.error("Invalid JSON in webhook payload")
        abort(400)

    event_type = event.get("type", "")

    if event_type == "checkout.session.completed":
        session = event.get("data", {}).get("object", {})
        customer_email = session.get("customer_details", {}).get("email", "")
        stripe_txn_id = session.get("payment_intent", "") or session.get("id", "")

        if not customer_email or not is_valid_email(customer_email):
            log.warning(f"Webhook: invalid customer email: {customer_email}")
            abort(400)

        # Check if license already exists for this transaction
        conn = get_db()
        existing = conn.execute(
            "SELECT license_code FROM licenses WHERE stripe_transaction_id = ?",
            (stripe_txn_id,)
        ).fetchone()

        if existing:
            log.info(f"Duplicate webhook for {stripe_txn_id}, resending license")
            license_code = existing["license_code"]
            conn.close()
        else:
            # Generate new license
            license_code = generate_license_code()
            signature = sign_license(license_code, customer_email, stripe_txn_id)
            now = datetime.now(timezone.utc).isoformat()

            conn.execute(
                """INSERT INTO licenses
                (license_code, license_signature, customer_email, stripe_transaction_id,
                 purchase_date, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'active', ?)""",
                (license_code, signature, customer_email, stripe_txn_id, now, now)
            )
            conn.commit()
            conn.close()

            log.info(f"License created: {license_code} for {customer_email}")

        # Send email
        sent, msg = send_license_email(customer_email, license_code, "")
        log_event("LICENSE_EMAIL_SENT" if sent else "LICENSE_EMAIL_FAILED",
                  license_code, msg, request.remote_addr)

        return jsonify({"status": "processed", "license": license_code[:8] + "..."}), 200

    elif event_type == "charge.refunded":
        # Handle refunds - revoke license
        charge = event.get("data", {}).get("object", {})
        stripe_txn_id = charge.get("payment_intent", "")

        conn = get_db()
        conn.execute(
            "UPDATE licenses SET status = 'revoked' WHERE stripe_transaction_id = ?",
            (stripe_txn_id,)
        )
        conn.commit()
        conn.close()

        log.info(f"License revoked for refunded transaction: {stripe_txn_id}")
        log_event("LICENSE_REVOKED", "", f"Refund: {stripe_txn_id}", request.remote_addr)
        return jsonify({"status": "revoked"}), 200

    else:
        log.info(f"Unhandled Stripe event type: {event_type}")
        return jsonify({"status": "ignored"}), 200

# ---------------------------------------------------------------------------
# LICENSE VERIFICATION ENDPOINT (FOR DESKTOP TOOL)
# ---------------------------------------------------------------------------

@app.route("/api/verify-license", methods=["POST"])
def verify_license_endpoint():
    """Verify a license code. Used by the desktop credential auditor."""
    data = request.get_json()
    if not data or "license_code" not in data:
        abort(400)

    code = data["license_code"].strip().upper()
    conn = get_db()
    row = conn.execute(
        "SELECT license_code, customer_email, stripe_transaction_id, license_signature, status FROM licenses WHERE license_code = ?",
        (code,)
    ).fetchone()
    conn.close()

    if not row:
        log_event("LICENSE_VERIFY_FAILED", code, "Not found", request.remote_addr)
        return jsonify({"valid": False, "reason": "License not found"}), 404

    if row["status"] != "active":
        log_event("LICENSE_VERIFY_FAILED", code, f"Status: {row['status']}", request.remote_addr)
        return jsonify({"valid": False, "reason": f"License {row['status']}"}), 403

    verified = verify_license(
        row["license_code"],
        row["customer_email"],
        row["stripe_transaction_id"],
        row["license_signature"]
    )

    log_event("LICENSE_VERIFIED", code, "OK", request.remote_addr)
    return jsonify({
        "valid": True,
        "email": row["customer_email"],
        "verified": verified,
        "status": row["status"]
    }), 200

# ---------------------------------------------------------------------------
# RESEND LICENSE (RATE LIMITED)
# ---------------------------------------------------------------------------

@app.route("/api/resend-license", methods=["POST"])
def resend_license():
    """Resend license email to the original purchaser. Rate limited."""
    ip = request.remote_addr or "unknown"

    if not check_rate_limit(ip):
        log.warning(f"Rate limit exceeded for IP: {ip}")
        abort(429)

    data = request.get_json()
    if not data or "email" not in data:
        abort(400)

    email = data["email"].strip().lower()
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email"}), 400

    conn = get_db()
    rows = conn.execute(
        "SELECT license_code, status FROM licenses WHERE customer_email = ? ORDER BY created_at DESC",
        (email,)
    ).fetchall()
    conn.close()

    if not rows:
        log_event("RESEND_FAILED", "", f"Email not found: {email}", ip)
        return jsonify({"error": "No licenses found for this email"}), 404

    active = [r for r in rows if r["status"] == "active"]
    if not active:
        return jsonify({"error": "All licenses for this email are revoked or expired"}), 403

    license_code = active[0]["license_code"]
    sent, msg = send_license_email(email, license_code, "")
    log_event("LICENSE_RESENT", license_code, msg, ip)

    if sent:
        return jsonify({"status": "sent"}), 200
    else:
        return jsonify({"error": "Email delivery failed"}), 500

# ---------------------------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------------------------

@app.route("/ping")
def ping():
    return jsonify({
        "status": "alive",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "db": os.path.exists(DB_PATH)
    })

# ---------------------------------------------------------------------------
# STATIC PAGE ROUTES
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/<path:filename>")
def serve_static(filename):
    """Serve static HTML files. Reject path traversal attempts."""
    if ".." in filename or filename.startswith("/"):
        abort(404)
    try:
        return send_from_directory(".", filename)
    except (FileNotFoundError, PermissionError):
        abort(404)

# ---------------------------------------------------------------------------
# ERROR HANDLERS
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Forbidden"}), 403

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Rate limit exceeded. Try again in 1 hour."}), 429

@app.errorhandler(500)
def server_error(e):
    log.error(f"500 error: {e}")
    return jsonify({"error": "Internal server error"}), 500

# ---------------------------------------------------------------------------
# STARTUP
# ---------------------------------------------------------------------------

init_db()

# Validate environment on startup
missing = []
if not STRIPE_SECRET_KEY:
    missing.append("STRIPE_SECRET_KEY")
if not STRIPE_WEBHOOK_SECRET:
    missing.append("STRIPE_WEBHOOK_SECRET")
if not RESEND_API_KEY:
    missing.append("RESEND_API_KEY")
if not LICENSE_SIGNING_KEY:
    missing.append("LICENSE_SIGNING_KEY")

if missing:
    log.warning(f"Missing environment variables: {', '.join(missing)}")
    log.warning("Some features will not work until these are set")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
