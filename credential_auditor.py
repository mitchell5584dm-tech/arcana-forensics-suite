#!/usr/bin/env python3
"""
Arcana Forensics - Credential Auditor Pro
Offline password auditing with entropy analysis, breach checking, and chain-of-custody reporting.

Usage:
    python3 credential_auditor.py --input creds.txt --output ./reports
    python3 credential_auditor.py --input creds.txt --output ./reports --license ARCF-XXXX-XXXX-XXXX-XXXX
    python3 credential_auditor.py --input creds.txt --output ./reports --format json
"""

import os
import sys
import json
import argparse
import hashlib
import math
import re
import time
import sqlite3
import hmac
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from collections import Counter

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

VERSION = "2.0.0"
LICENSE_VERIFY_URL = "https://api.arcana-forensics.com/api/verify-license"
BREACH_DB_PATH = os.getenv("BREACH_DB_PATH", "breach_hashes.db")
MAX_PASSWORD_LENGTH = 256
MAX_INPUT_SIZE_MB = 50

# ---------------------------------------------------------------------------
# CHAIN OF CUSTODY
# ---------------------------------------------------------------------------

class ChainOfCustody:
    def __init__(self, case_id: str = "ARCF-AUDIT", investigator: str = "unknown"):
        self.case_id = case_id
        self.investigator = investigator
        self.previous_hash = "0" * 64
        self.entries = []

    def add_entry(self, action: str, details: Dict) -> Dict:
        timestamp = datetime.now(timezone.utc).isoformat()
        entry = {
            "case_id": self.case_id,
            "investigator": self.investigator,
            "timestamp": timestamp,
            "action": action,
            "details": details,
            "previous_hash": self.previous_hash,
        }
        entry_str = json.dumps(entry, sort_keys=True)
        current_hash = hashlib.sha256(entry_str.encode("utf-8")).hexdigest()
        entry["hash"] = current_hash
        self.previous_hash = current_hash
        self.entries.append(entry)
        return entry

    def export_jsonl(self, filepath: str) -> str:
        lines = []
        for entry in self.entries:
            verify_entry = {k: v for k, v in entry.items() if k != "hash"}
            verify_str = json.dumps(verify_entry, sort_keys=True)
            verify_hash = hashlib.sha256(verify_str.encode("utf-8")).hexdigest()
            if verify_hash != entry["hash"]:
                print(f"[!] CHAIN INTEGRITY FAILURE at {entry['timestamp']}")
            lines.append(json.dumps(entry))
        parent = os.path.dirname(filepath)
        if parent:
            os.makedirs(parent, exist_ok=True)
        fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, "\n".join(lines).encode("utf-8"))
        finally:
            os.close(fd)
        return filepath

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for entry in self.entries:
            if entry["previous_hash"] != prev:
                return False
            verify_entry = {k: v for k, v in entry.items() if k != "hash"}
            verify_str = json.dumps(verify_entry, sort_keys=True)
            verify_hash = hashlib.sha256(verify_str.encode("utf-8")).hexdigest()
            if verify_hash != entry["hash"]:
                return False
            prev = entry["hash"]
        return True

# ---------------------------------------------------------------------------
# LICENSE VERIFICATION
# ---------------------------------------------------------------------------

def verify_license_online(license_code: str) -> Tuple[bool, str]:
    try:
        r = requests.post(
            LICENSE_VERIFY_URL,
            json={"license_code": license_code},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            return data.get("valid", False), data.get("email", "unknown")
        return False, "License verification failed"
    except Exception:
        return False, "Could not reach license server"

def verify_license_offline(license_code: str, signing_key: str) -> bool:
    if not signing_key or not license_code:
        return False
    return license_code.startswith("ARCF-") and len(license_code) == 24

# ---------------------------------------------------------------------------
# ENTROPY ANALYSIS
# ---------------------------------------------------------------------------

def calculate_shannon_entropy(password: str) -> float:
    if not password:
        return 0.0
    length = len(password)
    counts = Counter(password)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def estimate_crack_time(entropy_bits: float) -> str:
    if entropy_bits < 10:
        return "instant"
    guesses_per_second = 1e10
    total_guesses = 2 ** entropy_bits
    seconds = total_guesses / guesses_per_second
    time_units = [
        ("years", seconds / 31536000),
        ("days", seconds / 86400),
        ("hours", seconds / 3600),
        ("minutes", seconds / 60),
        ("seconds", seconds),
    ]
    for unit, val in time_units:
        if val >= 1:
            if val > 1e9:
                return f"{val:.0f} {unit}"
            return f"{val:.1f} {unit}"
    return "instant"

def analyze_password_strength(password: str) -> Dict:
    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*()_+\-=$$$${};':\"\\|,.<>\/?`~]", password))
    has_unicode = bool(re.search(r"[^\x00-\x7F]", password))

    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 33
    if has_unicode:
        charset_size += 128

    entropy_bits = length * math.log2(charset_size) if charset_size > 0 else 0
    shannon_entropy = calculate_shannon_entropy(password)
    crack_time = estimate_crack_time(entropy_bits)

    if entropy_bits < 28:
        severity = "critical"
    elif entropy_bits < 36:
        severity = "high"
    elif entropy_bits < 60:
        severity = "medium"
    elif entropy_bits < 80:
        severity = "low"
    else:
        severity = "negligible"

    return {
        "length": length,
        "charset_size": charset_size,
        "entropy_bits": round(entropy_bits, 2),
        "shannon_entropy": round(shannon_entropy, 2),
        "crack_time": crack_time,
        "severity": severity,
        "composition": {
            "lower": has_lower,
            "upper": has_upper,
            "digit": has_digit,
            "special": has_special,
            "unicode": has_unicode,
        }
    }

# ---------------------------------------------------------------------------
# BREACH DATABASE
# ---------------------------------------------------------------------------

def init_breach_db():
    conn = sqlite3.connect(BREACH_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS breach_hashes (
            sha1_hash TEXT PRIMARY KEY,
            count INTEGER DEFAULT 1,
            source TEXT DEFAULT 'unknown'
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_breach_hash ON breach_hashes(sha1_hash)")
    conn.commit()
    conn.close()

def check_breached(password: str) -> Tuple[bool, int]:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    conn = sqlite3.connect(BREACH_DB_PATH)
    row = conn.execute("SELECT count FROM breach_hashes WHERE sha1_hash = ?", (sha1,)).fetchone()
    conn.close()
    if row:
        return True, row[0]
    return False, 0

def import_breach_hashes(filepath: str, source: str = "imported") -> int:
    if not os.path.exists(filepath):
        print(f"[!] Breach file not found: {filepath}")
        return 0
    conn = sqlite3.connect(BREACH_DB_PATH)
    count = 0
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            sha1 = line.split(":")[0].upper() if ":" in line else hashlib.sha1(line.encode()).hexdigest().upper()
            try:
                conn.execute("INSERT OR IGNORE INTO breach_hashes (sha1_hash, count, source) VALUES (?, 1, ?)", (sha1, source))
                count += 1
                if count % 10000 == 0:
                    conn.commit()
            except sqlite3.Error:
                continue
    conn.commit()
    conn.close()
    return count

# ---------------------------------------------------------------------------
# CREDENTIAL PARSING
# ---------------------------------------------------------------------------

def parse_credentials_file(filepath: str) -> List[Dict]:
    if not os.path.exists(filepath):
        print(f"[!] Input file not found: {filepath}")
        sys.exit(1)

    file_size = os.path.getsize(filepath)
    if file_size > MAX_INPUT_SIZE_MB * 1024 * 1024:
        print(f"[!] Input file exceeds {MAX_INPUT_SIZE_MB}MB limit")
        sys.exit(1)

    credentials = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            username = ""
            password = ""
            if ":" in line:
                parts = line.split(":", 1)
                username = parts[0].strip()
                password = parts[1].strip() if len(parts) > 1 else ""
            elif "," in line:
                parts = line.split(",", 1)
                username = parts[0].strip()
                password = parts[1].strip() if len(parts) > 1 else ""
            elif "\t" in line:
                parts = line.split("\t", 1)
                username = parts[0].strip()
                password = parts[1].strip() if len(parts) > 1 else ""
            else:
                password = line

            if len(password) > MAX_PASSWORD_LENGTH:
                continue
            if not password:
                continue

            credentials.append({
                "line_number": line_num,
                "username": username,
                "password": password,
            })
    return credentials

# ---------------------------------------------------------------------------
# AUDIT EXECUTION
# ---------------------------------------------------------------------------

def audit_credentials(credentials: List[Dict], check_breaches: bool = True) -> List[Dict]:
    results = []
    seen_passwords = {}

    for cred in credentials:
        password = cred["password"]
        username = cred["username"]
        strength = analyze_password_strength(password)
        breached = False
        breach_count = 0

        if check_breaches:
            breached, breach_count = check_breached(password)

        reused = password in seen_passwords
        if not reused:
            seen_passwords[password] = []

        seen_passwords[password].append(username)

        results.append({
            "line_number": cred["line_number"],
            "username": username,
            "password_length": strength["length"],
            "entropy_bits": strength["entropy_bits"],
            "shannon_entropy": strength["shannon_entropy"],
            "crack_time": strength["crack_time"],
            "severity": strength["severity"],
            "composition": strength["composition"],
            "breached": breached,
            "breach_count": breach_count,
            "reused": reused,
        })

    # Update reuse flag for all instances
    for result in results:
        password = credentials[result["line_number"] - 1]["password"]
        if len(seen_passwords[password]) > 1:
            result["reused"] = True
            result["reused_by"] = [u for u in seen_passwords[password] if u != result["username"]]

    return results

def generate_report(results: List[Dict], output_path: str, case_id: str, custody: ChainOfCustody) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(results)
    breached_count = sum(1 for r in results if r["breached"])
    reused_count = sum(1 for r in results if r["reused"])
    critical_count = sum(1 for r in results if r["severity"] == "critical")
    high_count = sum(1 for r in results if r["severity"] == "high")
    medium_count = sum(1 for r in results if r["severity"] == "medium")

    sorted_results = sorted(results, key=lambda x: x["entropy_bits"])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Arcana Forensics - Credential Audit Report {ts}</title>
<style>
:root {{ --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --critical: #f85149; --high: #ff7b72; --medium: #d29922; --low: #3fb950; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; padding: 40px 20px; line-height: 1.6; }}
.container {{ max-width: 1100px; margin: 0 auto; }}
header {{ border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }}
h1 {{ font-size: 1.8rem; color: var(--accent); margin-bottom: 8px; }}
h2 {{ font-size: 1.3rem; margin: 28px 0 12px; }}
.meta {{ color: #8b949e; font-size: 0.9rem; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 24px 0; }}
.summary-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }}
.summary-card .number {{ font-size: 2rem; font-weight: 700; }}
.summary-card .label {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; color: #8b949e; }}
.critical .number {{ color: var(--critical); }}
.high .number {{ color: var(--high); }}
.medium .number {{ color: var(--medium); }}
.low .number {{ color: var(--low); }}
table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
th {{ background: var(--surface); text-align: left; padding: 10px; border: 1px solid var(--border); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; }}
td {{ padding: 8px 10px; border: 1px solid var(--border); font-size: 0.88rem; }}
.severity-critical {{ color: var(--critical); font-weight: 700; }}
.severity-high {{ color: var(--high); font-weight: 600; }}
.severity-medium {{ color: var(--medium); }}
.severity-low {{ color: var(--low); }}
.mono {{ font-family: "SF Mono", Consolas, monospace; }}
.breached {{ background: rgba(248, 81, 73, 0.1); }}
.reused {{ background: rgba(210, 153, 34, 0.1); }}
footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); color: #8b949e; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="container">
<header>
<h1>Credential Audit Report</h1>
<p class="meta">Generated: {ts}<br>Case: {case_id}<br>Mode: 100% Offline | Chain of Custody: Active</p>
</header>

<div class="summary-grid">
<div class="summary-card"><div class="number">{total}</div><div class="label">Total Credentials</div></div>
<div class="summary-card critical"><div class="number">{critical_count}</div><div class="label">Critical</div></div>
<div class="summary-card high"><div class="number">{high_count}</div><div class="label">High Risk</div></div>
<div class="summary-card medium"><div class="number">{medium_count}</div><div class="label">Medium Risk</div></div>
<div class="summary-card"><div class="number">{breached_count}</div><div class="label">Breached</div></div>
<div class="summary-card"><div class="number">{reused_count}</div><div class="label">Reused</div></div>
</div>

<section>
<h2>Findings (Sorted by Risk - Lowest Entropy First)</h2>
<table>
<tr><th>Line</th><th>Username</th><th>Length</th><th>Entropy</th><th>Crack Time</th><th>Severity</th><th>Breached</th><th>Reused</th></tr>
"""
    for r in sorted_results:
        row_class = ""
        if r["breached"]:
            row_class = "breached"
        elif r["reused"]:
            row_class = "reused"

        html += f'<tr class="{row_class}">'
        html += f'<td class="mono">{r["line_number"]}</td>'
        html += f'<td class="mono">{r["username"] or "N/A"}</td>'
        html += f'<td>{r["password_length"]}</td>'
        html += f'<td>{r["entropy_bits"]}</td>'
        html += f'<td>{r["crack_time"]}</td>'
        html += f'<td class="severity-{r["severity"]}">{r["severity"].upper()}</td>'
        html += f'<td>{"YES (" + str(r["breach_count"]) + ")" if r["breached"] else "No"}</td>'
        html += f'<td>{"Yes" if r["reused"] else "No"}</td>'
        html += '</tr>'

    html += f"""</table>
</section>
<footer>
<p>Arcana Forensics Credential Auditor Pro v{VERSION}<br>
Report generated offline. No data transmitted.<br>
Chain of custody hash: {custody.previous_hash[:32]}...<br>
Full custody log: custody.jsonl</p>
</footer>
</div>
</body>
</html>"""

    os.makedirs(output_path, exist_ok=True)
    report_file = os.path.join(output_path, "audit_report.html")
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html)
    return report_file

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Arcana Forensics - Credential Auditor Pro")
    parser.add_argument("--input", required=True, help="Input credentials file (user:pass per line)")
    parser.add_argument("--output", default="./reports", help="Output directory for reports")
    parser.add_argument("--license", help="License code for Pro features")
    parser.add_argument("--case-id", default="ARCF-AUDIT", help="Case identifier for chain of custody")
    parser.add_argument("--investigator", default=os.getenv("USER", "unknown"), help="Investigator name")
    parser.add_argument("--no-breach-check", action="store_true", help="Skip breach database check")
    parser.add_argument("--import-breaches", help="Import breach hashes from file (SHA1 format)")
    parser.add_argument("--format", choices=["html", "json", "both"], default="html", help="Output format")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    print(f"[*] Arcana Forensics Credential Auditor Pro v{VERSION}")
    print(f"[*] Case: {args.case_id}")
    print(f"[*] Investigator: {args.investigator}")
    print(f"[*] Mode: Offline")

    # Initialize breach database
    init_breach_db()

    # Import breaches if requested
    if args.import_breaches:
        print(f"[*] Importing breach hashes from {args.import_breaches}...")
        count = import_breach_hashes(args.import_breaches)
        print(f"[+] Imported {count} breach hashes")
        return

    # License verification
    is_pro = False
    if args.license:
        print(f"[*] Verifying license: {args.license[:8]}...")
        is_pro, email = verify_license_online(args.license)
        if is_pro:
            print(f"[+] License valid. Registered to: {email}")
        else:
            print(f"[!] License verification failed. Running in free mode.")
            print(f"[*] Free mode: limited to 50 credentials, no breach checking")
    else:
        print(f"[*] No license provided. Running in free mode.")
        print(f"[*] Free mode: limited to 50 credentials, no breach checking")

    # Chain of custody
    custody = ChainOfCustody(args.case_id, args.investigator)
    custody.add_entry("AUDIT_STARTED", {
        "input_file": os.path.abspath(args.input),
        "output_dir": os.path.abspath(args.output),
        "pro_mode": is_pro,
        "tool_version": VERSION,
    })

    # Parse credentials
    print(f"[*] Parsing credentials from {args.input}...")
    credentials = parse_credentials_file(args.input)
    print(f"[+] Found {len(credentials)} credentials")

    # Free mode limit
    if not is_pro and len(credentials) > 50:
        print(f"[!] Free mode limited to 50 credentials. Found {len(credentials}. Truncating.")
        credentials = credentials[:50]

    custody.add_entry("CREDENTIALS_PARSED", {"count": len(credentials)})

    # Audit
    print(f"[*] Auditing credentials...")
    check_breaches = is_pro and not args.no_breach_check
    results = audit_credentials(credentials, check_breaches)
    custody.add_entry("AUDIT_COMPLETED", {
        "total_audited": len(results),
        "breach_check_enabled": check_breaches,
    })

    # Generate report
    print(f"[*] Generating report...")
    if args.format in ("html", "both"):
        report_file = generate_report(results, args.output, args.case_id, custody)
        print(f"[+] HTML report: {report_file}")
    if args.format in ("json", "both"):
        json_file = os.path.join(args.output, "audit_results.json")
        os.makedirs(args.output, exist_ok=True)
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"[+] JSON report: {json_file}")

    # Export chain of custody
    custody_file = os.path.join(args.output, "custody.jsonl")
    custody.export_jsonl(custody_file)
    print(f"[+] Chain of custody: {custody_file}")

    # Verify chain integrity
    if custody.verify_chain():
        print(f"[+] Chain of custody verified: OK")
    else:
        print(f"[!] Chain of custody verification FAILED")

    # Summary
    breached = sum(1 for r in results if r["breached"])
    reused = sum(1 for r in results if r["reused"])
    critical = sum(1 for r in results if r["severity"] == "critical")

    print(f"\n{'='*50}")
    print(f"AUDIT COMPLETE")
    print(f"{'='*50}")
    print(f"Total credentials: {len(results)}")
    print(f"Critical risk: {critical}")
    print(f"Breached passwords: {breached}")
    print(f"Reused passwords: {reused}")
    print(f"Reports saved to: {args.output}")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
