#!/usr/bin/env python3
"""
Arcana Forensics - Credential Auditor Pro
Offline credential auditing with chain-of-custody evidence logging.

Usage:
    python3 credential_auditor.py --input creds.txt --breach-db hashes.txt --output ./reports
    python3 credential_auditor.py --shadow --breach-db hashes.txt --output ./reports
    python3 credential_auditor.py --input creds.csv --output ./reports

Input formats accepted:
    TXT:  username:password (one per line)
    CSV:  username,password (header row expected)
    JSON: [{"username": "x", "password": "y"}, ...]

Breach database format:
    SHA-1 hashes, one per line (plaintext passwords hashed, newline separated)
    Compatible with HaveIBeenPwned offline SHA-1 dumps
"""

import os
import sys
import csv
import json
import math
import argparse
import hashlib
import getpass
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {
    "Critical": 100,
    "High": 60,
    "Medium": 30,
    "Low": 10,
    "Info": 0,
}

# Common password list (subset for offline use without external deps)
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "letmein",
    "dragon", "master", "sunshine", "princess", "admin", "welcome", "login",
    "trustno1", "000000", "password1", "123456789", "1234567", "12345",
    "iloveyou", "shadow", "starwars", "whatever", "football", "baseball",
    "superman", "batman", "michael", "jordan", "harley", "ranger", "hunter",
    "passw0rd", "p@ssword", "p@ssw0rd", "ninja", "mustang", "access", "flower",
}

KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdf", "asdfgh", "asdfghjkl",
    "zxcv", "zxcvbn", "zxcvbnm", "1234", "2345", "3456",
    "4567", "5678", "6789", "7890", "qazwsx", "wsxedc",
]

SEQUENTIAL_PATTERNS = [
    "abcdef", "bcdefg", "cdefgh", "defghi", "efghij",
    "123456", "234567", "345678", "456789", "012345",
]

REPETITION_PATTERN = re.compile(r"(.)\1{2,}")

# ---------------------------------------------------------------------------
# FILE PERMISSIONS
# ---------------------------------------------------------------------------

def secure_write(filepath: str, content: str, mode: str = "w") -> str:
    """Write content with restrictive permissions (owner-only access)."""
    abs_path = os.path.abspath(filepath)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True) if os.path.dirname(abs_path) else None
    fd = os.open(abs_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        if isinstance(content, bytes):
            os.write(fd, content)
        else:
            os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)
    return abs_path

# ---------------------------------------------------------------------------
# INPUT PARSING
# ---------------------------------------------------------------------------

def parse_credential_file(filepath: str) -> List[Dict[str, str]]:
    """Parse credential files in TXT, CSV, or JSON format."""
    creds = []
    ext = Path(filepath).suffix.lower()

    if ext == ".json":
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict) and "username" in entry and "password" in entry:
                        creds.append({"username": str(entry["username"]), "password": str(entry["password"])})
            elif isinstance(data, dict):
                for username, password in data.items():
                    creds.append({"username": str(username), "password": str(password)})
    elif ext == ".csv":
        with open(filepath, "r", newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                username = row.get("username") or row.get("user") or row.get("Username") or ""
                password = row.get("password") or row.get("pass") or row.get("Password") or ""
                if username and password:
                    creds.append({"username": username.strip(), "password": password})
    else:
        # TXT: username:password or username,password
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for delimiter in [":", ",", "\t", ";", "|"]:
                    if delimiter in line:
                        parts = line.split(delimiter, 1)
                        if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                            creds.append({"username": parts[0].strip(), "password": parts[1]})
                        break
    return creds

def parse_shadow() -> List[Dict[str, str]]:
    """Parse /etc/shadow for password hashes (requires root)."""
    creds = []
    shadow_path = "/etc/shadow"
    if not os.path.exists(shadow_path):
        print(f"[-] {shadow_path} not found (Linux only, requires root)")
        return creds
    if not os.access(shadow_path, os.R_OK):
        print(f"[-] Cannot read {shadow_path} (run as root or with sudo)")
        return creds
    with open(shadow_path, "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) < 2:
                continue
            username = parts[0]
            hash_field = parts[1]
            if hash_field in ("", "*", "!", "!!", "x"):
                continue  # No password set or locked
            creds.append({"username": username, "password": hash_field, "is_hash": True})
    return creds

def load_breach_database(filepath: str) -> set:
    """Load SHA-1 hashes from a breach database file."""
    hashes = set()
    if not filepath or not os.path.exists(filepath):
        print(f"[-] Breach database not found: {filepath}")
        return hashes
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            h = line.strip().upper()
            if len(h) == 40:
                hashes.add(h)
    print(f"[+] Loaded {len(hashes)} breach hashes from {filepath}")
    return hashes

# ---------------------------------------------------------------------------
# PASSWORD ANALYSIS
# ---------------------------------------------------------------------------

def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of a password in bits."""
    if not password:
        return 0.0
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for c in password):
        charset_size += 32
    if any(ord(c) > 127 for c in password):
        charset_size += 128
    if charset_size == 0:
        charset_size = 1
    return math.log2(charset_size) * len(password)

def check_patterns(password: str) -> List[str]:
    """Detect keyboard walks, sequential patterns, and repetitions."""
    issues = []
    lower = password.lower()

    for pattern in KEYBOARD_PATTERNS:
        if pattern in lower:
            issues.append(f"Keyboard pattern detected: {pattern}")
            break

    for pattern in SEQUENTIAL_PATTERNS:
        if pattern in lower:
            issues.append(f"Sequential pattern detected: {pattern}")
            break

    if REPETITION_PATTERN.search(password):
        issues.append("Character repetition detected (3+ identical consecutive)")

    if lower != password and password.isupper():
        issues.append("All uppercase - reduces keyspace")

    return issues

def check_breach(password: str, breach_hashes: set) -> bool:
    """Check if password appears in the breach database (SHA-1)."""
    if not breach_hashes:
        return False
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return sha1 in breach_hashes

def audit_password(password: str, breach_hashes: set, username: str = "") -> Dict:
    """Run full password analysis and return findings."""
    findings = []
    severity = "Info"

    if not password:
        findings.append("Empty password")
        return {"severity": "Critical", "issues": findings, "score": 0}

    length = len(password)
    entropy = calculate_entropy(password)
    lower = password.lower()

    # Length checks
    if length < 8:
        findings.append(f"Critical: Password length {length} below minimum (8)")
        severity = "Critical"
    elif length < 12:
        findings.append(f"Password length {length} below recommended (12)")
        if SEVERITY_WEIGHTS["High"] > SEVERITY_WEIGHTS.get(severity, 0):
            severity = "High"
    elif length < 16:
        findings.append(f"Password length {length} acceptable but below strong (16)")
        if SEVERITY_WEIGHTS["Medium"] > SEVERITY_WEIGHTS.get(severity, 0):
            severity = "Medium"

    # Entropy checks
    if entropy < 28:
        findings.append(f"Critical: Entropy {entropy:.1f} bits - extremely weak")
        severity = "Critical"
    elif entropy < 40:
        findings.append(f"Entropy {entropy:.1f} bits - weak")
        if SEVERITY_WEIGHTS["High"] > SEVERITY_WEIGHTS.get(severity, 0):
            severity = "High"
    elif entropy < 60:
        findings.append(f"Entropy {entropy:.1f} bits - moderate")
        if SEVERITY_WEIGHTS["Medium"] > SEVERITY_WEIGHTS.get(severity, 0):
            severity = "Medium"
    else:
        findings.append(f"Entropy {entropy:.1f} bits - strong")

    # Common password check
    if lower in COMMON_PASSWORDS:
        findings.append("Critical: Password found in common password dictionary")
        severity = "Critical"

    # Username in password
    if username and username.lower() in lower:
        findings.append("Critical: Username embedded in password")
        severity = "Critical"

    # Pattern detection
    pattern_issues = check_patterns(password)
    for issue in pattern_issues:
        findings.append(issue)
        if "Keyboard" in issue or "Sequential" in issue:
            if SEVERITY_WEIGHTS["High"] > SEVERITY_WEIGHTS.get(severity, 0):
                severity = "High"
        elif SEVERITY_WEIGHTS["Medium"] > SEVERITY_WEIGHTS.get(severity, 0):
            severity = "Medium"

    # Breach check
    if check_breach(password, breach_hashes):
        findings.append("Critical: Password found in breach database")
        severity = "Critical"

    return {
        "severity": severity,
        "issues": findings,
        "score": SEVERITY_WEIGHTS[severity],
        "entropy": round(entropy, 2),
        "length": length,
    }

def detect_reuse(credentials: List[Dict]) -> Dict[str, List[str]]:
    """Detect passwords reused across multiple accounts."""
    password_map = {}
    for cred in credentials:
        if cred.get("is_hash"):
            continue
        pw = cred["password"]
        if pw not in password_map:
            password_map[pw] = []
        password_map[pw].append(cred["username"])

    reused = {}
    for pw, users in password_map.items():
        if len(users) > 1:
            reused[pw] = users
    return reused

# ---------------------------------------------------------------------------
# CHAIN OF CUSTODY
# ---------------------------------------------------------------------------

class ChainOfCustody:
    """SHA-256 chained JSONL evidence log."""

    def __init__(self, case_id: str = "ARCF-DEFAULT", investigator: str = "unknown"):
        self.case_id = case_id
        self.investigator = investigator
        self.previous_hash = "0" * 64
        self.entries = []

    def add_entry(self, action: str, details: Dict) -> Dict:
        """Add a chained evidence entry."""
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
        """Export the chain as JSONL with integrity verification."""
        lines = []
        for entry in self.entries:
            verify_entry = {k: v for k, v in entry.items() if k != "hash"}
            verify_str = json.dumps(verify_entry, sort_keys=True)
            verify_hash = hashlib.sha256(verify_str.encode("utf-8")).hexdigest()
            if verify_hash != entry["hash"]:
                print(f"[!] CHAIN INTEGRITY FAILURE at entry {entry['timestamp']}")
            lines.append(json.dumps(entry))
        content = "\n".join(lines)
        return secure_write(filepath, content)

    def verify_chain(self) -> bool:
        """Verify the entire chain hasn't been tampered with."""
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
# REPORT GENERATION
# ---------------------------------------------------------------------------

def generate_html_report(findings: List[Dict], reuse_map: Dict, metadata: Dict, output_path: str) -> str:
    """Generate a structured HTML report with findings table."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total_creds = metadata.get("total_credentials", 0)
    critical_pct = (severity_counts["Critical"] / max(total_creds, 1)) * 100

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Arcana Forensics - Credential Audit Report {ts}</title>
<style>
:root {{ --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --critical: #f85149; --high: #ff7b72; --medium: #d29922; --low: #3fb950; --info: #58a6ff; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; padding: 40px 20px; line-height: 1.6; }}
.container {{ max-width: 1100px; margin: 0 auto; }}
header {{ border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }}
h1 {{ font-size: 1.8rem; color: var(--accent); margin-bottom: 8px; }}
h2 {{ font-size: 1.3rem; margin: 24px 0 12px; color: var(--text); }}
.meta {{ color: #8b949e; font-size: 0.9rem; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 24px 0; }}
.summary-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
.summary-card .count {{ font-size: 2rem; font-weight: 700; }}
.summary-card .label {{ font-size: 0.8rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; }}
.critical .count {{ color: var(--critical); }}
.high .count {{ color: var(--high); }}
.medium .count {{ color: var(--medium); }}
.low .count {{ color: var(--low); }}
.info .count {{ color: var(--info); }}
table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
th {{ background: var(--surface); text-align: left; padding: 12px; border: 1px solid var(--border); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }}
td {{ padding: 10px 12px; border: 1px solid var(--border); font-size: 0.9rem; vertical-align: top; }}
.sev-Critical {{ color: var(--critical); font-weight: 700; }}
.sev-High {{ color: var(--high); font-weight: 600; }}
.sev-Medium {{ color: var(--medium); font-weight: 600; }}
.sev-Low {{ color: var(--low); }}
.sev-Info {{ color: var(--info); }}
.issues {{ font-size: 0.85rem; }}
.issues li {{ margin-bottom: 4px; }}
.reuse-entry {{ background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--critical); border-radius: 4px; padding: 12px; margin: 8px 0; }}
.reuse-users {{ color: var(--critical); font-weight: 600; }}
footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); color: #8b949e; font-size: 0.8rem; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; margin-left: 8px; }}
.badge-offline {{ background: #1a3d2e; color: var(--low); }}
</style>
</head>
<body>
<div class="container">
<header>
<h1>Arcana Forensics - Credential Audit Report</h1>
<p class="meta">Generated: {ts}<br>
Case: {metadata.get('case_id', 'N/A')} | Investigator: {metadata.get('investigator', 'N/A')}<br>
Mode: 100% Offline <span class="badge badge-offline">No Telemetry</span></p>
</header>

<section>
<h2>Executive Summary</h2>
<div class="summary-grid">
<div class="summary-card critical"><div class="count">{severity_counts["Critical"]}</div><div class="label">Critical</div></div>
<div class="summary-card high"><div class="count">{severity_counts["High"]}</div><div class="label">High</div></div>
<div class="summary-card medium"><div class="count">{severity_counts["Medium"]}</div><div class="label">Medium</div></div>
<div class="summary-card low"><div class="count">{severity_counts["Low"]}</div><div class="label">Low</div></div>
<div class="summary-card info"><div class="count">{severity_counts["Info"]}</div><div class="label">Info</div></div>
<div class="summary-card"><div class="count">{total_creds}</div><div class="label">Credentials Audited</div></div>
</div>
<p>Critical findings affect {critical_pct:.1f}% of audited credentials. Immediate remediation recommended.</p>
</section>
"""

    if reuse_map:
        html += """
<section>
<h2>Password Reuse Detection</h2>
<p>The following passwords are shared across multiple accounts. This is a critical security risk.</p>
"""
        for pw, users in reuse_map.items():
            masked = pw[:2] + "*" * (len(pw) - 4) + pw[-2:] if len(pw) > 4 else "*" * len(pw)
            html += f'<div class="reuse-entry"><div>Password: <code>{masked}</code></div><div class="reuse-users">Accounts ({len(users)}): {", ".join(users)}</div></div>'
        html += "</section>"

    html += """
<section>
<h2>Detailed Findings</h2>
<table>
<tr><th>Username</th><th>Severity</th><th>Length</th><th>Entropy</th><th>Issues</th><th>Recommended Fix</th></tr>
"""
    for f in findings:
        issues_html = "<ul class='issues'>" + "".join(f"<li>{issue}</li>" for issue in f.get("issues", [])) + "</ul>" if f.get("issues") else "None"
        fix = "Change password immediately - 16+ chars, mixed case, symbols" if f.get("severity") == "Critical" else "Update password to meet 12+ char policy" if f.get("severity") == "High" else "Consider updating at next cycle"
        html += f"""<tr>
<td>{f.get('username', 'N/A')}</td>
<td class="sev-{f.get('severity', 'Info')}">{f.get('severity', 'Info')}</td>
<td>{f.get('length', 'N/A')}</td>
<td>{f.get('entropy', 'N/A')}</td>
<td>{issues_html}</td>
<td>{fix}</td>
</tr>"""

    html += f"""</table>
</section>
<footer>
<p>Arcana Forensics - Credential Auditor Pro | Offline Report<br>
Chain of custody: {metadata.get('custody_hash', 'N/A')} | SHA-256 verified<br>
No data transmitted. All analysis performed locally.</p>
</footer>
</div>
</body>
</html>"""

    return secure_write(output_path, html)

def generate_csv_report(findings: List[Dict], output_path: str) -> str:
    """Generate CSV report of findings."""
    lines = ["Username,Severity,Length,Entropy,Issues,Fix,Timestamp"]
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for f in findings:
        issues = " | ".join(f.get("issues", []))
        fix = "Change immediately" if f.get("severity") == "Critical" else "Update to 12+ chars" if f.get("severity") == "High" else "Review"
        lines.append(f'{f.get("username","")},{f.get("severity","")},{f.get("length","")},{f.get("entropy","")},"{issues}","{fix}",{ts}')
    return secure_write(output_path, "\n".join(lines))

# ---------------------------------------------------------------------------
# NOTIFICATION (SIMPLE, NO TKINTER SWALLOW)
# ---------------------------------------------------------------------------

def notify(filepath: str):
    """Print completion info. Desktop notifications optional, non-fatal."""
    abs_path = os.path.abspath(filepath)
    print(f"[+] Report saved: {abs_path}")
    try:
        import subprocess
        subprocess.Popen(["notify-send", "Arcana Forensics", f"Report: {os.path.basename(abs_path)}"], stderr=subprocess.DEVNULL)
    except (FileNotFoundError, OSError):
        pass  # No notify-send on this system, not an error

# ---------------------------------------------------------------------------
# MAIN AUDIT PIPELINE
# ---------------------------------------------------------------------------

def run_audit(args):
    """Execute the full credential audit pipeline."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = os.path.expanduser(args.output) if args.output else os.path.expanduser(f"~/Arcana_Forensics_Reports/{timestamp}")
    os.makedirs(output_dir, exist_ok=True)

    investigator = args.investigator or getpass.getuser()
    case_id = args.case_id or f"ARCF-{timestamp}"
    custody = ChainOfCustody(case_id=case_id, investigator=investigator)

    custody.add_entry("AUDIT_INITIATED", {
        "output_directory": output_dir,
        "arguments": vars(args),
    })

    # Load credentials
    credentials = []
    if args.shadow:
        shadow_creds = parse_shadow()
        credentials.extend(shadow_creds)
        custody.add_entry("SHADOW_PARSED", {"user_count": len(shadow_creds)})

    if args.input:
        file_creds = parse_credential_file(args.input)
        credentials.extend(file_creds)
        custody.add_entry("CREDENTIAL_FILE_PARSED", {
            "file": args.input,
            "entry_count": len(file_creds),
        })

    if not credentials:
        print("[!] No credentials found. Provide --input or --shadow.")
        print("    Example: python3 credential_auditor.py --input creds.txt")
        sys.exit(1)

    # Enforce user limit
    if len(credentials) > args.max_users:
        print(f"[!] Credential count ({len(credentials)}) exceeds limit ({args.max_users}). Truncating.")
        credentials = credentials[:args.max_users]
        custody.add_entry("USER_LIMIT_REACHED", {"limit": args.max_users, "truncated": True})

    # Load breach database
    breach_hashes = load_breach_database(args.breach_db) if args.breach_db else set()
    if breach_hashes:
        custody.add_entry("BREACH_DB_LOADED", {"hash_count": len(breach_hashes), "source": args.breach_db})

    # Audit each credential
    findings = []
    for cred in credentials:
        username = cred["username"]
        password = cred["password"]
        is_hash = cred.get("is_hash", False)

        if is_hash:
            findings.append({
                "username": username,
                "severity": "Info",
                "issues": ["Password stored as hash - offline strength audit unavailable. Hash type detected."],
                "length": 0,
                "entropy": 0,
            })
            continue

        result = audit_password(password, breach_hashes, username)
        findings.append({
            "username": username,
            "severity": result["severity"],
            "issues": result["issues"],
            "length": result["length"],
            "entropy": result["entropy"],
        })
        custody.add_entry("CREDENTIAL_AUDITED", {
            "username": username,
            "severity": result["severity"],
            "score": result["score"],
        })

    # Reuse detection
    reuse_map = detect_reuse(credentials)
    if reuse_map:
        custody.add_entry("REUSE_DETECTED", {
            "reuse_count": len(reuse_map),
            "affected_accounts": sum(len(users) for users in reuse_map.values()),
        })

    # Verify chain integrity
    chain_valid = custody.verify_chain()
    custody.add_entry("AUDIT_COMPLETE", {
        "total_credentials": len(credentials),
        "total_findings": len(findings),
        "chain_integrity": chain_valid,
    })

    # Generate reports
    html_path = os.path.join(output_dir, f"Arcana_Audit_Report_{timestamp}.html")
    csv_path = os.path.join(output_dir, f"Arcana_Audit_Findings_{timestamp}.csv")
    jsonl_path = os.path.join(output_dir, f"Arcana_ChainOfCustody_{timestamp}.jsonl")

    metadata = {
        "case_id": case_id,
        "investigator": investigator,
        "total_credentials": len(credentials),
        "custody_hash": custody.previous_hash,
    }

    generate_html_report(findings, reuse_map, metadata, html_path)
    notify(html_path)

    generate_csv_report(findings, csv_path)
    notify(csv_path)

    custody.export_jsonl(jsonl_path)
    notify(jsonl_path)

    # Summary
    print(f"\n{'='*60}")
    print(f"ARCANA FORENSICS - AUDIT COMPLETE")
    print(f"{'='*60}")
    print(f"Credentials audited: {len(credentials)}")
    print(f"Chain of custody:    {'VALID' if chain_valid else 'COMPROMISED'}")
    print(f"Reuse detected:      {len(reuse_map)} shared passwords")
    print(f"Reports location:    {output_dir}")
    print(f"  - HTML:  {os.path.basename(html_path)}")
    print(f"  - CSV:   {os.path.basename(csv_path)}")
    print(f"  - JSONL: {os.path.basename(jsonl_path)}")
    print(f"{'='*60}\n")

# ---------------------------------------------------------------------------
# ARGUMENT PARSING
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Arcana Forensics - Offline Credential Auditor Pro",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Audit a credential file:
    python3 credential_auditor.py --input creds.txt --output ./reports

  Audit with breach database:
    python3 credential_auditor.py --input creds.txt --breach-db pwned-hashes.txt --output ./reports

  Audit /etc/shadow (requires root):
    python3 credential_auditor.py --shadow --output ./reports

  Audit with case tracking:
    python3 credential_auditor.py --input creds.csv --case-id ARCF-2026-001 --investigator "analyst@org" --output ./reports
        """,
    )
    parser.add_argument("--input", "-i", help="Credential file (TXT, CSV, or JSON)")
    parser.add_argument("--shadow", action="store_true", help="Parse /etc/shadow (Linux, requires root)")
    parser.add_argument("--breach-db", "-b", help="Breach database file (SHA-1 hashes, one per line)")
    parser.add_argument("--output", "-o", help="Output directory for reports (default: ~/Arcana_Forensics_Reports/)")
    parser.add_argument("--max-users", type=int, default=500, help="Maximum credentials to audit (default: 500)")
    parser.add_argument("--case-id", help="Case identifier for chain of custody")
    parser.add_argument("--investigator", help="Investigator identifier for chain of custody")

    args = parser.parse_args()

    if not args.input and not args.shadow:
        parser.error("Provide --input <file> or --shadow to specify credential source")

    run_audit(args)

if __name__ == "__main__":
    main()