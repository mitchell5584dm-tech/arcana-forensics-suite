#!/usr/bin/env python3
"""
Arcana Forensics - Linux Triage Helper (Free Forever)
Offline system triage and evidence collection for Linux.

Usage:
    python3 linux_triage.py --output ./triage_report
    python3 linux_triage.py --output ./triage_report --case-id ARCF-2026-001
"""

import os
import sys
import json
import argparse
import hashlib
import platform
import subprocess
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional

def secure_write(filepath: str, content: str) -> str:
    abs_path = os.path.abspath(filepath)
    parent = os.path.dirname(abs_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd = os.open(abs_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)
    return abs_path

class ChainOfCustody:
    def __init__(self, case_id: str = "ARCF-TRIAGE", investigator: str = "unknown"):
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
        return secure_write(filepath, "\n".join(lines))

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

def run_command(cmd: List[str], timeout: int = 10) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return result.stdout.strip() if result.stdout else ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""

def read_file_safe(filepath: str, max_lines: int = 500) -> List[str]:
    if not os.path.exists(filepath):
        return []
    if not os.access(filepath, os.R_OK):
        return []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = []
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                lines.append(line.rstrip())
            return lines
    except (IOError, OSError):
        return []

def collect_system_info() -> Dict:
    return {
        "hostname": platform.node(),
        "os": platform.platform(),
        "kernel": platform.release(),
        "python_version": platform.python_version(),
        "architecture": platform.machine(),
        "boot_time": run_command(["uptime", "-p"]),
        "current_user": os.getenv("USER", "unknown"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

def collect_processes() -> List[Dict]:
    output = run_command(["ps", "aux"])
    if not output:
        return []
    lines = output.split("\n")
    processes = []
    if len(lines) < 2:
        return processes
    header = lines[0].split()
    cpu_idx = header.index("%CPU") if "%CPU" in header else 2
    mem_idx = header.index("%MEM") if "%MEM" in header else 3
    for line in lines[1:]:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        try:
            processes.append({
                "user": parts[0],
                "pid": parts[1],
                "cpu": float(parts[cpu_idx]),
                "mem": float(parts[mem_idx]),
                "command": parts[10],
            })
        except (ValueError, IndexError):
            continue
    processes.sort(key=lambda x: x["cpu"], reverse=True)
    return processes[:20]

def collect_network_connections() -> List[Dict]:
    connections = []
    output = run_command(["ss", "-tulnp"])
    if output:
        lines = output.split("\n")
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 6:
                connections.append({
                    "protocol": parts[0],
                    "local_address": parts[4],
                    "peer_address": parts[5] if len(parts) > 5 else "*",
                    "process": parts[6] if len(parts) > 6 else "unknown",
                })
    return connections

def collect_listening_ports() -> List[Dict]:
    ports = []
    output = run_command(["ss", "-tlnp"])
    if output:
        lines = output.split("\n")
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4:
                addr = parts[3]
                port_match = re.search(r":(\d+)$", addr)
                if port_match:
                    ports.append({
                        "address": addr,
                        "port": int(port_match.group(1)),
                        "process": parts[5] if len(parts) > 5 else "unknown",
                    })
    return ports

def collect_failed_logins() -> List[Dict]:
    failed = []
    log_paths = ["/var/log/auth.log", "/var/log/secure"]
    for log_path in log_paths:
        lines = read_file_safe(log_path, max_lines=1000)
        for line in lines:
            if "Failed password" in line:
                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                user_match = re.search(r"for (?:invalid user )?(\S+)", line)
                time_match = re.match(r"^(\S+\s+\d+\s+\d+:\d+:\d+)", line)
                failed.append({
                    "timestamp": time_match.group(1) if time_match else "unknown",
                    "source_ip": ip_match.group(1) if ip_match else "unknown",
                    "target_user": user_match.group(1) if user_match else "unknown",
                    "log_source": log_path,
                })
    ip_counts = {}
    for entry in failed:
        ip = entry["source_ip"]
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    unique_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    return [{"ip": ip, "attempts": count} for ip, count in unique_ips[:20]]

def collect_cron_jobs() -> List[Dict]:
    jobs = []
    system_cron = read_file_safe("/etc/crontab", max_lines=100)
    for line in system_cron:
        if line.strip() and not line.startswith("#"):
            jobs.append({"source": "/etc/crontab", "entry": line.strip()})
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]
    for cron_dir in cron_dirs:
        if os.path.exists(cron_dir) and os.path.isdir(cron_dir):
            for item in os.listdir(cron_dir):
                filepath = os.path.join(cron_dir, item)
                contents = read_file_safe(filepath, max_lines=10)
                for line in contents:
                    if line.strip() and not line.startswith("#"):
                        jobs.append({"source": filepath, "entry": line.strip()})
    user_crontab = run_command(["crontab", "-l"])
    if user_crontab:
        for line in user_crontab.split("\n"):
            if line.strip() and not line.startswith("#"):
                jobs.append({"source": "user_crontab", "entry": line.strip()})
    return jobs

def collect_suid_files() -> List[str]:
    output = run_command(["find", "/usr", "/bin", "/sbin", "/opt", "-type", "f", "-perm", "-4000"], timeout=30)
    if not output:
        return []
    return [f for f in output.split("\n") if f.strip()]

def collect_recent_modified() -> List[Dict]:
    sensitive_dirs = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin"]
    modified = []
    for directory in sensitive_dirs:
        if not os.path.exists(directory):
            continue
        output = run_command(["find", directory, "-type", "f", "-mtime", "-1"], timeout=20)
        if output:
            for filepath in output.split("\n"):
                if filepath.strip():
                    try:
                        stat = os.stat(filepath)
                        modified.append({
                            "path": filepath,
                            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        })
                    except OSError:
                        modified.append({"path": filepath, "modified": "unknown"})
    return modified[:50]

def collect_user_accounts() -> List[Dict]:
    users = []
    lines = read_file_safe("/etc/passwd", max_lines=200)
    for line in lines:
        parts = line.split(":")
        if len(parts) >= 7:
            uid = int(parts[2]) if parts[2].isdigit() else -1
            users.append({
                "username": parts[0],
                "uid": uid,
                "shell": parts[6],
                "home": parts[5],
                "has_login_shell": parts[6] not in ["/nologin", "/bin/false", "/usr/sbin/nologin"],
            })
    return users

def collect_disk_usage() -> List[Dict]:
    usage = []
    output = run_command(["df", "-h"])
    if output:
        lines = output.split("\n")
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 6:
                usage.append({
                    "filesystem": parts[0],
                    "size": parts[1],
                    "used": parts[2],
                    "available": parts[3],
                    "use_percent": parts[4],
                    "mount": parts[5],
                })
    return usage

def collect_memory_info() -> Dict:
    lines = read_file_safe("/proc/meminfo", max_lines=10)
    info = {}
    for line in lines:
        parts = line.split(":")
        if len(parts) == 2:
            key = parts[0].strip()
            val = parts[1].strip().split()[0]
            info[key] = val
    return info

def collect_kernel_modules() -> List[str]:
    output = run_command(["lsmod"])
    if not output:
        return []
    lines = output.split("\n")[1:]
    return [line.split()[0] for line in lines if line.strip()]

def detect_suspicious_processes(processes: List[Dict]) -> List[Dict]:
    suspicious = []
    suspicious_patterns = ["nc ", "ncat", "socat", "cryptominer", "xmrig", "kworker", "kdevtmpfs"]
    for proc in processes:
        cmd_lower = proc["command"].lower()
        for pattern in suspicious_patterns:
            if pattern in cmd_lower:
                suspicious.append({
                    "process": proc["command"],
                    "pid": proc["pid"],
                    "reason": f"Matches suspicious pattern: {pattern}",
                })
                break
    for proc in processes:
        if "/tmp/" in proc["command"] or "/dev/shm/" in proc["command"]:
            suspicious.append({
                "process": proc["command"],
                "pid": proc["pid"],
                "reason": "Running from temporary filesystem",
            })
    return suspicious

def detect_suspicious_ports(ports: List[Dict]) -> List[Dict]:
    suspicious = []
    known_risky_ports = {31337, 1234, 4444, 6667, 6668, 6669, 12345, 54321}
    for port in ports:
        if port["port"] in known_risky_ports:
            suspicious.append({
                "port": port["port"],
                "address": port["address"],
                "reason": "Known malware/RAT port",
            })
        if "127.0.0.1" not in port["address"] and "0.0.0.0" in port["address"]:
            suspicious.append({
                "port": port["port"],
                "address": port["address"],
                "reason": "Bound to all interfaces (0.0.0.0)",
            })
    return suspicious

def detect_anomalous_logins(failed: List[Dict]) -> List[Dict]:
    anomalous = []
    for entry in failed:
        if entry["attempts"] >= 10:
            anomalous.append({
                "ip": entry["ip"],
                "attempts": entry["attempts"],
                "reason": "High failed login count - possible brute force",
            })
    return anomalous

def generate_triage_report(data: Dict, custody_hash: str, output_path: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sys_info = data["system_info"]
    suspicious_procs = data["suspicious_processes"]
    suspicious_ports = data["suspicious_ports"]
    anomalous_logins = data["anomalous_logins"]
    total_findings = len(suspicious_procs) + len(suspicious_ports) + len(anomalous_logins)

    if total_findings == 0:
        banner_class = "findings-none"
        banner_text = "No suspicious activity detected in triage scan"
    elif total_findings <= 3:
        banner_class = "findings-low"
        banner_text = f"{total_findings} findings require review"
    else:
        banner_class = "findings-high"
        banner_text = f"{total_findings} findings detected - investigate immediately"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Arcana Forensics - Triage Report {ts}</title>
<style>
:root {{ --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --critical: #f85149; --high: #ff7b72; --medium: #d29922; --low: #3fb950; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; padding: 40px 20px; line-height: 1.6; }}
.container {{ max-width: 1100px; margin: 0 auto; }}
header {{ border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }}
h1 {{ font-size: 1.8rem; color: var(--accent); margin-bottom: 8px; }}
h2 {{ font-size: 1.3rem; margin: 28px 0 12px; color: var(--text); }}
.meta {{ color: #8b949e; font-size: 0.9rem; }}
.findings-banner {{ padding: 16px; border-radius: 8px; margin: 20px 0; text-align: center; font-size: 1.1rem; font-weight: 600; }}
.findings-none {{ background: #1a3d2e; color: var(--low); border: 1px solid #2d5a42; }}
.findings-low {{ background: #2d3b1a; color: var(--medium); border: 1px solid #4a5c2d; }}
.findings-high {{ background: #3d1a1a; color: var(--critical); border: 1px solid #5a2d2d; }}
section {{ margin-bottom: 32px; }}
.info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; }}
.info-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }}
.info-card .label {{ font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }}
.info-card .value {{ font-size: 1rem; color: var(--text); }}
table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
th {{ background: var(--surface); text-align: left; padding: 10px; border: 1px solid var(--border); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; }}
td {{ padding: 8px 10px; border: 1px solid var(--border); font-size: 0.88rem; vertical-align: top; }}
.mono {{ font-family: "SF Mono", Consolas, monospace; font-size: 0.85rem; }}
.suspicious {{ border-left: 3px solid var(--critical); }}
footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); color: #8b949e; font-size: 0.8rem; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
.badge-offline {{ background: #1a3d2e; color: var(--low); }}
</style>
</head>
<body>
<div class="container">
<header>
<h1>Arcana Forensics - Linux Triage Report</h1>
<p class="meta">Generated: {ts}<br>
Case: {data.get('case_id', 'N/A')} | Investigator: {data.get('investigator', 'N/A')}<br>
Mode: 100% Offline <span class="badge badge-offline">No Telemetry</span></p>
</header>
<div class="findings-banner {banner_class}">{banner_text}</div>
<section>
<h2>System Information</h2>
<div class="info-grid">
<div class="info-card"><div class="label">Hostname</div><div class="value">{sys_info.get('hostname', 'N/A')}</div></div>
<div class="info-card"><div class="label">OS</div><div class="value">{sys_info.get('os', 'N/A')}</div></div>
<div class="info-card"><div class="label">Kernel</div><div class="value">{sys_info.get('kernel', 'N/A')}</div></div>
<div class="info-card"><div class="label">Uptime</div><div class="value">{sys_info.get('boot_time', 'N/A')}</div></div>
<div class="info-card"><div class="label">User</div><div class="value">{sys_info.get('current_user', 'N/A')}</div></div>
<div class="info-card"><div class="label">Arch</div><div class="value">{sys_info.get('architecture', 'N/A')}</div></div>
</div>
</section>
"""

    if suspicious_procs:
        html += '<section><h2>Suspicious Processes</h2><table><tr><th>PID</th><th>Command</th><th>Reason</th></tr>'
        for proc in suspicious_procs:
            html += f'<tr class="suspicious"><td class="mono">{proc["pid"]}</td><td class="mono">{proc["process"]}</td><td>{proc["reason"]}</td></tr>'
        html += '</table></section>'

    if suspicious_ports:
        html += '<section><h2>Suspicious Network Ports</h2><table><tr><th>Port</th><th>Address</th><th>Reason</th></tr>'
        for port in suspicious_ports:
            html += f'<tr class="suspicious"><td class="mono">{port["port"]}</td><td class="mono">{port["address"]}</td><td>{port["reason"]}</td></tr>'
        html += '</table></section>'

    if anomalous_logins:
        html += '<section><h2>Anomalous Login Activity</h2><table><tr><th>IP Address</th><th>Failed Attempts</th><th>Reason</th></tr>'
        for login in anomalous_logins:
            html += f'<tr class="suspicious"><td class="mono">{login["ip"]}</td><td>{login["attempts"]}</td><td>{login["reason"]}</td></tr>'
        html += '</table></section>'

    html += f'<section><h2>Top Processes (by CPU)</h2><table><tr><th>PID</th><th>User</th><th>CPU%</th><th>MEM%</th><th>Command</th></tr>'
    for proc in data["processes"][:10]:
        html += f'<tr><td class="mono">{proc["pid"]}</td><td>{proc["user"]}</td><td>{proc["cpu"]}</td><td>{proc["mem"]}</td><td class="mono">{proc["command"][:80]}</td></tr>'
    html += '</table></section>'

    html += '<section><h2>Network Connections</h2><table><tr><th>Protocol</th><th>Local</th><th>Peer</th><th>Process</th></tr>'
    for conn in data["network_connections"]:
        html += f'<tr><td>{conn["protocol"]}</td><td class="mono">{conn["local_address"]}</td><td class="mono">{conn["peer_address"]}</td><td class="mono">{conn["process"]}</td></tr>'
    html += '</table></section>'

    html += '<section><h2>User Accounts with Login Shells</h2><table><tr><th>Username</th><th>UID</th><th>Shell</th><th>Home</th></tr>'
    for user in data["user_accounts"]:
        if user["has_login_shell"]:
            html += f'<tr><td class="mono">{user["username"]}</td><td>{user["uid"]}</td><td class="mono">{user["shell"]}</td><td class="mono">{user["home"]}</td></tr>'
    html += '</table></section>'

    html += '<section><h2>Cron Jobs</h2><table><tr><th>Source</th><th>Entry</th></tr>'
    for job in data["cron_jobs"]:
        html += f'<tr><td class="mono">{job["source"]}</td><td class="mono">{job["entry"]}</td></tr>'
    html += '</table></section>'

    html += '<section><h2>SUID Files</h2><table><tr><th>Path</th></tr>'
    for f in data["suid_files"]:
        html += f'<tr><td class="mono">{f}</td></tr>'
    html += '</table></section>'

    if data["recent_modified"]:
        html += '<section><h2>Recently Modified System Files (last 24h)</h2><table><tr><th>Path</th><th>Modified</th></tr>'
        for f in data["recent_modified"]:
            html += f'<tr><td class="mono">{f["path"]}</td><td>{f["modified"]}</td></tr>'
        html += '</table></section>'

    html += f"""<section><h2>System Resources</h2>
<div class="info-grid">
<div class="info-card"><div class="label">Memory Total</div><div class="value">{data["memory_info"].get("MemTotal", "N/A")} kB</div></div>
<div class="info-card"><div class="label">Memory Free</div><div class="value">{data["memory_info"].get("MemFree", "N/A")} kB</div></div>
<div class="info-card"><div class="label">Memory Available</div><div class="value">{data["memory_info"].get("MemAvailable", "N/A")} kB</div></div>
</div>
<table><tr><th>Filesystem</th><th>Size</th><th>Used</th><th>Available</th><th>Use%</th><th>Mount</th></tr>
"""
    for d in data["disk_usage"]:
        html += f'<tr><td class="mono">{d["filesystem"]}</td><td>{d["size"]}</td><td>{d["used"]}</td><td>{d["available"]}</td><td>{d["use_percent"]}</td><td class="mono">{d["mount"]}</td></tr>'
    html += '</table></section>'

    html += f"""<footer>
<p>Arcana Forensics Linux Triage Helper v1.0.0<br>
Report generated offline. No data transmitted.<br>
Chain of custody hash: {custody_hash[:32]}...<br>
Full custody log: custody.jsonl</p>
</footer>
</div>
</body>
</html>"""

    os.makedirs(output_path, exist_ok=True)
    report_file = os.path.join(output_path, "triage_report.html")
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html)
    return report_file

def main():
    parser = argparse.ArgumentParser(description="Arcana Forensics - Linux Triage Helper")
    parser.add_argument("--output", default="./triage_report", help="Output directory")
    parser.add_argument("--case-id", default="ARCF-TRIAGE", help="Case identifier")
    parser.add_argument("--investigator", default=os.getenv("USER", "unknown"), help="Investigator name")
    args = parser.parse_args()

    print(f"[*] Arcana Forensics Linux Triage Helper v1.0.0")
    print(f"[*] Case: {args.case_id}")
    print(f"[*] Investigator: {args.investigator}")
    print(f"[*] Mode: 100% Offline")
    print()

    custody = ChainOfCustody(args.case_id, args.investigator)
    custody.add_entry("TRIAGE_STARTED", {
        "output_dir": os.path.abspath(args.output),
        "tool_version": "1.0.0",
    })

    print("[*] Collecting system information...")
    sys_info = collect_system_info()
    custody.add_entry("SYSTEM_INFO_COLLECTED", {"hostname": sys_info["hostname"]})

    print("[*] Scanning processes...")
    processes = collect_processes()
    custody.add_entry("PROCESSES_COLLECTED", {"count": len(processes)})

    print("[*] Scanning network connections...")
    connections = collect_network_connections()
    ports = collect_listening_ports()
    custody.add_entry("NETWORK_COLLECTED", {"connections": len(connections), "ports": len(ports)})

    print("[*] Checking failed logins...")
    failed = collect_failed_logins()
    custody.add_entry("FAILED_LOGINS_COLLECTED", {"unique_ips": len(failed)})

    print("[*] Scanning cron jobs...")
    cron = collect_cron_jobs()
    custody.add_entry("CRON_COLLECTED", {"count": len(cron)})

    print("[*] Finding SUID binaries...")
    suid = collect_suid_files()
    custody.add_entry("SUID_COLLECTED", {"count": len(suid)})

    print("[*] Checking recently modified files...")
    modified = collect_recent_modified()
    custody.add_entry("MODIFIED_FILES_COLLECTED", {"count": len(modified)})

    print("[*] Collecting user accounts...")
    users = collect_user_accounts()
    custody.add_entry("USERS_COLLECTED", {"count": len(users)})

    print("[*] Collecting resource info...")
    disk = collect_disk_usage()
    mem = collect_memory_info()
    modules = collect_kernel_modules()
    custody.add_entry("RESOURCES_COLLECTED", {"disk_partitions": len(disk)})

    print("[*] Running suspicious activity detection...")
    suspicious_procs = detect_suspicious_processes(processes)
    suspicious_ports = detect_suspicious_ports(ports)
    anomalous_logins = detect_anomalous_logins(failed)
    custody.add_entry("SUSPICIOUS_DETECTION", {
        "suspicious_processes": len(suspicious_procs),
        "suspicious_ports": len(suspicious_ports),
        "anomalous_logins": len(anomalous_logins),
    })

    data = {
        "system_info": sys_info,
        "processes": processes,
        "network_connections": connections,
        "listening_ports": ports,
        "failed_logins": failed,
        "cron_jobs": cron,
        "suid_files": suid,
        "recent_modified": modified,
        "user_accounts": users,
        "disk_usage": disk,
        "memory_info": mem,
        "kernel_modules": modules,
        "suspicious_processes": suspicious_procs,
        "suspicious_ports": suspicious_ports,
        "anomalous_logins": anomalous_logins,
        "case_id": args.case_id,
        "investigator": args.investigator,
    }

    print("[*] Generating report...")
    report_file = generate_triage_report(data, custody.previous_hash, args.output)
    print(f"[+] HTML report: {report_file}")

    json_file = os.path.join(args.output, "triage_data.json")
    secure_write(json_file, json.dumps(data, indent=2, default=str))
    print(f"[+] JSON data: {json_file}")

    custody_file = os.path.join(args.output, "custody.jsonl")
    custody.export_jsonl(custody_file)
    print(f"[+] Chain of custody: {custody_file}")

    if custody.verify_chain():
        print("[+] Chain of custody verified: OK")
    else:
        print("[!] Chain of custody verification FAILED")

    total_findings = len(suspicious_procs) + len(suspicious_ports) + len(anomalous_logins)
    print(f"\n{'='*50}")
    print(f"TRIAGE COMPLETE")
    print(f"{'='*50}")
    print(f"Suspicious processes: {len(suspicious_procs)}")
    print(f"Suspicious ports: {len(suspicious_ports)}")
    print(f"Anomalous login IPs: {len(anomalous_logins)}")
    print(f"Total findings: {total_findings}")
    print(f"Reports saved to: {args.output}")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
