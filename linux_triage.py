# Arcana-Forensics

[![Live Site](https://img.shields.io/badge/Live-arcana--forensics.com-FFB020)](https://arcana-forensics.com) [![License](https://img.shields.io/badge/license-Commercial%20License-blue.svg)](https://arcana-forensics.com/terms.html) [![Release](https://img.shields.io/github/v/release/mitchell5584dm-tech/arcana-forensics-site?color=22C55E)](https://arcana-forensics.com/success.html)

**Arcana-Forensics — offline-first, defensible digital forensics and data protection for individuals, families, and companies safeguarding sensitive information.**

The same investigative capabilities as the large forensic suites — artifact parsing, password auditing, chain-of-custody reporting — with one fundamental difference: **your data never leaves your machine.** No cloud. No telemetry. No vendor lock-in.

Live site: **https://arcana-forensics.com**

---

## What is this?

**Free tools stay free. Pro keeps the lights on.**

**1. Linux Triage Helper — FREE FOREVER**
Quick, safe check when Linux feels off. For home users, students, small shops.
- Collects processes & logs, creates an evidence-grade report
- Offline, read-only — nothing is uploaded or shared

**2. Credential Auditor Pro — Lifetime License (14-day full trial)**
Find weak, reused, and breached passwords before attackers do.
- Up to 500 users, offline, one-click owner report
- Chain-of-custody JSONL with SHA-256 verification
- Prioritizes what to fix first
- Current pricing: **https://arcana-forensics.com**

## Also in the ecosystem

- **Security-Operations-Forensics-Toolkit** — the production toolkit (Triage + Crucible Pro)
- **forensics-orchestrator** — API-driven DFIR pipeline with Docker-reproducible workflows
- **LinuxForensics** — browser history forensics with HTML dashboards and JSON timelines

## Quick Start

Download from releases or run locally:

```bash
python3 credential_auditor.py --input creds.txt --output ./reports
```
