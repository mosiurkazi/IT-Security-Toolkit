# IT Security Toolkit

This project demonstrates:
- Help Desk troubleshooting workflow
- Security-minded incident triage
- Evidence collection & reporting
- Basic IOC (Indicator of Compromise) checking (offline)
  
## Contents
- `triage_toolkit/triage.py` — Collects system + network diagnostics and writes a JSON + text report
- `triage_toolkit/ioc_check.py` — Offline IOC checker (hash compare + simple regex indicators)
- `runbooks/HelpDesk_Incident_Triage_Runbook.md` — Step-by-step triage process
- `templates/Security_Ticket_Template.md` — Ticket template for escalations
- `samples/ioc_list.txt` — Example IOC hashes you can replace with your own
- `requirements.txt` — Python dependencies (minimal)

---

## Quick Start

### 1) Install Python dependencies
```bash
pip3 install -r requirements.txt
```

### 2) Run triage (creates `reports/`)
```bash
python3 triage_toolkit/triage.py --outdir reports
```

Optional: include a specific file to hash & check:
```bash
python3 triage_toolkit/triage.py --outdir reports --hash-file /path/to/suspicious_file.exe
```

### 3) Run IOC check (offline)
```bash
python3 triage_toolkit/ioc_check.py --ioc-file samples/ioc_list.txt --hash-file /path/to/suspicious_file.exe
```

---

## What the triage report contains
- Host info (OS, hostname, user)
- Uptime (where available)
- IP addresses, default gateway (best-effort)
- DNS resolver configuration (best-effort)
- Recent network connections (best-effort)
- Top processes snapshot (name, PID, CPU/mem if available)
- Security notes (common red flags checklist)

> This is intentionally **safe** and does not exploit anything. It’s designed for help desk evidence collection and escalation.

## Disclaimer
Use this toolkit only on systems you own or have permission to assess.
