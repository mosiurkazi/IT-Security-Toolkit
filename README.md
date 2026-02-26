# IT Security Toolkit

A **resume-ready** project you can run on Windows or Linux to demonstrate:
- Help Desk troubleshooting workflow
- Security-minded incident triage
- Evidence collection & reporting
- Basic IOC (Indicator of Compromise) checking (offline)

 **What you can claim (truthfully) after running this in your lab:**  
- Built a Python-based triage tool that collects endpoint diagnostics (processes, network connections, DNS config, event snippets where available) and produces a timestamped report for escalation.  
- Implemented offline IOC checks (file hashes & suspicious indicators) and documented a repeatable incident-response workflow suitable for IT Technician / Help Desk escalation.

---

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

---

## Suggested screenshots for your GitHub README
Add screenshots to `docs/screenshots/`:
1. Running `triage.py` and generating reports
2. Example report file opened (JSON or TXT)
3. Running `ioc_check.py` with a test file hash

---

## Resume bullets (copy/paste)
- Built a cross-platform Python **IT security triage toolkit** to collect endpoint diagnostics (host, processes, network, DNS) and generate timestamped reports for escalation workflows.
- Created an offline **IOC checking utility** (hash comparison + indicator scanning) and documented a structured help desk incident triage runbook and ticket template.

---

## Disclaimer
Use this toolkit only on systems you own or have permission to assess.
