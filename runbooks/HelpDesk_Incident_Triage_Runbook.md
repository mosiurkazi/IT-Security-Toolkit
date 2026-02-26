# Help Desk Incident Triage Runbook (Security-Aware)

## Purpose
Provide a **repeatable** workflow for IT Help Desk / IT Technician staff to triage security-related tickets and collect evidence for escalation.

## When to use
- User reports popups, suspicious emails, unknown software installs
- Device unusually slow, CPU spikes, fan loud
- Suspicious login alerts / MFA prompts
- Network issues that may be security-related (DNS hijack, proxy changes)

---

## 1) Confirm scope and impact (2 minutes)
- Who is affected? One user or many?
- When did it start?
- Is business interrupted?
- Any sensitive data involved?

## 2) Immediate containment (if needed)
- If malware suspected: disconnect device from network (Wi‑Fi off / unplug)
- If account compromise suspected: reset password + force sign-out, revoke sessions (if M365/Entra)
- Preserve evidence: avoid “cleaning” before collecting basics

## 3) Collect evidence (10 minutes)
Run:
- `triage_toolkit/triage.py --outdir reports`
Collect:
- Report files from `reports/`
- Any suspicious file path(s)
- Screenshots of alerts/messages
- Email headers (if phishing)

## 4) Quick checks (offline, safe)
- If you have a suspicious file, compute hash and compare to IOC list:
  - `ioc_check.py --ioc-file samples/ioc_list.txt --hash-file <file>`

## 5) Decide: resolve vs escalate
### Resolve at Help Desk
- Clear browser cache, remove PUP extensions (if confirmed benign)
- Update OS/apps, run AV scan (per org policy)

### Escalate to IT/Sec
Escalate if:
- IOC match
- Evidence of persistence (unknown startup items)
- Lateral movement suspected (multiple machines)
- Credential compromise indicators
- Unusual admin tool usage

## 6) Document everything
Use `templates/Security_Ticket_Template.md` and attach:
- Triage report(s)
- Hash values
- Screenshots
- Timeline of actions taken
