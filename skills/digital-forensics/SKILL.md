---
name: digital-forensics
description: >-
  Digital Forensics & Incident Response (DFIR) methodology based on NIST SP 800-86
  and ISO/IEC 27037 standards. Covers MACB timeline reconstruction, USBSTOR artifact auditing,
  and Windows Event Log forensics.
---

# 🔍 Digital Forensics & Incident Response (DFIR) Runbook

Standard operating procedures for forensic evidence acquisition and analysis following **NIST SP 800-86** guidelines.

## Primary Investigation Domains
1. **USB Artifact Audit:** Inspect `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` to reconstruct flash drive connections, serial numbers, and first/last install timestamps.
2. **Timeline MACB:** Extract Modified, Accessed, Created, and Born timestamps to detect timestomping.
3. **Event Log Triage:**
   - `4624` / `4625`: Successful / Failed logon events.
   - `4688`: New process creation (Command-line auditing).
   - `7045`: New service installation (Persistence).
   - `1102`: Audit log cleared (Defense evasion).
