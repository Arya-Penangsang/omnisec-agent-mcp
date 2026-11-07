---
name: purple-team
description: >-
  Web Purple Teaming & Triad Security Assessment Runbook.
  Integrates Red Team attack emulation (T1595, T1190, T1110, T1083)
  with Blue Team defensive verification (WAF, CSP, HSTS, Cookie security)
  based on MITRE ATT&CK for Web Applications and NIST CSF.
---

# 🟣 Web Purple Teaming & Triad Validation Runbook

Runbook for continuous security validation that combines ethical offensive simulations (**Red Team**) with defensive posture hardening (**Blue Team**) mapped to the **MITRE ATT&CK for Web Applications** matrix.

---

## 🎯 MITRE ATT&CK Web Matrix

| MITRE Tactic | Technique ID | Technique Name | Red Team Probe | Blue Team Verification | Target Status |
| :--- | :---: | :--- | :--- | :--- | :---: |
| **Reconnaissance** | `T1595` | Active Scanning | Sensitive Dotfiles (`/.env`, `/.git`) | Access blocked (HTTP 403/404) | **DEFENDED** |
| **Initial Access** | `T1190` | Exploit Public App | SQLi (`' OR 1=1--`) & XSS Probe | Input sanitized & WAF reset | **DEFENDED** |
| **Credential Access** | `T1110` | Brute Force | Burst login POST attempts | Rate limiting (HTTP 429) | **BLOCKED** |
| **Persistence** | `T1505.003`| Web Shell Drop | Upload script execution | Script engine disabled in uploads | **DEFENDED** |
| **Discovery** | `T1083` | File Discovery | Database dump (`/backup.sql`) | Download forbidden or TCP Reset | **DEFENDED** |

---

## ⚡ Execution via MCP

Use the native MCP tool `purple_audit_triad` or `purple_emulate_threat`:
```json
{
  "name": "purple_audit_triad",
  "arguments": {
    "target_url": "http://target-host:port"
  }
}
```
Outputs return dense, token-saving results that can be toggled via `set_cave_mode`.
