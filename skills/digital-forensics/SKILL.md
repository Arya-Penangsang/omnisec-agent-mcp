---
name: digital-forensics
description: >-
  Digital Forensics & Incident Response (DFIR) methodology based on NIST SP 800-86
  and ISO/IEC 27037 standards. Covers MACB timeline reconstruction, USBSTOR artifact auditing,
  and Windows Event Log forensics.
---

# 🔍 Digital Forensics & Incident Response (DFIR) Runbook

Standard operating procedures for forensic evidence acquisition, USB artifact auditing, and Windows Event Log triage following **NIST SP 800-86** and **ISO/IEC 27037** standards.

## 🛠️ Native MCP Tools

### 1. `forensics_audit_usb`
Queries the Windows Registry at `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` to audit all historical and active removable USB storage devices (flash drives, external SSDs/HDDs).

```json
{
  "name": "forensics_audit_usb",
  "arguments": {
    "include_all_usb": false
  }
}
```

**Parsed Artifacts:**
- Friendly device name (e.g., `SanDisk Ultra USB Device`, `SSD 3.0 USB Device`)
- Device instance ID / serial number
- Vendor, Product, and Revision identifiers
- Unique Container GUID

**Caveman Mode Output:**
- **Ultra:** `USBSTOR: 1 devices | SSD 3.0 USB Device (SN: 6339961022475678872&0)`
- **Full:** Enumerated list with vendor/product breakdown and Container ID.

---

### 2. `forensics_triage_logs`
Automated extraction and forensic triage of Windows Event Logs (`Security`, `System`, `Application`) via native `wevtutil`.

```json
{
  "name": "forensics_triage_logs",
  "arguments": {
    "category": "logon",
    "count": 5
  }
}
```

**Investigation Categories:**
- `logon`: Authentication analysis (`EventID 4624` successful, `4625` failed logons).
- `service`: Persistence detection (`EventID 7045` new service installed, `7040` start type modified).
- `audit_tamper`: Anti-forensics / evasion detection (`EventID 1102` audit log cleared).
- `system` / `security` / `application`: General recent event audit.
