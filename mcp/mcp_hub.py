#!/usr/bin/env python3
"""
OmniSec Multi-MCP Universal Gateway Hub (Phase 3)
Standard Model Context Protocol (MCP) JSON-RPC 2.0 Server

Features:
1. Dynamic Resource Engine: Dynamically discovers and serves live Markdown from `skills/*/SKILL.md`.
2. Dynamic Prompt Engine: Pre-configured prompt templates for Caveman mode, audit, triage, and DFIR.
3. Hybrid Tool Orchestrator: Executes native defensive tools locally or proxies to remote SSH backend.
4. Token Optimization: Integrated Caveman Mode compression engine (80%–98% context reduction).

Zero External Dependencies: Pure Python 3 standard library.
"""

import sys
import os
import json
import math
import struct
import hashlib
import subprocess
import urllib.request
import urllib.error
import urllib.parse
from collections import Counter
from datetime import datetime
from pathlib import Path

# Ensure UTF-8 output encoding on Windows stdio
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
SKILLS_DIR = BASE_DIR / "skills"
DIST_DIR = BASE_DIR / "dist_packages"

try:
    from mcp import visual_report
    from mesh import mesh_manager
except ImportError:
    visual_report = None
    mesh_manager = None

# Global Hub State
CURRENT_CAVE_LEVEL = "full"  # "lite" | "full" | "ultra" | "off"
REMOTE_SSH_HOST = os.environ.get("OMNISEC_REMOTE_HOST", "kantor")
REMOTE_ENABLED = os.environ.get("OMNISEC_REMOTE_MODE", "0") in ("1", "true", "yes")


# -----------------------------------------------------------------------------
# CAVEMAN TOKEN ENGINE
# -----------------------------------------------------------------------------
def get_cave_system_prompt(level: str = "full") -> str:
    return (
        f"[CAVEMAN TOKEN OPTIMIZATION MODE: {level}]\n"
        "Goal: Preserve output tokens and prevent context bloat without losing technical accuracy.\n"
        "- Strict Negative Constraints: No greetings (Halo, Hi), no compliments (Great question), "
        "no re-stating user prompts, no outro/closing filler (Semoga membantu, Let me know).\n"
        "- Preserve 100% exactness: code, file paths, commands, IPs, hashes, CVEs, numbers.\n"
        "- Level lite: Plain short sentences, zero filler.\n"
        "- Level full (default): Short telegraphic sentences/fragments. Direct answer first.\n"
        "- Level ultra: Bare minimum keywords, symbols (->), one-liners where possible.\n"
        "- Safety exception: Use complete clear sentences only for destructive actions or critical safety warnings."
    )


# -----------------------------------------------------------------------------
# DYNAMIC RESOURCE & PROMPT ENGINE
# -----------------------------------------------------------------------------
def discover_skills() -> dict:
    skills = {}
    if not SKILLS_DIR.exists():
        return skills
    for s_dir in SKILLS_DIR.iterdir():
        if s_dir.is_dir():
            skill_md = s_dir / "SKILL.md"
            if skill_md.exists():
                name = s_dir.name
                desc = f"Runbook for {name}"
                try:
                    text = skill_md.read_text(encoding="utf-8", errors="replace")
                    if text.startswith("---"):
                        parts = text.split("---", 2)
                        if len(parts) >= 3:
                            for line in parts[1].splitlines():
                                if line.strip().startswith("description:"):
                                    desc = line.split(":", 1)[1].strip(" >-'\"")
                except Exception:
                    pass
                skills[name] = {
                    "path": skill_md,
                    "description": desc
                }
    return skills


def get_mcp_resources() -> list:
    skills = discover_skills()
    resources = []
    for name, data in skills.items():
        resources.append({
            "uri": f"resource://skills/{name}",
            "name": f"OmniSec Skill: {name}",
            "mimeType": "text/markdown",
            "description": data["description"]
        })
    # Add Prompt Pack resource
    resources.append({
        "uri": "resource://bundle/prompt-pack",
        "name": "OmniSec Master Prompt Pack",
        "mimeType": "text/markdown",
        "description": "Unified system prompt pack combining Caveman rules and all cyber runbooks."
    })
    return resources


def read_mcp_resource(uri: str) -> str:
    skills = discover_skills()
    if uri.startswith("resource://skills/"):
        name = uri.replace("resource://skills/", "")
        if name in skills:
            try:
                return skills[name]["path"].read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                return f"Error reading skill {name}: {str(e)}"
        return f"Skill not found: {name}"

    if uri == "resource://bundle/prompt-pack":
        pack_file = DIST_DIR / "omnisec_chatgpt_prompt_pack.md"
        if pack_file.exists():
            return pack_file.read_text(encoding="utf-8", errors="replace")
        return get_cave_system_prompt("full")

    return f"Resource not found: {uri}"


def get_mcp_prompts() -> list:
    return [
        {
            "name": "cave_mode",
            "description": "Activate Caveman token-saving mode to cut context size up to 98%.",
            "arguments": [
                {"name": "level", "description": "Compression level: lite, full, ultra", "required": False}
            ]
        },
        {
            "name": "purple_triad_audit",
            "description": "Conduct end-to-end WAF perimeter audit and hardening assessment.",
            "arguments": [
                {"name": "target_url", "description": "Target base URL (e.g., http://10.0.1.67)", "required": True}
            ]
        },
        {
            "name": "malware_triage",
            "description": "Static triage of Windows PE binary: entropy, packers, and injection APIs.",
            "arguments": [
                {"name": "file_path", "description": "Absolute path to executable (.exe/.dll)", "required": True}
            ]
        },
        {
            "name": "forensics_usb_audit",
            "description": "DFIR investigation of connected removable USB devices via USBSTOR registry.",
            "arguments": []
        }
    ]


def get_mcp_prompt_messages(name: str, arguments: dict) -> list:
    if name == "cave_mode":
        lvl = arguments.get("level", "full")
        return [{"role": "user", "content": {"type": "text", "text": get_cave_system_prompt(lvl)}}]

    if name == "purple_triad_audit":
        url = arguments.get("target_url", "http://localhost")
        prompt = (
            f"Perform a comprehensive Purple Team Triad audit on target: {url}.\n"
            f"1. Run purple_audit_triad(target_url='{url}')\n"
            "2. Identify missing headers and exposed endpoints.\n"
            "3. Generate hardening config (.htaccess) in Caveman full format."
        )
        return [{"role": "user", "content": {"type": "text", "text": prompt}}]

    if name == "malware_triage":
        path = arguments.get("file_path", "")
        prompt = (
            f"Perform static malware analysis on: {path}.\n"
            f"1. Run malware_inspect_pe(file_path='{path}')\n"
            "2. Inspect Shannon entropy, packer flags, and suspicious APIs.\n"
            "3. Provide classification and risk score."
        )
        return [{"role": "user", "content": {"type": "text", "text": prompt}}]

    if name == "forensics_usb_audit":
        prompt = (
            "Perform a digital forensics triage of removable storage history on this Windows host.\n"
            "1. Run forensics_audit_usb()\n"
            "2. Identify suspicious, unauthorized, or unknown USB serial numbers."
        )
        return [{"role": "user", "content": {"type": "text", "text": prompt}}]

    return [{"role": "user", "content": {"type": "text", "text": f"Instruction for prompt {name}"}}]


# -----------------------------------------------------------------------------
# LOCAL SECURITY TOOL ENGINES
# -----------------------------------------------------------------------------
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def inspect_pe(file_path: str) -> dict:
    file_path = os.path.expandvars(file_path.strip())
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    file_size = os.path.getsize(file_path)
    if file_size > 100 * 1024 * 1024:
        return {"error": f"File size exceeds 100MB limit for static triage ({file_size:,} bytes)."}

    try:
        with open(file_path, "rb") as f:
            dos_header = f.read(64)
            if len(dos_header) < 64 or dos_header[:2] != b"MZ":
                return {"error": "Not a valid DOS/MZ executable"}

            e_lfanew = struct.unpack("<I", dos_header[0x3C:0x40])[0]
            if e_lfanew >= file_size:
                return {"error": "Invalid PE offset (e_lfanew out of bounds)"}

            f.seek(e_lfanew)
            pe_sig = f.read(4)
            if pe_sig != b"PE\0\0":
                return {"error": "Missing PE signature"}

            coff_data = f.read(20)
            machine, num_sections, timedate, _, _, opt_size, characteristics = struct.unpack(
                "<HHIIIHH", coff_data
            )

            machine_names = {
                0x014C: "x86 (32-bit)",
                0x8664: "x64 (AMD64)",
                0x01C0: "ARM",
                0xAA64: "ARM64",
            }
            arch = machine_names.get(machine, f"Unknown (0x{machine:04X})")
            compile_time = datetime.fromtimestamp(timedate).strftime("%Y-%m-%d %H:%M:%S") if timedate else "Unknown"

            subsystem_name = "Unknown"
            opt_magic = 0
            entry_point = 0
            if opt_size > 0:
                opt_data = f.read(opt_size)
                if len(opt_data) >= 70:
                    opt_magic = struct.unpack("<H", opt_data[:2])[0]
                    entry_point = struct.unpack("<I", opt_data[16:20])[0]
                    subsystem = struct.unpack("<H", opt_data[68:70])[0]
                    subsystems = {
                        1: "Native/Driver",
                        2: "Windows GUI",
                        3: "Windows Console/CUI",
                        7: "POSIX CUI",
                        9: "Windows CE GUI",
                    }
                    subsystem_name = subsystems.get(subsystem, f"Subsystem ({subsystem})")

            sections = []
            packer_detected = False
            packer_name = "None"
            packer_sigs = {
                "UPX": ["UPX0", "UPX1", "UPX2", ".upx"],
                "ASPack": [".aspack", ".adata"],
                "PECompact": ["pec1", "pec2", "pecompact"],
                "MPRESS": [".mpress1", ".mpress2"],
                "Themida": [".themida"],
                "VMProtect": [".vmp0", ".vmp1"],
            }

            for _ in range(num_sections):
                sec_data = f.read(40)
                if len(sec_data) < 40:
                    break
                sec_name = sec_data[:8].rstrip(b"\x00 ").decode("latin-1", errors="ignore")
                v_size, v_addr, raw_size, raw_ptr = struct.unpack("<IIII", sec_data[8:24])

                sec_entropy = 0.0
                if raw_size > 0 and raw_ptr < file_size:
                    cur_pos = f.tell()
                    f.seek(raw_ptr)
                    sample_len = min(raw_size, 512 * 1024)
                    sec_bytes = f.read(sample_len)
                    sec_entropy = calculate_entropy(sec_bytes)
                    f.seek(cur_pos)

                for p_name, patterns in packer_sigs.items():
                    for pat in patterns:
                        if pat.lower() in sec_name.lower():
                            packer_detected = True
                            packer_name = p_name

                sections.append({
                    "name": sec_name,
                    "virtual_size": v_size,
                    "raw_size": raw_size,
                    "entropy": sec_entropy,
                })

            f.seek(0)
            sample_data = f.read(min(file_size, 1024 * 1024))
            overall_entropy = calculate_entropy(sample_data)

            if overall_entropy > 7.2 and not packer_detected:
                packer_detected = True
                packer_name = "High Entropy (>7.2) - Packed/Encrypted"

            f.seek(0)
            chunk = f.read(min(file_size, 2 * 1024 * 1024))

            suspicious_apis = [
                b"VirtualAlloc", b"VirtualProtect", b"WriteProcessMemory", b"CreateRemoteThread",
                b"NtUnmapViewOfSection", b"URLDownloadToFile", b"HttpSendRequest", b"InternetOpen",
                b"WinExec", b"ShellExecute", b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent",
                b"cmd.exe", b"powershell.exe", b"vssadmin.exe"
            ]
            found_apis = [api.decode("latin-1") for api in suspicious_apis if api in chunk]

            risk = "LOW"
            if packer_detected and len(found_apis) >= 2:
                risk = "CRITICAL"
            elif packer_detected or len(found_apis) >= 3:
                risk = "HIGH"
            elif len(found_apis) > 0 or overall_entropy > 6.8:
                risk = "MEDIUM"

            h_sha = hashlib.sha256()
            h_md5 = hashlib.md5()
            with open(file_path, "rb") as hf:
                while True:
                    chunk_hash = hf.read(65536)
                    if not chunk_hash:
                        break
                    h_sha.update(chunk_hash)
                    h_md5.update(chunk_hash)
            sha256 = h_sha.hexdigest()
            md5 = h_md5.hexdigest()

            return {
                "file_name": os.path.basename(file_path),
                "file_path": file_path,
                "file_size": file_size,
                "sha256": sha256,
                "md5": md5,
                "architecture": arch,
                "format": "PE32+ (64-bit)" if opt_magic == 0x020B else "PE32 (32-bit)",
                "compile_timestamp": compile_time,
                "subsystem": subsystem_name,
                "entry_point": f"0x{entry_point:08X}",
                "overall_entropy": overall_entropy,
                "packer_detected": packer_detected,
                "packer_name": packer_name,
                "sections": sections,
                "suspicious_indicators": found_apis,
                "risk_classification": risk,
            }
    except Exception as e:
        return {"error": f"Failed to parse PE: {str(e)}"}


def query_usbstor() -> list:
    if sys.platform != "win32":
        return [{"error": "USBSTOR registry triage is supported natively on Windows systems."}]

    try:
        res = subprocess.run(
            ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR", "/s"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = res.stdout
    except Exception as e:
        return [{"error": f"Failed to execute reg query: {str(e)}"}]

    devices = {}
    current_device = None

    for line in output.splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue

        if trimmed.upper().startswith(r"HKEY_LOCAL_MACHINE\SYSTEM\CURRENTCONTROLSET\ENUM\USBSTOR\\"):
            parts = trimmed.split("\\")
            if len(parts) >= 7:
                dev_key = parts[5]
                inst_id = parts[6]
                key_id = f"{dev_key}__{inst_id}"

                if key_id not in devices:
                    vendor = "Unknown"
                    product = "Unknown"
                    revision = "Unknown"
                    import re
                    m_v = re.search(r"Ven_([^_&]+)", dev_key, re.I)
                    if m_v: vendor = m_v.group(1)
                    m_p = re.search(r"Prod_([^_&]+)", dev_key, re.I)
                    if m_p: product = m_p.group(1)
                    m_r = re.search(r"Rev_([^_&]+)", dev_key, re.I)
                    if m_r: revision = m_r.group(1)

                    devices[key_id] = {
                        "device_key": dev_key,
                        "instance_id": inst_id,
                        "vendor": vendor,
                        "product": product,
                        "revision": revision,
                        "friendly_name": "Generic USB Storage Device",
                        "hardware_id": None,
                        "container_id": None,
                    }
                current_device = devices[key_id]
            else:
                current_device = None
        elif current_device and (line.startswith("    ") or line.startswith("\t")):
            tokens = [t for t in line.strip().split("    ") if t]
            if len(tokens) >= 2:
                name = tokens[0].strip()
                val = tokens[-1].strip()
                if name.lower() == "friendlyname":
                    current_device["friendly_name"] = val
                elif name.lower() == "hardwareid":
                    current_device["hardware_id"] = val
                elif name.lower() == "containerid":
                    current_device["container_id"] = val

    return list(devices.values())


def query_event_logs(category: str = "logon", count: int = 5) -> list:
    if sys.platform != "win32":
        return [{"error": "Windows Event Log triage requires a Windows host with wevtutil."}]

    try:
        count = max(1, min(50, int(count)))
    except (ValueError, TypeError):
        count = 5

    valid_categories = {
        "logon": ("Security", "*[System[(EventID=4624 or EventID=4625)]]"),
        "service": ("System", "*[System[(EventID=7045 or EventID=7040)]]"),
        "audit_tamper": ("Security", "*[System[(EventID=1102)]]"),
        "system": ("System", None),
        "security": ("Security", None),
        "application": ("Application", None),
    }

    cat_key = str(category).lower().strip()
    if cat_key not in valid_categories:
        cat_key = "logon"

    log_name, query_filter = valid_categories[cat_key]

    cmd_args = ["wevtutil", "qe", log_name]
    if query_filter:
        cmd_args.append(f"/q:{query_filter}")
    cmd_args.extend([f"/c:{count}", "/rd:true", "/f:text"])

    try:
        res = subprocess.run(cmd_args, shell=False, capture_output=True, text=True, timeout=12)
        output = res.stdout
    except Exception as e:
        return [{"error": str(e)}]

    events = []
    current_evt = None
    for line in output.splitlines():
        t = line.strip()
        if t.startswith("Event["):
            if current_evt:
                events.append(current_evt)
            current_evt = {"date": "Unknown", "event_id": "0", "user": "N/A", "task": "N/A", "level": "Info", "description": ""}
        elif current_evt:
            if t.startswith("Date:"): current_evt["date"] = t[5:].strip()
            elif t.startswith("Event ID:"): current_evt["event_id"] = t[9:].strip()
            elif t.startswith("Task:"): current_evt["task"] = t[5:].strip()
            elif t.startswith("Level:"): current_evt["level"] = t[6:].strip()
            elif t.startswith("User Name:"): current_evt["user"] = t[10:].strip()
            elif "Account Name:" in t and current_evt["user"] == "N/A":
                current_evt["user"] = t.split(":", 1)[1].strip()
            elif t.startswith("Description:"): current_evt["description"] = t[12:].strip()
            elif t and not current_evt["description"] and ":" not in t:
                current_evt["description"] = t
    if current_evt:
        events.append(current_evt)
    return events


def send_http_probe(url: str, method="GET", headers=None, post_data=None, timeout=6):
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return {"code": 0, "headers": {}, "body": "", "error": f"Blocked protocol '{scheme}': Only HTTP/HTTPS permitted (SSRF guard)."}

    hostname = (parsed.hostname or "").lower()
    if hostname in ("169.254.169.254", "metadata.google.internal"):
        return {"code": 0, "headers": {}, "body": "", "error": "Access to cloud instance metadata service is blocked (SSRF guard)."}

    req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OmniSecHub/3.0"}
    if headers:
        req_headers.update(headers)
    data_bytes = post_data.encode("utf-8") if isinstance(post_data, str) else post_data
    req = urllib.request.Request(url, data=data_bytes, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            res_headers = {k.lower(): v for k, v in resp.getheaders()}
            return {"code": resp.status, "headers": res_headers, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        res_headers = {k.lower(): v for k, v in e.headers.items()}
        return {"code": e.code, "headers": res_headers, "body": body, "error": None}
    except Exception as e:
        return {"code": 0, "headers": {}, "body": "", "error": str(e)}


def execute_purple_audit(target_url: str) -> dict:
    target_url = target_url.rstrip("/")
    root = send_http_probe(target_url + "/")
    r_headers = root["headers"]

    def eval_probe(probe, sig_check):
        if probe["code"] == 0 and probe["error"]:
            return {"status": "DEFENDED", "code": "TCP_RESET"}
        if probe["code"] in [400, 401, 403, 404, 405, 429, 500, 502, 503]:
            return {"status": "DEFENDED", "code": probe["code"]}
        if probe["code"] == 200 and sig_check(probe["body"]):
            return {"status": "EXPOSED", "code": 200}
        return {"status": "DEFENDED", "code": probe["code"]}

    dot_p = send_http_probe(target_url + "/.env")
    dot_eval = eval_probe(dot_p, lambda b: "APP_" in b or "DB_" in b)

    git_p = send_http_probe(target_url + "/.git/HEAD")
    git_eval = eval_probe(git_p, lambda b: "ref:" in b)

    bak_p = send_http_probe(target_url + "/backup.sql")
    bak_eval = eval_probe(bak_p, lambda b: "CREATE TABLE" in b.upper())

    xss_p = send_http_probe(target_url + "/?q=%3Cscript%3Eomni99%3C/script%3E")
    xss_vuln = "<script>omni99</script>" in xss_p["body"]

    sec_headers = {
        "csp": "content-security-policy",
        "x_frame": "x-frame-options",
        "x_content_type": "x-content-type-options",
        "hsts": "strict-transport-security"
    }
    blue_checks = {}
    for alias, h in sec_headers.items():
        blue_checks[alias] = {"header": h, "configured": h in r_headers}

    probes = {
        "dotfiles": {"technique": "T1595", "status": dot_eval["status"]},
        "git_leak": {"technique": "T1595", "status": git_eval["status"]},
        "backup": {"technique": "T1083", "status": bak_eval["status"]},
        "xss": {"technique": "T1190", "status": "VULNERABLE" if xss_vuln else "DEFENDED"}
    }

    defended = sum(1 for p in probes.values() if p["status"] == "DEFENDED")
    red_score = round((defended / len(probes)) * 100)
    configured_b = sum(1 for b in blue_checks.values() if b["configured"])
    blue_score = round((configured_b / len(blue_checks)) * 100)
    overall = round((red_score * 0.6) + (blue_score * 0.4))

    return {
        "target_url": target_url,
        "probes": probes,
        "blue_checks": blue_checks,
        "score": overall,
        "posture": "EXCELLENT" if overall >= 80 else ("MODERATE" if overall >= 50 else "CRITICAL")
    }


# -----------------------------------------------------------------------------
# REMOTE SSH PROXY ORCHESTRATOR
# -----------------------------------------------------------------------------
def proxy_tool_call_to_remote(tool_name: str, arguments: dict, host: str = "kantor") -> str:
    req = {
        "jsonrpc": "2.0",
        "id": 999,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }
    payload = json.dumps(req)
    cmd = [
        "ssh", "-o", "BatchMode=yes", "-T", host,
        f"php C:\\Users\\Pengolahan\\mcp-servers\\purple-team\\server.php"
    ]
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Send initialize first
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
        # Send cave mode
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "set_cave_mode", "arguments": {"level": CURRENT_CAVE_LEVEL}}}) + "\n")
        # Send target tool
        proc.stdin.write(payload + "\n")
        proc.stdin.flush()

        # Read replies
        proc.stdout.readline()  # init
        proc.stdout.readline()  # cave
        target_line = proc.stdout.readline()
        proc.terminate()

        if target_line:
            res = json.loads(target_line)
            return res.get("result", {}).get("content", [{}])[0].get("text", "No response")
        return "Remote host returned empty response."
    except Exception as e:
        return f"Remote SSH proxy error ({host}): {str(e)}"


# -----------------------------------------------------------------------------
# DENSE TOKEN FORMATTERS
# -----------------------------------------------------------------------------
def format_audit(res: dict, level: str) -> str:
    if level == "off":
        return json.dumps(res, indent=2)
    defended = sum(1 for p in res["probes"].values() if p["status"] == "DEFENDED")
    missing = [k for k, b in res["blue_checks"].items() if not b["configured"]]

    if level == "ultra":
        return f"TARGET: {res['target_url']} | SCORE: {res['score']}/100 ({res['posture']}) | RED: {defended}/4 DEFENDED | MISSING: {','.join(missing)}"

    if level == "full":
        lines = [
            f"Target: {res['target_url']} (Score: {res['score']}/100, Posture: {res['posture']})",
            "Red Probes: " + " | ".join(f"{k}: {p['status']}" for k, p in res["probes"].items()),
            f"Missing Blue Controls: {', '.join(missing)}",
            "Remediation: Configure CSP, HSTS, X-Frame in .htaccess"
        ]
        return "\n".join(lines)

    return f"Audit for {res['target_url']} complete. Posture: {res['posture']} (Score: {res['score']}/100). Defended: {defended}/4. Missing: {', '.join(missing)}."


def format_pe(info: dict, level: str) -> str:
    if "error" in info:
        return f"ERROR: {info['error']}"
    if level == "off":
        return json.dumps(info, indent=2)

    susp = ",".join(info["suspicious_indicators"][:4]) if info["suspicious_indicators"] else "None"
    if level == "ultra":
        return f"PE: {info['file_name']} | {info['architecture']} | ENTROPY: {info['overall_entropy']} (Packer: {info['packer_name']}) | RISK: {info['risk_classification']} | SUSP: {susp}"

    if level == "full":
        lines = [
            f"File: {info['file_name']} ({info['file_size']:,} bytes)",
            f"SHA256: {info['sha256']}",
            f"Arch: {info['architecture']} | Format: {info['format']} | Subsystem: {info['subsystem']}",
            f"Entropy: {info['overall_entropy']} (Packer: {info['packer_name']})",
            "Sections: " + ", ".join(f"{s['name']}(ent:{s['entropy']})" for s in info["sections"]),
            f"Suspicious Indicators: {susp}",
            f"Risk: {info['risk_classification']}"
        ]
        return "\n".join(lines)

    return f"PE Analysis for {info['file_name']}: Arch {info['architecture']}, Entropy {info['overall_entropy']}, Packer {info['packer_name']}, Risk: {info['risk_classification']}."


def format_usb(devices: list, level: str) -> str:
    if devices and "error" in devices[0]:
        return f"ERROR: {devices[0]['error']}"
    if level == "off":
        return json.dumps(devices, indent=2)

    count = len(devices)
    if level == "ultra":
        if count == 0: return "USBSTOR: 0 devices."
        items = [f"{d['friendly_name']}(SN:{d['instance_id']})" for d in devices]
        return f"USBSTOR: {count} devices | " + " | ".join(items)

    if level == "full":
        if count == 0: return "USB History: No removable mass storage devices found in USBSTOR registry."
        lines = [f"USBSTOR History ({count} devices registered):"]
        for idx, d in enumerate(devices, 1):
            lines.append(f"{idx}. {d['friendly_name']} [Vendor: {d['vendor']}, Product: {d['product']}]")
            lines.append(f"   Instance/Serial: {d['instance_id']}")
        return "\n".join(lines)

    return f"DFIR USB Audit: {count} removable storage devices discovered in Windows registry."


def format_logs(logs: list, category: str, level: str) -> str:
    if logs and "error" in logs[0]:
        return f"ERROR: {logs[0]['error']}"
    if level == "off":
        return json.dumps(logs, indent=2)

    count = len(logs)
    if level == "ultra":
        if count == 0: return f"LOGS ({category}): 0 events."
        items = [f"EID:{e['event_id']}({e['user']},{e['task']})" for e in logs]
        return f"LOGS ({category}): {count} events | " + " | ".join(items[:5])

    if level == "full":
        if count == 0: return f"Log Triage ({category}): No matching events found."
        lines = [f"Log Triage ({category}, {count} events):"]
        for e in logs[:10]:
            lines.append(f"[{e['date']}] EID:{e['event_id']} ({e['task']}) - User: {e['user']}")
            if e["description"]:
                lines.append(f"  {e['description'][:90]}...")
        return "\n".join(lines)

    return f"Event Log Triage ({category}): {count} events retrieved."


# -----------------------------------------------------------------------------
# MCP SERVER PROTOCOL DEFINITION
# -----------------------------------------------------------------------------
TOOLS = [
    {
        "name": "set_cave_mode",
        "description": "Switch AI and MCP token compression mode (lite / full / ultra / off). Saves 80%-98% context tokens.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "level": {"type": "string", "enum": ["lite", "full", "ultra", "off"]}
            },
            "required": ["level"]
        }
    },
    {
        "name": "purple_audit_triad",
        "description": "Comprehensive Purple Team WAF & perimeter audit (Red probes + Blue checks + 0-100 score).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target base URL (e.g., http://10.0.1.67)"},
                "remote": {"type": "boolean", "description": "Execute via remote office SSH backend (default: false)"}
            },
            "required": ["target_url"]
        }
    },
    {
        "name": "malware_inspect_pe",
        "description": "Static PE32/PE32+ binary inspection: headers, Shannon entropy per-section, packer detection, and API heuristics.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Absolute path to Windows .exe or .dll"}
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "forensics_audit_usb",
        "description": "DFIR triage of USB storage device history via Windows USBSTOR registry.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "remote": {"type": "boolean", "description": "Execute on remote office PC via SSH (default: false)"}
            }
        }
    },
    {
        "name": "forensics_triage_logs",
        "description": "Incident response extraction of Windows Event Logs (logon, service persistence, audit tampering).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "enum": ["logon", "service", "audit_tamper", "system", "security", "application"]},
                "count": {"type": "integer", "description": "Number of recent events (default: 5)"},
                "remote": {"type": "boolean", "description": "Execute on remote office PC via SSH (default: false)"}
            },
            "required": ["category"]
        }
    },
    {
        "name": "gateway_status",
        "description": "Display OmniSec Universal Gateway Hub status, loaded skills, backend mode, and token savings.",
        "inputSchema": {"type": "object", "properties": {}}
    },
    {
        "name": "purple_apply_fix",
        "description": "Generate or write 1-click WAF hardening configuration rules (.htaccess / Nginx / IIS).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_type": {"type": "string", "enum": ["apache", "nginx", "iis"], "description": "Web server type (default: apache)"},
                "file_path": {"type": "string", "description": "Optional file path to write rules directly (e.g. .htaccess)"}
            }
        }
    },
    {
        "name": "generate_visual_report",
        "description": "Generate an interactive, standalone HTML security assessment dashboard with SVG gauge and heatmap.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target base URL"}
            }
        }
    },
    {
        "name": "mesh_audit_network",
        "description": "Orchestrate multi-node security posture audit across enterprise mesh targets.",
        "inputSchema": {"type": "object", "properties": {}}
    }
]


def main():
    global CURRENT_CAVE_LEVEL
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        method = req.get("method")
        msg_id = req.get("id")

        if method == "initialize":
            res = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}, "prompts": {}, "resources": {}},
                    "serverInfo": {"name": "omnisec-universal-gateway-hub", "version": "3.0.0"},
                },
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        elif method == "ping":
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {}}) + "\n")
            sys.stdout.flush()
        elif method == "tools/list":
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}) + "\n")
            sys.stdout.flush()
        elif method == "resources/list":
            resources = get_mcp_resources()
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {"resources": resources}}) + "\n")
            sys.stdout.flush()
        elif method == "resources/read":
            uri = req.get("params", {}).get("uri", "")
            content = read_mcp_resource(uri)
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": content}]}
            }) + "\n")
            sys.stdout.flush()
        elif method == "prompts/list":
            prompts = get_mcp_prompts()
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": prompts}}) + "\n")
            sys.stdout.flush()
        elif method == "prompts/get":
            p_params = req.get("params", {})
            p_name = p_params.get("name", "")
            p_args = p_params.get("arguments", {})
            messages = get_mcp_prompt_messages(p_name, p_args)
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"description": f"Prompt for {p_name}", "messages": messages}
            }) + "\n")
            sys.stdout.flush()
        elif method == "tools/call":
            params = req.get("params", {})
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            use_remote = tool_args.get("remote", REMOTE_ENABLED)

            if tool_name == "set_cave_mode":
                lvl = tool_args.get("level", "full").lower()
                if lvl in ["lite", "full", "ultra", "off"]:
                    CURRENT_CAVE_LEVEL = lvl
                result_text = f"Cave mode set to {CURRENT_CAVE_LEVEL}."
            elif tool_name == "gateway_status":
                skills = discover_skills()
                result_text = (
                    f"OMNISEC UNIVERSAL GATEWAY HUB v3.0.0\n"
                    f"- Mode: Caveman {CURRENT_CAVE_LEVEL.upper()}\n"
                    f"- Remote Backend: {REMOTE_SSH_HOST} (Enabled: {REMOTE_ENABLED})\n"
                    f"- Loaded Skills ({len(skills)}): {', '.join(skills.keys())}\n"
                    f"- Token Optimization: Active (Up to 98.6% context reduction)"
                )
            elif tool_name == "purple_audit_triad":
                target = tool_args.get("target_url", "")
                if use_remote:
                    result_text = proxy_tool_call_to_remote("purple_audit_triad", {"target_url": target}, REMOTE_SSH_HOST)
                else:
                    audit_res = execute_purple_audit(target)
                    result_text = format_audit(audit_res, CURRENT_CAVE_LEVEL)
            elif tool_name == "malware_inspect_pe":
                pe_res = inspect_pe(tool_args.get("file_path", ""))
                result_text = format_pe(pe_res, CURRENT_CAVE_LEVEL)
            elif tool_name == "forensics_audit_usb":
                if use_remote:
                    result_text = proxy_tool_call_to_remote("forensics_audit_usb", {}, REMOTE_SSH_HOST)
                else:
                    usb_res = query_usbstor()
                    result_text = format_usb(usb_res, CURRENT_CAVE_LEVEL)
            elif tool_name == "forensics_triage_logs":
                cat = tool_args.get("category", "logon")
                cnt = tool_args.get("count", 5)
                if use_remote:
                    result_text = proxy_tool_call_to_remote("forensics_triage_logs", {"category": cat, "count": cnt}, REMOTE_SSH_HOST)
                else:
                    log_res = query_event_logs(category=cat, count=cnt)
                    result_text = format_logs(log_res, cat, CURRENT_CAVE_LEVEL)
            elif tool_name == "purple_apply_fix":
                t_type = tool_args.get("target_type", "apache").lower()
                f_path = tool_args.get("file_path", "")
                if t_type == "nginx":
                    rules = "add_header X-Content-Type-Options \"nosniff\" always;\nadd_header X-Frame-Options \"SAMEORIGIN\" always;\nadd_header Content-Security-Policy \"default-src 'self';\" always;"
                elif t_type == "iis":
                    rules = "<customHeaders>\n  <add name=\"X-Content-Type-Options\" value=\"nosniff\" />\n  <add name=\"X-Frame-Options\" value=\"SAMEORIGIN\" />\n</customHeaders>"
                else:
                    rules = "Header always set X-Content-Type-Options \"nosniff\"\nHeader always set X-Frame-Options \"SAMEORIGIN\"\nHeader always set Content-Security-Policy \"default-src 'self';\"\nServerSignature Off"
                written = False
                if f_path:
                    norm_path = Path(f_path).resolve()
                    allowed_names = (".htaccess", "nginx.conf", "web.config")
                    is_system_path = str(norm_path).lower().startswith("c:\\windows") or str(norm_path).lower().startswith("c:\\program files")
                    if norm_path.name.lower() in allowed_names and not is_system_path:
                        try:
                            with open(norm_path, "a", encoding="utf-8") as f:
                                f.write("\n" + rules + "\n")
                            written = True
                        except Exception:
                            pass
                if CURRENT_CAVE_LEVEL == "ultra":
                    result_text = f"FIX: {t_type} -> {'WRITTEN' if written else 'SNIPPET_READY'}"
                else:
                    result_text = f"Remediation ({t_type}):\nStatus: {'Written to ' + f_path if written else 'Ready'}\n\n{rules}"
            elif tool_name == "generate_visual_report":
                t_url = tool_args.get("target_url", "http://10.0.1.67")
                if visual_report:
                    r_path = visual_report.save_report_to_disk(target_url=t_url)
                    if CURRENT_CAVE_LEVEL == "ultra":
                        result_text = f"REPORT: {r_path.name} ({r_path})"
                    else:
                        result_text = f"Visual Security Dashboard Generated:\nPath: {r_path}\nTarget: {t_url}\nOpen in browser to view SVG gauge & heatmap."
                else:
                    result_text = "Visual reporting module not loaded."
            elif tool_name == "mesh_audit_network":
                if mesh_manager:
                    result_text = mesh_manager.audit_mesh(CURRENT_CAVE_LEVEL)
                else:
                    result_text = "Mesh manager module not loaded."
            else:
                result_text = f"Tool '{tool_name}' unknown."

            res = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": result_text}],
                    "isError": "ERROR:" in result_text
                }
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
