"""
OmniSec Agent MCP Server (Python Native Implementation)
Standard Model Context Protocol (MCP) JSON-RPC 2.0 over Stdio

Zero-dependency: Pure Python 3 standard library
Works across Windows, Linux, and macOS.
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
from collections import Counter
from datetime import datetime

# Global Caveman State
CURRENT_CAVE_LEVEL = "full"  # "lite" | "full" | "ultra" | "off"


def get_cave_system_prompt(level="full"):
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


def send_http_probe(url: str, method="GET", headers=None, post_data=None, timeout=6):
    req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OmniSecAgentMCP-Py/2.0"}
    if headers:
        req_headers.update(headers)

    data_bytes = post_data.encode("utf-8") if isinstance(post_data, str) else post_data
    req = urllib.request.Request(url, data=data_bytes, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            res_headers = {k.lower(): v for k, v in resp.getheaders()}
            return {"code": code, "headers": res_headers, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        res_headers = {k.lower(): v for k, v in e.headers.items()}
        return {"code": e.code, "headers": res_headers, "body": body, "error": None}
    except Exception as e:
        return {"code": 0, "headers": {}, "body": "", "error": str(e)}


def inspect_pe(file_path: str):
    file_path = os.path.expandvars(file_path.strip())
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    file_size = os.path.getsize(file_path)
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

            # Risk score
            risk = "LOW"
            if packer_detected and len(found_apis) >= 2:
                risk = "CRITICAL"
            elif packer_detected or len(found_apis) >= 3:
                risk = "HIGH"
            elif len(found_apis) > 0 or overall_entropy > 6.8:
                risk = "MEDIUM"

            with open(file_path, "rb") as hf:
                content = hf.read()
                sha256 = hashlib.sha256(content).hexdigest()
                md5 = hashlib.md5(content).hexdigest()

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


def format_pe_output(info, level):
    if "error" in info:
        return f"ERROR: {info['error']}"

    if level == "off":
        return json.dumps(info, indent=2)

    if level == "ultra":
        susp = ",".join(info["suspicious_indicators"][:4]) if info["suspicious_indicators"] else "None"
        return f"PE: {info['file_name']} | {info['architecture']} | ENTROPY: {info['overall_entropy']} (Packer: {info['packer_name']}) | RISK: {info['risk_classification']} | SUSP: {susp}"

    if level == "full":
        lines = [
            f"File: {info['file_name']} ({info['file_size']:,} bytes)",
            f"SHA256: {info['sha256']}",
            f"Arch: {info['architecture']} | Format: {info['format']} | Subsystem: {info['subsystem']}",
            f"Entropy: {info['overall_entropy']} (Packer: {info['packer_name']})",
            "Sections: " + ", ".join(f"{s['name']} (ent: {s['entropy']})" for s in info["sections"]),
            "Suspicious Indicators: " + (", ".join(info["suspicious_indicators"]) if info["suspicious_indicators"] else "None"),
            f"Risk: {info['risk_classification']}",
        ]
        return "\n".join(lines)

    lines = [
        f"Portable Executable Analysis for {info['file_name']}:",
        f"- Architecture: {info['architecture']}, Format: {info['format']}",
        f"- SHA256: {info['sha256']}",
        f"- Shannon Entropy: {info['overall_entropy']} (Packed: {info['packer_detected']})",
        f"- Detected Sections: {len(info['sections'])}",
        f"- Suspicious APIs: {', '.join(info['suspicious_indicators']) if info['suspicious_indicators'] else 'None'}",
        f"- Risk: {info['risk_classification']}",
    ]
    return "\n".join(lines)


def query_usbstor():
    if sys.platform != "win32":
        return {"error": "USBSTOR registry triage is supported natively on Windows systems."}

    try:
        res = subprocess.run(
            ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR", "/s"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = res.stdout
    except Exception as e:
        return {"error": f"Failed to execute reg query: {str(e)}"}

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


def format_usb_output(devices, level):
    if isinstance(devices, dict) and "error" in devices:
        return f"ERROR: {devices['error']}"

    if level == "off":
        return json.dumps(devices, indent=2)

    count = len(devices)
    if level == "ultra":
        if count == 0:
            return "USBSTOR: 0 devices connected."
        items = [f"{d['friendly_name']} (SN: {d['instance_id']})" for d in devices]
        return f"USBSTOR: {count} devices | " + " | ".join(items)

    if level == "full":
        if count == 0:
            return "USB History: No removable mass storage devices found in USBSTOR registry."
        lines = [f"USBSTOR History: {count} devices registered"]
        for idx, d in enumerate(devices, 1):
            lines.append(f"{idx}. {d['friendly_name']} [Vendor: {d['vendor']}, Product: {d['product']}]")
            lines.append(f"   Instance/Serial: {d['instance_id']}")
            if d.get("container_id"):
                lines.append(f"   ContainerID: {d['container_id']}")
        return "\n".join(lines)

    lines = [f"Digital Forensics Audit - USB Storage Devices ({count} found):"]
    for d in devices:
        lines.append(f"- Device: {d['friendly_name']}")
        lines.append(f"  Vendor: {d['vendor']}, Product: {d['product']}")
        lines.append(f"  Serial / Instance ID: {d['instance_id']}")
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# MCP SERVER PROTOCOL
# -----------------------------------------------------------------------------
TOOLS = [
    {
        "name": "set_cave_mode",
        "description": "Ubah gaya respon AI dan output MCP menjadi mode Caveman hemat token (lite / full / ultra / off).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "level": {
                    "type": "string",
                    "enum": ["lite", "full", "ultra", "off"],
                    "description": "Tingkat kompresi output"
                }
            },
            "required": ["level"]
        }
    },
    {
        "name": "purple_audit_triad",
        "description": "Audit triad keamanan menyeluruh (Red probes + Blue checks + scoring) dengan output terkompresi.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "URL target web"}
            },
            "required": ["target_url"]
        }
    },
    {
        "name": "malware_inspect_pe",
        "description": "Analisis statis binary PE32/PE32+ (Windows EXE/DLL): arsitektur, Shannon entropy, deteksi packer (UPX, ASPack), suspicious APIs, dan klasifikasi risiko.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path absolut ke file binary executable Windows"}
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "forensics_audit_usb",
        "description": "Triage forensik digital riwayat flashdisk/perangkat penyimpanan eksternal (USBSTOR Registry) pada Windows host.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_all_usb": {"type": "boolean", "description": "Sertakan perangkat USB umum"}
            }
        }
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
                    "serverInfo": {"name": "omnisec-agent-mcp-py", "version": "2.1.0"},
                },
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        elif method == "ping":
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {}}) + "\n")
            sys.stdout.flush()
        elif method == "tools/list":
            res = {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        elif method == "prompts/list":
            prompts = [{
                "name": "cave_mode",
                "description": "Caveman Mode System Prompt",
                "arguments": [{"name": "level", "description": "lite, full, ultra", "required": False}]
            }]
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": prompts}}) + "\n")
            sys.stdout.flush()
        elif method == "prompts/get":
            p_args = req.get("params", {}).get("arguments", {})
            lvl = p_args.get("level", "full")
            res = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "description": "Caveman Prompt",
                    "messages": [{"role": "user", "content": {"type": "text", "text": get_cave_system_prompt(lvl)}}]
                }
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        elif method == "resources/list":
            resources = [
                {"uri": "resource://skills/cave", "name": "Universal Cave Skill Guide", "mimeType": "text/markdown"},
                {"uri": "resource://skills/purple-team", "name": "Purple Team Triad Assessment", "mimeType": "text/markdown"},
                {"uri": "resource://skills/malware-triage", "name": "Malware Triage Runbook", "mimeType": "text/markdown"},
                {"uri": "resource://skills/digital-forensics", "name": "Digital Forensics DFIR Runbook", "mimeType": "text/markdown"},
            ]
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {"resources": resources}}) + "\n")
            sys.stdout.flush()
        elif method == "resources/read":
            uri = req.get("params", {}).get("uri", "")
            text = "Resource content for " + uri
            if uri == "resource://skills/cave":
                text = get_cave_system_prompt("full")
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": text}]}
            }) + "\n")
            sys.stdout.flush()
        elif method == "tools/call":
            params = req.get("params", {})
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})

            if tool_name == "set_cave_mode":
                lvl = tool_args.get("level", "full").lower()
                if lvl in ["lite", "full", "ultra", "off"]:
                    CURRENT_CAVE_LEVEL = lvl
                result_text = f"Cave mode set to {CURRENT_CAVE_LEVEL}."
            elif tool_name == "malware_inspect_pe":
                pe_res = inspect_pe(tool_args.get("file_path", ""))
                result_text = format_pe_output(pe_res, CURRENT_CAVE_LEVEL)
            elif tool_name == "forensics_audit_usb":
                usb_res = query_usbstor()
                result_text = format_usb_output(usb_res, CURRENT_CAVE_LEVEL)
            else:
                result_text = f"Tool {tool_name} not implemented in Python core."

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
