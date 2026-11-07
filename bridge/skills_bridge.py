#!/usr/bin/env python3
"""
OmniSec Universal Bridge CLI
Automates cross-platform distribution of MCP servers and agent skills
across Claude Desktop, Claude Code, Google Antigravity, Cursor, and ChatGPT.
"""

import os
import sys
import json
import zipfile
import shutil
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MCP_SERVER_PATH = BASE_DIR / "mcp" / "server.php"
SKILLS_DIR = BASE_DIR / "skills"
DIST_DIR = BASE_DIR / "dist_packages"

def get_claude_desktop_config_path():
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "Claude" / "claude_desktop_config.json"
    return Path.home() / ".config" / "claude" / "claude_desktop_config.json"

def get_antigravity_config_path():
    return Path.home() / ".gemini" / "config" / "mcp_config.json"

def get_claude_code_skills_dir():
    return Path.home() / ".claude" / "skills"

def cmd_status():
    print("=" * 65)
    print("       OMNISEC AGENT MCP: PLATFORM DETECTION STATUS       ")
    print("=" * 65)

    claude_cfg = get_claude_desktop_config_path()
    agy_cfg = get_antigravity_config_path()
    claude_code_dir = get_claude_code_skills_dir()

    print(f"[*] Base Directory       : {BASE_DIR}")
    print(f"[*] MCP Server           : {MCP_SERVER_PATH} [{'FOUND' if MCP_SERVER_PATH.exists() else 'MISSING'}]")
    print(f"[*] Claude Desktop Config: {claude_cfg} [{'DETECTED' if claude_cfg.parent.exists() else 'NOT FOUND'}]")
    print(f"[*] Antigravity Config   : {agy_cfg} [{'DETECTED' if agy_cfg.parent.exists() else 'NOT FOUND'}]")
    print(f"[*] Claude Code Skills   : {claude_code_dir} [{'DETECTED' if claude_code_dir.exists() else 'NOT FOUND'}]")

    skills = [d.name for d in SKILLS_DIR.iterdir() if d.is_dir()]
    print(f"[*] Available Skills ({len(skills)}): {', '.join(skills)}")
    print("=" * 65)

def cmd_pack(args):
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    target_skill = args.skill

    skills_to_pack = [SKILLS_DIR / target_skill] if target_skill else [d for d in SKILLS_DIR.iterdir() if d.is_dir()]

    print(f"[*] Packing {len(skills_to_pack)} skills into ZIP packages for Claude Web (claude.ai)...")
    for s in skills_to_pack:
        if not s.exists():
            print(f"[-] Skill not found: {s.name}")
            continue
        zip_path = DIST_DIR / f"{s.name}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(s):
                for f in files:
                    full_p = Path(root) / f
                    rel_p = full_p.relative_to(s.parent)
                    zf.write(full_p, rel_p)
        print(f"[+] Created Claude Web Skill package: {zip_path}")

def cmd_sync(args):
    target = args.target.lower()
    print(f"[*] Syncing OmniSec configurations for target: {target}")

    mcp_entry = {
        "command": "php",
        "args": [str(MCP_SERVER_PATH)]
    }

    # 1. Antigravity
    if target in ["all", "antigravity"]:
        agy_path = get_antigravity_config_path()
        if agy_path.parent.exists():
            cfg = {"mcpServers": {}}
            if agy_path.exists():
                try:
                    with open(agy_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                except Exception:
                    cfg = {"mcpServers": {}}
            cfg.setdefault("mcpServers", {})["omnisec"] = mcp_entry
            with open(agy_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            print(f"[+] Updated Antigravity MCP config: {agy_path}")
        else:
            print(f"[-] Antigravity config directory not found: {agy_path.parent}")

    # 2. Claude Desktop
    if target in ["all", "claude-desktop", "claude"]:
        claude_path = get_claude_desktop_config_path()
        claude_path.parent.mkdir(parents=True, exist_ok=True)
        cfg = {"mcpServers": {}}
        if claude_path.exists():
            try:
                with open(claude_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
            except Exception:
                cfg = {"mcpServers": {}}
        cfg.setdefault("mcpServers", {})["omnisec"] = mcp_entry
        with open(claude_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        print(f"[+] Updated Claude Desktop MCP config: {claude_path}")

    # 3. Claude Code CLI
    if target in ["all", "claude-code"]:
        claude_skills = get_claude_code_skills_dir()
        claude_skills.mkdir(parents=True, exist_ok=True)
        for s in SKILLS_DIR.iterdir():
            if s.is_dir():
                dest = claude_skills / s.name
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(s, dest)
                print(f"[+] Copied skill '{s.name}' to Claude Code: {dest}")

    # 4. Cursor / Windsurf Project Rules
    if target in ["all", "cursor", "windsurf"]:
        cursor_dir = Path.cwd() / ".cursor"
        cursor_dir.mkdir(parents=True, exist_ok=True)
        cursor_mcp = cursor_dir / "mcp.json"
        cfg = {"mcpServers": {"omnisec": mcp_entry}}
        with open(cursor_mcp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        print(f"[+] Generated Cursor workspace MCP config: {cursor_mcp}")

    print("[+] Sync completed successfully!")

def cmd_export(args):
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    out_file = DIST_DIR / "omnisec_chatgpt_prompt_pack.md"
    print(f"[*] Generating compact Prompt Pack for ChatGPT / Claude Projects...")

    lines = [
        "# OMNISEC AGENT SYSTEM INSTRUCTIONS & RUNBOOK PACK\n",
        "## 1. Universal Caveman Mode (Token-Saving Response Style)\n"
    ]

    cave_skill = SKILLS_DIR / "cave" / "SKILL.md"
    if cave_skill.exists():
        lines.append(cave_skill.read_text(encoding="utf-8"))

    lines.append("\n\n## 2. Security Runbooks & Threat Emulation\n")
    for s in ["purple-team", "malware-triage", "digital-forensics"]:
        skill_md = SKILLS_DIR / s / "SKILL.md"
        if skill_md.exists():
            lines.append(f"\n### Domain: {s}\n")
            lines.append(skill_md.read_text(encoding="utf-8"))

    out_file.write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] Prompt Pack generated at: {out_file} (Ready to upload to ChatGPT / Claude Projects)")

def main():
    parser = argparse.ArgumentParser(description="OmniSec Universal Bridge CLI")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status", help="Detect installed AI platforms and MCP status")
    
    pack_p = subparsers.add_parser("pack", help="Create ZIP skill packages for Claude Web")
    pack_p.add_argument("--skill", help="Specific skill name to pack (default: all)")

    sync_p = subparsers.add_parser("sync", help="Sync MCP config to local AI clients")
    sync_p.add_argument("--target", default="all", choices=["all", "claude", "claude-desktop", "claude-code", "antigravity", "cursor", "windsurf"])

    subparsers.add_parser("export", help="Export compact prompt pack for ChatGPT/Claude Projects")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "status":
        cmd_status()
    elif args.command == "pack":
        cmd_pack(args)
    elif args.command == "sync":
        cmd_sync(args)
    elif args.command == "export":
        cmd_export(args)

if __name__ == "__main__":
    main()
