#!/usr/bin/env python3
"""
OmniSec Universal Bridge CLI (Phase 2 & 3)
Cross-platform distribution, MCP configuration sync, and packaging engine
Supports Claude Desktop, Claude Code, Cursor, Windsurf, Antigravity, and Web LLMs.
"""

import os
import sys
import json
import zipfile
import shutil
import argparse
import platform
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MCP_DIR = BASE_DIR / "mcp"
PHP_SERVER_PATH = MCP_DIR / "server.php"
PY_SERVER_PATH = MCP_DIR / "server.py"
HUB_SERVER_PATH = MCP_DIR / "mcp_hub.py"
SKILLS_DIR = BASE_DIR / "skills"
DIST_DIR = BASE_DIR / "dist_packages"

SYSTEM_OS = platform.system()

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def get_claude_desktop_config_path() -> Path:
    if SYSTEM_OS == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Claude" / "claude_desktop_config.json"
        return Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    elif SYSTEM_OS == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    else:
        return Path.home() / ".config" / "claude" / "claude_desktop_config.json"


def get_antigravity_config_paths() -> list:
    paths = [
        Path.home() / ".gemini" / "antigravity" / "mcp_config.json",
        Path.home() / ".gemini" / "config" / "mcp_config.json",
    ]
    return paths


def get_claude_code_skills_dir() -> Path:
    return Path.home() / ".claude" / "skills"


def get_cursor_mcp_path(workspace_dir: Path = None) -> Path:
    ws = workspace_dir or Path.cwd()
    return ws / ".cursor" / "mcp.json"


def get_windsurf_mcp_path(workspace_dir: Path = None) -> Path:
    ws = workspace_dir or Path.cwd()
    return ws / ".windsurf" / "mcp.json"


def build_mcp_entry(runtime: str = "auto", mode: str = "local", remote_host: str = "kantor") -> dict:
    if mode == "remote":
        return {
            "command": "ssh",
            "args": [
                "-o", "BatchMode=yes",
                "-T", remote_host,
                "php C:\\Users\\Pengolahan\\mcp-servers\\purple-team\\server.php"
            ]
        }

    # Local mode
    if runtime == "python" or (runtime == "auto" and PY_SERVER_PATH.exists()):
        return {
            "command": "python",
            "args": ["-u", str(PY_SERVER_PATH)]
        }
    else:
        return {
            "command": "php",
            "args": [str(PHP_SERVER_PATH)]
        }


def cmd_status():
    print("=" * 70)
    print("       🛡️  OMNISEC AGENT MCP: MULTI-PLATFORM STATUS       ")
    print("=" * 70)

    claude_cfg = get_claude_desktop_config_path()
    claude_code_dir = get_claude_code_skills_dir()
    agy_cfgs = get_antigravity_config_paths()
    cursor_mcp = get_cursor_mcp_path()

    print(f"[*] Base Directory       : {BASE_DIR}")
    print(f"[*] OS Environment       : {SYSTEM_OS} ({platform.machine()})")
    print(f"[*] PHP Server Engine    : {PHP_SERVER_PATH} [{'FOUND' if PHP_SERVER_PATH.exists() else 'MISSING'}]")
    print(f"[*] Python Server Engine : {PY_SERVER_PATH} [{'FOUND' if PY_SERVER_PATH.exists() else 'MISSING'}]")
    print(f"[*] Claude Desktop Config: {claude_cfg} [{'EXISTS' if claude_cfg.exists() else ('DIR_READY' if claude_cfg.parent.exists() else 'NOT_FOUND')}]")
    print(f"[*] Claude Code Skills   : {claude_code_dir} [{'EXISTS' if claude_code_dir.exists() else 'NOT_FOUND'}]")
    for idx, p in enumerate(agy_cfgs, 1):
        print(f"[*] Antigravity Config #{idx}: {p} [{'EXISTS' if p.exists() else ('DIR_READY' if p.parent.exists() else 'NOT_FOUND')}]")
    print(f"[*] Cursor Workspace MCP : {cursor_mcp} [{'EXISTS' if cursor_mcp.exists() else 'READY_TO_CREATE'}]")

    skills = [d.name for d in SKILLS_DIR.iterdir() if d.is_dir()]
    print(f"[*] Available Skills ({len(skills)}): {', '.join(skills)}")
    print("=" * 70)


def cmd_pack(args):
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    target_skill = args.skill

    skills_to_pack = [SKILLS_DIR / target_skill] if target_skill else [d for d in SKILLS_DIR.iterdir() if d.is_dir()]

    print(f"[*] Packing {len(skills_to_pack)} skills into ZIP packages for Claude Web (claude.ai)...")
    created = []
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
        print(f"[+] Created Claude Skill package: {zip_path.name}")
        created.append(zip_path)

    # Master bundle containing all skills
    all_zip = DIST_DIR / "omnisec_all_skills.zip"
    with zipfile.ZipFile(all_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(SKILLS_DIR):
            for f in files:
                full_p = Path(root) / f
                rel_p = full_p.relative_to(SKILLS_DIR)
                zf.write(full_p, rel_p)
    print(f"[+] Created Master Bundle: {all_zip.name}")
    print(f"[+] All packages saved in: {DIST_DIR}")


def cmd_sync(args):
    target = args.target.lower()
    runtime = args.runtime
    mode = args.mode
    remote_host = args.remote_host

    print(f"[*] Syncing OmniSec configurations [Target: {target}, Runtime: {runtime}, Mode: {mode}]...")

    mcp_entry = build_mcp_entry(runtime=runtime, mode=mode, remote_host=remote_host)

    def update_json_config(file_path: Path, server_key: str = "omnisec"):
        file_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"mcpServers": {}}
        if file_path.exists():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = {"mcpServers": {}}
        data.setdefault("mcpServers", {})[server_key] = mcp_entry
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Configured MCP server '{server_key}' in: {file_path}")

    # 1. Antigravity
    if target in ["all", "antigravity"]:
        for agy_path in get_antigravity_config_paths():
            if agy_path.parent.exists():
                update_json_config(agy_path)

    # 2. Claude Desktop
    if target in ["all", "claude", "claude-desktop"]:
        claude_path = get_claude_desktop_config_path()
        update_json_config(claude_path)

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

    # 4. Cursor IDE
    if target in ["all", "cursor"]:
        cursor_mcp = get_cursor_mcp_path()
        update_json_config(cursor_mcp)

    # 5. Windsurf IDE
    if target in ["all", "windsurf"]:
        windsurf_mcp = get_windsurf_mcp_path()
        update_json_config(windsurf_mcp)

    print("[+] Synchronization completed successfully!")


def cmd_export(args):
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    target = args.target.lower()

    if target in ["all", "prompt-pack", "chatgpt"]:
        out_file = DIST_DIR / "omnisec_chatgpt_prompt_pack.md"
        print("[+] Generating compact Prompt Pack for ChatGPT / Claude Projects...")

        lines = [
            "# 🛡️ OMNISEC AGENT SYSTEM INSTRUCTIONS & RUNBOOK PACK\n",
            "> Model-Agnostic Cybersecurity & Token-Saving Knowledge Pack (Claude, GPT-4o, Gemini, DeepSeek)\n",
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
        print(f"[+] Prompt Pack written: {out_file}")

    if target in ["all", "cursorrules", "cursor"]:
        dest_dir = Path(args.dest) if getattr(args, "dest", None) else BASE_DIR
        cr_path = dest_dir / ".cursorrules"
        print(f"[+] Generating .cursorrules at: {cr_path}...")
        cr_content = (
            "# OmniSec Agent Rules for Cursor / Windsurf\n\n"
            "# 1. TOKEN OPTIMIZATION (Caveman Mode Full)\n"
            "- Direct answer first. No greetings ('Hello', 'Sure!'), no conversational outro filler.\n"
            "- Exact technical precision: preserve 100% of code, file paths, shell commands, IPs, hashes, CVEs.\n"
            "- Use telegraphic fragments and structured tables for dense output.\n\n"
            "# 2. CYBERSECURITY ASSISTANCE WORKFLOWS\n"
            "- When auditing web endpoints: verify WAF defenses against dotfiles (/.env, /.git), SQLi, and backup dumps.\n"
            "- When analyzing executables: inspect PE headers, check Shannon entropy (>7.2 = packed), and detect packers.\n"
            "- When performing DFIR: query USBSTOR registry for removable storage history and triage Windows Event Logs.\n"
        )
        cr_path.write_text(cr_content, encoding="utf-8")
        print(f"[+] Generated .cursorrules successfully!")


def main():
    parser = argparse.ArgumentParser(description="OmniSec Universal Bridge CLI (Phase 2 & 3)")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status", help="Detect installed AI platforms and MCP configuration status")

    pack_p = subparsers.add_parser("pack", help="Create ZIP skill packages for Claude Web and Claude Projects")
    pack_p.add_argument("--skill", help="Specific skill name to pack (default: all)")

    sync_p = subparsers.add_parser("sync", help="Sync MCP configuration to local AI clients")
    sync_p.add_argument("--target", default="all", choices=["all", "claude", "claude-desktop", "claude-code", "antigravity", "cursor", "windsurf"])
    sync_p.add_argument("--runtime", default="auto", choices=["auto", "python", "php"], help="Execution runtime (auto, python, php)")
    sync_p.add_argument("--mode", default="local", choices=["local", "remote"], help="Execution mode (local or remote SSH)")
    sync_p.add_argument("--remote-host", default="kantor", help="Remote SSH host alias (default: kantor)")

    exp_p = subparsers.add_parser("export", help="Export Prompt Pack for ChatGPT or .cursorrules")
    exp_p.add_argument("--target", default="all", choices=["all", "prompt-pack", "chatgpt", "cursorrules", "cursor"])
    exp_p.add_argument("--dest", help="Destination directory for exported rules (default: repo root)")

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
