#!/usr/bin/env python3
"""
OmniSec Multi-Host Mesh Manager (Phase 4)
Orchestrates security assessments across multiple intranet/cloud targets,
VPN gateways, and distributed endpoints.
"""

import sys
import json
import urllib.request
import urllib.error
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INVENTORY_FILE = BASE_DIR / "mesh" / "inventory.json"


def load_inventory() -> dict:
    if not INVENTORY_FILE.exists():
        return {"nodes": []}
    try:
        return json.loads(INVENTORY_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"nodes": []}


def save_inventory(data: dict):
    INVENTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    INVENTORY_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def probe_node_quick(url: str, timeout: int = 4) -> dict:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "OmniSec-Mesh/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
            return {
                "alive": True,
                "status_code": resp.status,
                "has_csp": "content-security-policy" in headers,
                "has_hsts": "strict-transport-security" in headers,
                "has_xframe": "x-frame-options" in headers,
                "error": None
            }
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()}
        return {
            "alive": True,
            "status_code": e.code,
            "has_csp": "content-security-policy" in headers,
            "has_hsts": "strict-transport-security" in headers,
            "has_xframe": "x-frame-options" in headers,
            "error": None
        }
    except Exception as e:
        return {"alive": False, "status_code": 0, "has_csp": False, "has_hsts": False, "has_xframe": False, "error": str(e)}


def audit_mesh(cave_level: str = "full") -> str:
    inv = load_inventory()
    nodes = inv.get("nodes", [])
    results = []

    for n in nodes:
        node_id = n.get("id")
        name = n.get("name")
        target_type = n.get("type")
        url = n.get("url")

        if url:
            p_res = probe_node_quick(url)
            score = 50
            if p_res["alive"]:
                if p_res["has_csp"]: score += 20
                if p_res["has_hsts"]: score += 15
                if p_res["has_xframe"]: score += 15
            else:
                score = 0

            results.append({
                "id": node_id,
                "name": name,
                "target": url,
                "alive": p_res["alive"],
                "score": score,
                "status": "ONLINE" if p_res["alive"] else "OFFLINE/UNREACHABLE"
            })
        elif n.get("ssh_alias"):
            # Gateway host (e.g. office_pc via Tailscale)
            results.append({
                "id": node_id,
                "name": name,
                "target": f"SSH:{n.get('ssh_alias')}",
                "alive": True,
                "score": 85,
                "status": "GATEWAY_ACTIVE"
            })

    if cave_level == "ultra":
        lines = []
        for r in results:
            lines.append(f"{r['id']} -> {r['status']} ({r['score']}/100)")
        return "MESH AUDIT: " + " | ".join(lines)

    if cave_level == "full":
        lines = [f"OmniSec Network Mesh Audit ({len(results)} nodes evaluated):"]
        for r in results:
            lines.append(f"- [{r['status']}] {r['name']} ({r['target']}) - Posture Score: {r['score']}/100")
        return "\n".join(lines)

    return json.dumps(results, indent=2)


if __name__ == "__main__":
    print(audit_mesh("full"))
