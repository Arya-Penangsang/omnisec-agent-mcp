#!/usr/bin/env python3
"""
OmniSec Cloud Gateway & HTTP/SSE Daemon (Phase 4)
Standard Model Context Protocol (MCP) Streamable HTTP / Server-Sent Events (SSE) Transport

Features:
- Streamable SSE endpoint (`GET /sse`) & JSON-RPC message receiver (`POST /message`)
- Interactive Web Security Dashboard (`GET /report`)
- Node Health & Status API (`GET /health`)
- Optional Bearer Token Authentication
- Zero External Dependencies: Pure Python 3 standard library (`http.server`, `threading`, `uuid`)
"""

import sys
import os
import json
import uuid
import queue
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

# Ensure UTF-8
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from mcp import mcp_hub
from mcp import visual_report
from mesh import mesh_manager

# Active SSE Client Streams: sessionId -> queue.Queue
ACTIVE_SSE_SESSIONS = {}
AUTH_TOKEN = os.environ.get("OMNISEC_AUTH_TOKEN", "")


class McpSseHandler(BaseHTTPRequestHandler):
    server_version = "OmniSecGateway/4.0.0"

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def _send_cors_headers(self):
        origin = self.headers.get("Origin", "")
        # Safe origin validation: allow localhost/loopback or LAN, restrict arbitrary external origins
        if origin and any(h in origin for h in ("localhost", "127.0.0.1", "100.93.")):
            self.send_header("Access-Control-Allow-Origin", origin)
        else:
            self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:8765")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _check_auth(self) -> bool:
        if not AUTH_TOKEN:
            return True
        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            token = auth_hdr.split(" ", 1)[1].strip()
            return token == AUTH_TOKEN
        return False

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if not self._check_auth() and path not in ["/health", "/"]:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Unauthorized. Invalid Bearer Token."}).encode("utf-8"))
            return

        # 1. Health & Status
        if path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            body = {
                "status": "HEALTHY",
                "service": "omnisec-cloud-gateway",
                "version": "4.0.0",
                "active_sse_clients": len(ACTIVE_SSE_SESSIONS),
                "auth_required": bool(AUTH_TOKEN)
            }
            self.wfile.write(json.dumps(body, indent=2).encode("utf-8"))
            return

        # 2. Interactive Visual Report Dashboard
        if path == "/report":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._send_cors_headers()
            self.end_headers()
            html = visual_report.build_security_dashboard_html()
            self.wfile.write(html.encode("utf-8"))
            return

        # 3. Landing & Gateway Status Page
        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._send_cors_headers()
            self.end_headers()
            landing = f"""<!DOCTYPE html>
<html>
<head>
  <title>OmniSec Cloud Gateway Hub</title>
  <style>
    body {{ background: #090D16; color: #E2E8F0; font-family: -apple-system, sans-serif; padding: 40px; text-align: center; }}
    .card {{ max-width: 650px; margin: 0 auto; background: #111827; border: 1px solid #1F2937; border-radius: 12px; padding: 32px; box-shadow: 0 4px 24px rgba(0,0,0,0.5); }}
    h1 {{ color: #C084FC; margin-bottom: 8px; }}
    p {{ color: #94A3B8; font-size: 14px; line-height: 1.6; }}
    .btn {{ display: inline-block; background: #7C3AED; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: 700; margin: 8px; }}
    .btn:hover {{ background: #6D28D9; }}
    .code {{ background: #030712; padding: 12px; border-radius: 6px; font-family: monospace; color: #38BDF8; font-size: 12px; text-align: left; margin: 16px 0; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>🛡️ OmniSec Cloud Gateway</h1>
    <p>Model Context Protocol (MCP) Streamable HTTP / Server-Sent Events (SSE) Transport</p>
    <div class="code">
      SSE Endpoint    : http://{self.headers.get('Host', 'localhost:8765')}/sse<br>
      Message Receiver: http://{self.headers.get('Host', 'localhost:8765')}/message<br>
      Health Check    : http://{self.headers.get('Host', 'localhost:8765')}/health
    </div>
    <a href="/report" class="btn">📊 View Security Dashboard</a>
    <a href="/health" class="btn" style="background: #059669;">💚 Gateway Health</a>
  </div>
</body>
</html>"""
            self.wfile.write(landing.encode("utf-8"))
            return

        # 4. Standard MCP SSE Stream Endpoint (`GET /sse`)
        if path == "/sse":
            session_id = str(uuid.uuid4())
            msg_queue = queue.Queue()
            ACTIVE_SSE_SESSIONS[session_id] = msg_queue

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self._send_cors_headers()
            self.end_headers()

            # First event: tell client where to send POST messages
            endpoint_url = f"/message?sessionId={session_id}"
            self.wfile.write(f"event: endpoint\ndata: {endpoint_url}\n\n".encode("utf-8"))
            self.wfile.flush()

            try:
                while True:
                    try:
                        msg = msg_queue.get(timeout=20)
                        if msg is None:
                            break
                        self.wfile.write(f"event: message\ndata: {json.dumps(msg)}\n\n".encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        # Send SSE keep-alive comment
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
            except (ConnectionResetError, BrokenPipeError):
                pass
            finally:
                if session_id in ACTIVE_SSE_SESSIONS:
                    del ACTIVE_SSE_SESSIONS[session_id]
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if not self._check_auth():
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Unauthorized"}).encode("utf-8"))
            return

        if path == "/message":
            params = parse_qs(parsed.query)
            session_id = params.get("sessionId", [None])[0]

            content_len = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_len).decode("utf-8", errors="replace")

            try:
                rpc_req = json.loads(raw_body)
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(f"Invalid JSON: {str(e)}".encode("utf-8"))
                return

            # Process MCP JSON-RPC Request
            response = self._process_mcp_request(rpc_req)

            # If SSE session exists, push response to stream
            if session_id and session_id in ACTIVE_SSE_SESSIONS:
                ACTIVE_SSE_SESSIONS[session_id].put(response)
                self.send_response(202)  # Accepted
                self._send_cors_headers()
                self.end_headers()
            else:
                # Direct HTTP fallback
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps(response).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def _process_mcp_request(self, req: dict) -> dict:
        method = req.get("method")
        msg_id = req.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}, "prompts": {}, "resources": {}},
                    "serverInfo": {"name": "omnisec-cloud-gateway", "version": "4.0.0"}
                }
            }
        elif method == "tools/list":
            tools = list(mcp_hub.TOOLS)
            # Add mesh audit tool
            tools.append({
                "name": "mesh_audit_network",
                "description": "Orchestrate multi-node security posture audit across enterprise mesh targets.",
                "inputSchema": {"type": "object", "properties": {}}
            })
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": tools}}
        elif method == "resources/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": mcp_hub.get_mcp_resources()}}
        elif method == "resources/read":
            uri = req.get("params", {}).get("uri", "")
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": mcp_hub.read_mcp_resource(uri)}]}
            }
        elif method == "prompts/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": mcp_hub.get_mcp_prompts()}}
        elif method == "prompts/get":
            p_args = req.get("params", {})
            name = p_args.get("name", "")
            args = p_args.get("arguments", {})
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"description": f"Prompt for {name}", "messages": mcp_hub.get_mcp_prompt_messages(name, args)}
            }
        elif method == "tools/call":
            params = req.get("params", {})
            t_name = params.get("name")
            t_args = params.get("arguments", {})

            if t_name == "mesh_audit_network":
                res_text = mesh_manager.audit_mesh(mcp_hub.CURRENT_CAVE_LEVEL)
            elif t_name == "purple_audit_triad":
                res = mcp_hub.execute_purple_audit(t_args.get("target_url", ""))
                res_text = mcp_hub.format_audit(res, mcp_hub.CURRENT_CAVE_LEVEL)
            elif t_name == "set_cave_mode":
                lvl = t_args.get("level", "full").lower()
                if lvl in ["lite", "full", "ultra", "off"]:
                    mcp_hub.CURRENT_CAVE_LEVEL = lvl
                res_text = f"Cave mode set to {mcp_hub.CURRENT_CAVE_LEVEL}."
            elif t_name == "malware_inspect_pe":
                pe_res = mcp_hub.inspect_pe(t_args.get("file_path", ""))
                res_text = mcp_hub.format_pe(pe_res, mcp_hub.CURRENT_CAVE_LEVEL)
            elif t_name == "forensics_audit_usb":
                usb_res = mcp_hub.query_usbstor()
                res_text = mcp_hub.format_usb(usb_res, mcp_hub.CURRENT_CAVE_LEVEL)
            else:
                res_text = f"Tool '{t_name}' processed via Cloud Gateway."

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": res_text}], "isError": False}
            }

        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}}


def run_daemon(host: str = "0.0.0.0", port: int = 8765):
    server = HTTPServer((host, port), McpSseHandler)
    print("=" * 65)
    print("       ☁️  OMNISEC CLOUD GATEWAY & SSE DAEMON (PHASE 4)       ")
    print("=" * 65)
    print(f"[*] Bound Host       : {host}")
    print(f"[*] Bound Port       : {port}")
    print(f"[*] SSE Endpoint     : http://localhost:{port}/sse")
    print(f"[*] Dashboard URL    : http://localhost:{port}/report")
    print(f"[*] Health API       : http://localhost:{port}/health")
    print(f"[*] Authentication   : {'BEARER_ENABLED' if AUTH_TOKEN else 'PUBLIC_DEV_MODE'}")
    print("=" * 65)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Cloud Gateway Daemon...")
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OmniSec Cloud Gateway Daemon")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="HTTP port (default: 8765)")
    parser.add_argument("--token", default="", help="Optional Bearer authentication token")
    args = parser.parse_args()

    if args.token:
        AUTH_TOKEN = args.token

    run_daemon(host=args.host, port=args.port)
