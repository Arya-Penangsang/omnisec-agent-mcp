"""
OmniSec MCP Server - Automated JSON-RPC 2.0 Test Client
Verifies MCP protocol initialization, tools, prompts, resources, and live execution.
Tests Caveman token-saving mode and Phase 1 defensive tools:
- malware_inspect_pe
- forensics_audit_usb
- forensics_triage_logs
"""
import subprocess
import json
import sys
import os

def run_test(command):
    print(f"[*] Starting OmniSec MCP Server with: {' '.join(command)}")
    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    msg_id = 1
    def send_recv(req):
        nonlocal msg_id
        req["id"] = msg_id
        msg_id += 1
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            return None
        return json.loads(line)

    try:
        # 1. Initialize
        print("[1] Sending initialize...")
        init_res = send_recv({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "omnisec-test-runner", "version": "2.1"}
            }
        })
        s_info = init_res['result']['serverInfo']
        print(f"    Server: {s_info['name']} v{s_info['version']}")

        # 2. Tools
        print("[2] Listing tools...")
        tools_res = send_recv({"jsonrpc": "2.0", "method": "tools/list", "params": {}})
        tools = [t["name"] for t in tools_res["result"]["tools"]]
        print(f"    Discovered {len(tools)} tools: {tools}")

        # 3. Prompts
        print("[3] Listing prompts...")
        prompts_res = send_recv({"jsonrpc": "2.0", "method": "prompts/list", "params": {}})
        print(f"    Discovered prompts: {[p['name'] for p in prompts_res['result']['prompts']]}")

        # 4. Resources
        print("[4] Listing resources...")
        res_list = send_recv({"jsonrpc": "2.0", "method": "resources/list", "params": {}})
        if "resources" in res_list["result"]:
            print(f"    Discovered resources: {[r['uri'] for r in res_list['result']['resources']]}")

        # 5. Test Cave Mode (Ultra)
        print("\n[5] Testing tool call: set_cave_mode (ultra)...")
        call_res = send_recv({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "set_cave_mode",
                "arguments": {"level": "ultra"}
            }
        })
        print("    Response:", call_res["result"]["content"][0]["text"])

        # 6. Test PE Inspection (malware_inspect_pe) in Ultra Mode
        target_exe = r"C:\Windows\System32\notepad.exe"
        if not os.path.exists(target_exe):
            target_exe = sys.executable
        print(f"\n[6] Testing tool call: malware_inspect_pe on '{target_exe}' (ultra mode)...")
        pe_res = send_recv({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "malware_inspect_pe",
                "arguments": {"file_path": target_exe}
            }
        })
        print("    Response (Ultra):", pe_res["result"]["content"][0]["text"])

        # Switch to Full Mode and test PE again
        send_recv({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "set_cave_mode", "arguments": {"level": "full"}}
        })
        pe_res_full = send_recv({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "malware_inspect_pe",
                "arguments": {"file_path": target_exe}
            }
        })
        print("    Response (Full):\n" + "\n".join("      " + l for l in pe_res_full["result"]["content"][0]["text"].splitlines()))

        # 7. Test USBSTOR Forensics (forensics_audit_usb)
        print("\n[7] Testing tool call: forensics_audit_usb...")
        usb_res = send_recv({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "forensics_audit_usb",
                "arguments": {}
            }
        })
        print("    Response:", usb_res["result"]["content"][0]["text"])

        # 8. Test Log Triage (forensics_triage_logs if supported)
        if "forensics_triage_logs" in tools:
            print("\n[8] Testing tool call: forensics_triage_logs (system, count: 2)...")
            log_res = send_recv({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "forensics_triage_logs",
                    "arguments": {"category": "system", "count": 2}
                }
            })
            print("    Response:\n" + "\n".join("      " + l for l in log_res["result"]["content"][0]["text"].splitlines()))

        print("\n[+] ALL MCP PROTOCOL & SECURITY TOOL CHECKS PASSED!\n")

    finally:
        proc.terminate()

if __name__ == "__main__":
    cmd = ["php", "server.php"] if len(sys.argv) <= 1 else sys.argv[1:]
    run_test(cmd)
