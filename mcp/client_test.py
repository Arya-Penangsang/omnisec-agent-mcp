"""
OmniSec MCP Server - Automated JSON-RPC 2.0 Test Client
Verifies MCP protocol initialization, tools, prompts, resources, and execution.
"""
import subprocess
import json
import sys

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
                "clientInfo": {"name": "omnisec-test-runner", "version": "2.0"}
            }
        })
        print(f"    Server: {init_res['result']['serverInfo']['name']} v{init_res['result']['serverInfo']['version']}")

        # 2. Tools
        print("[2] Listing tools...")
        tools_res = send_recv({"jsonrpc": "2.0", "method": "tools/list", "params": {}})
        tools = [t["name"] for t in tools_res["result"]["tools"]]
        print(f"    Discovered {len(tools)} tools: {tools}")

        # 3. Prompts (Caveman Mode Prompt)
        print("[3] Listing prompts...")
        prompts_res = send_recv({"jsonrpc": "2.0", "method": "prompts/list", "params": {}})
        print(f"    Discovered prompts: {[p['name'] for p in prompts_res['result']['prompts']]}")

        # 4. Resources
        print("[4] Listing resources...")
        res_list = send_recv({"jsonrpc": "2.0", "method": "resources/list", "params": {}})
        print(f"    Discovered resources: {[r['uri'] for r in res_list['result']['resources']]}")

        # 5. Call Tool (Cave mode switch)
        print("[5] Testing tool call: set_cave_mode (ultra)...")
        call_res = send_recv({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "set_cave_mode",
                "arguments": {"level": "ultra"}
            }
        })
        print("    Response:", call_res["result"]["content"][0]["text"][:100] + "...")

        print("\n[+] ALL MCP PROTOCOL CHECKS PASSED!\n")

    finally:
        proc.terminate()

if __name__ == "__main__":
    cmd = ["php", "server.php"] if len(sys.argv) <= 1 else sys.argv[1:]
    run_test(cmd)
