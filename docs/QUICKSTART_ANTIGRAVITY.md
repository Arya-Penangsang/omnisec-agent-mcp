# 🟣 Google Antigravity Quickstart

Guide to integrating **OmniSec Agent MCP** into Google Antigravity.

---

## 1. Register MCP Server

Add OmniSec to `~/.gemini/config/mcp_config.json`:

```json
{
  "mcpServers": {
    "omnisec": {
      "command": "php",
      "args": [
        "G:\\project\\ANTIGRAVIT PROJECT\\omnisec-agent-mcp\\mcp\\server.php"
      ]
    }
  }
}
```

*Or run the bridge automatic sync:*
```bash
python bridge/skills_bridge.py sync --target antigravity
```

---

## 2. Remote Office PC Execution via SSH

To execute security audits from an intranet server (e.g. office PC `PRESERVASI-BPMN`):

```json
{
  "mcpServers": {
    "omnisec-remote": {
      "command": "ssh",
      "args": [
        "-o", "BatchMode=yes",
        "-T", "kantor",
        "C:\\php\\php.exe",
        "C:\\Users\\Pengolahan\\mcp-servers\\purple-team\\server.php"
      ]
    }
  }
}
```

---

## 3. Using Caveman Token-Saving Mode

Activate token conservation at any time:
```text
/cave
cave ultra
set_cave_mode(level="ultra")
```
Output payloads are compressed by up to 98%, preserving context space.
