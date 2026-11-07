# 🟠 Claude Desktop & Claude Code Quickstart

Guide to integrating **OmniSec Agent MCP** with Anthropic Claude.

---

## 1. Claude Desktop (MCP Stdio Integration)

Add OmniSec to your Claude Desktop configuration file:
* **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
* **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

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
python bridge/skills_bridge.py sync --target claude-desktop
```

---

## 2. Claude Web (claude.ai) Skill Integration

1. Run the pack command:
   ```bash
   python bridge/skills_bridge.py pack --skill cave
   ```
2. In [claude.ai](https://claude.ai), go to **Settings > Capabilities > Skills**.
3. Upload `dist_packages/cave.zip` and enable the toggle.

---

## 3. Claude Code CLI Integration

Sync all skills directly to Claude Code's local skill directory:
```bash
python bridge/skills_bridge.py sync --target claude-code
```
*(Files will be copied to `~/.claude/skills/`)*
