# 🟦 Cursor & Windsurf IDE Quickstart

Guide to integrating **OmniSec Agent MCP** with Cursor and Windsurf IDE.

---

## 1. Configure Workspace MCP

Generate `.cursor/mcp.json` automatically:
```bash
python bridge/skills_bridge.py sync --target cursor
```

Or manually create `.cursor/mcp.json` in your workspace:
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

---

## 2. Setting up Cursor Rules (`.cursorrules`)

Add the following rule to `.cursorrules` to enable Caveman Mode across the workspace:

```markdown
# OmniSec Token Conservation Rule
When the user mentions "cave", "/cave", or "hemat token", adopt Caveman Mode:
- Omit greetings, praise, and closing polite remarks.
- Deliver direct technical answers, commands, and code blocks first.
- Keep numbers, paths, diffs, and IPs 100% exact.
```
