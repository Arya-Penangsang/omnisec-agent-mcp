# Contributing to OmniSec Agent MCP

Thank you for your interest in contributing to **OmniSec Agent MCP**! 🛡️

We welcome contributions from cybersecurity engineers, AI researchers, and open-source developers worldwide.

---

## 🎯 Contribution Areas

1. **New MITRE ATT&CK Techniques:**
   - Add new emulation probes in `mcp/server.php` and `mcp/server.py` (e.g., SSRF `T1190`, Path Traversal `T1083`, CORS misconfiguration).
2. **Sigma Detection Rules:**
   - Extend the detection database with production Sigma rules.
3. **Forensic Artifact Decoders:**
   - Add new registry keys, Prefetch parsers, or event log filters.
4. **Platform Bridges:**
   - Add native integration adapters for new developer environments and agent runtimes.
5. **Token Optimization:**
   - Enhance the Caveman dense output formatter for higher token conservation.

---

## 🛠️ Local Development & Testing

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Arya-Penangsang/omnisec-agent-mcp.git
   cd omnisec-agent-mcp
   ```

2. **Verify Environment Status:**
   ```bash
   python bridge/skills_bridge.py status
   ```

3. **Run End-to-End Test Suite:**
   ```bash
   python mcp/test_e2e.py
   ```

4. **Verify MCP Handshake manually:**
   ```bash
   python mcp/client_test.py python -u mcp/server.py
   ```

---

## 📋 Pull Request Guidelines

- Ensure `python mcp/test_e2e.py` passes without errors on your machine.
- Follow Caveman Mode token-saving principles for all tool output formatters.
- Maintain documentation parity across `README.md` and `README.id.md`.
- Keep core server scripts zero-dependency (rely only on standard libraries where possible).

Thank you for helping make autonomous AI security agents safer and more efficient!
