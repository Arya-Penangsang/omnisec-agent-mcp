# 🛡️ OmniSec Agent MCP (`omnisec-agent-mcp`)

[![License: MIT](https://img.shields.io/badge/Lisensi-MIT-blue.svg)](LICENSE)
[![MCP Standard](https://img.shields.io/badge/MCP-2024--11--05-purple.svg)](https://modelcontextprotocol.io/)
[![Multi-Model](https://img.shields.io/badge/Model-Claude%20%7C%20GPT--4o%20%7C%20Gemini%20%7C%20DeepSeek-green.svg)](#)

> **Server Model Context Protocol (MCP) Keamanan Siber Universal & Skill Agen Hemat Token untuk Claude, GPT, Antigravity, dan Cursor.**

OmniSec menggabungkan fungsi audit keamanan siber (Purple Team WAF audit, simulasi ancaman MITRE ATT&CK, analisis malware PE, dan forensik DFIR) dengan mesin penghemat token agresif **(Universal Caveman Mode)**, memastikan agen AI Anda dapat bekerja mendalam tanpa cepat menghabiskan limit percakapan (*rate limits*).

---

## ⚡ Fitur Utama

1. **Arsitektur Penghemat Token Ganda (*Dual Token Saver*):**
   * **Level Backend/Tool:** Formatter MCP dense memangkas token input sebesar **80%–98%**.
   * **Level Model/Teks:** Universal Caveman mode memangkas token output sebesar **60%–75%** dengan membuang basa-basi pembuka dan penutup.
2. **Agnostik Model:** Berjalan mulus di **Claude 3.5/3.7**, **GPT-4o/o1**, **Gemini 2.0/Pro**, dan model lokal (**Ollama / DeepSeek**).
3. **Multi-Platform Bridge:** Sinkronisasi 1-klik ke Claude Desktop, Claude Code CLI, Google Antigravity, dan Cursor.
4. **Eksekusi Lokal & Remote:** Menguji target lokal maupun tunneling via SSH ke server intranet kantor.

---

## 📊 Tolok Ukur Penghematan Token

Hasil uji coba nyata terhadap server web Apache/Ubuntu:

| Mode Output | Format Payload | Jumlah Token | Efisiensi | Penggunaan Terbaik |
| :--- | :--- | :---: | :---: | :--- |
| **Raw JSON (Mati)** | Pohon JSON mentah lengkap | ~1.200 token | 0% | Debugging teknis / Pipeline API |
| **Cave `FULL` (Default)** | Ringkasan telegrafik terstruktur | **~55 token** | **95.4%** | Analisis kerja agen sehari-hari |
| **Cave `ULTRA`** | Satu baris simbol & kata kunci | **~17 token** | **98.6%** | Loop berulang & batas token ketat |

---

## 🛠️ Daftar Tools MCP

| Nama Tool | Domain | Deskripsi |
| :--- | :---: | :--- |
| `set_cave_mode` | **Optimasi** | Mengubah level densitas respon AI dan tool (`lite`, `full`, `ultra`, `off`). |
| `purple_audit_triad` | **Purple Team** | Audit keamanan triad: simulasi Red probe + cek Blue perimeter + skor postur (0–100). |
| `purple_emulate_threat` | **Red Team** | Simulasi teknik spesifik MITRE ATT&CK (`T1595`, `T1190`, `T1110`, `T1083`). |
| `purple_validate_defense`| **Blue Team** | Evaluasi HTTP Security Headers (CSP, HSTS, X-Frame) dan menghasilkan konfigurasi `.htaccess`. |

---

## 🚀 Panduan Penggunaan Cepat

### 1. Periksa Status Platform
```bash
python bridge/skills_bridge.py status
```

### 2. Sinkronisasi Otomatis ke Platform AI
```bash
# Sinkronkan ke Claude Desktop, Antigravity, dan Cursor sekaligus:
python bridge/skills_bridge.py sync --target all
```

### 3. Buat Paket ZIP untuk Claude Web (claude.ai)
```bash
python bridge/skills_bridge.py pack
# Berkas ZIP siap diunggah akan berada di folder dist_packages/
```

---

## 🙏 Atribusi & Sumber Orisinal

* **[claude-skill-cave](https://github.com/asauntung/claude-skill-cave)**: Terima kasih dan apresiasi sebesar-besarnya kepada **[@asauntung](https://github.com/asauntung)** atas kreasi skill orisinal *Caveman mode* untuk Claude. OmniSec mengadaptasi dan memperluas konsep tersebut menjadi mesin penghemat token universal lintas-model.
* **[Model Context Protocol (MCP)](https://modelcontextprotocol.io/)**: Standar terbuka yang diinisiasi oleh Anthropic.
* **MITRE ATT&CK for Enterprise**: Taksonomi dan definisi teknik simulasi ancaman.

---

## 📄 Lisensi

Didistribusikan di bawah lisensi terbuka [MIT License](LICENSE).
