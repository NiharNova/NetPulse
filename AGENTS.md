# AGENTS.md - Workspace Agent Instructions

## Workspace: NetPulse - Real-Time Network Traffic Analysis System

This workspace contains the complete implementation of **NetPulse: Real-Time Network Traffic Analysis System**, a full-stack network intelligence platform built for a Computer Networks project.

### Core Guidelines & Rules:
1. **Tech Stack Integrity**:
   - Backend: Python 3.10+, FastAPI, Uvicorn, WebSockets, Scapy, Prometheus Client, SQLite.
   - Frontend: Vanilla HTML5, Vanilla CSS3, Vanilla ES6 JavaScript, Chart.js CDN. No React, no Vue, no bundler/build step. All static assets are served directly by FastAPI.
2. **Design Standards (Dark NOC Cyber Terminal)**:
   - Primary Background: `#05080a`, Panel Background: `#0b1215`, Card Border: `1px solid rgba(0, 255, 156, 0.2)` or `rgba(0, 229, 255, 0.2)`.
   - Accent Palette: Neon Green (`#00ff9c`), Cyber Cyan (`#00e5ff`), Warning Amber (`#ffb300`), Alert Red (`#ff3b3b`).
   - Monospace typography (`JetBrains Mono`, `Fira Code`, `Consolas`, monospace).
   - High-tech details: Scanlines overlay, blinking terminal cursor, "SYSTEM ONLINE" LED indicators, glow filters.
3. **Resilience & Demo Mode**:
   - Live packet sniffing requires administrator/root privileges and Npcap on Windows or libpcap on Linux/macOS.
   - When Npcap is missing or when the user runs without admin, the system MUST NOT crash. It falls back gracefully to high-fidelity **Demo Mode** with realistic synthetic network traffic, attack injection (Port Scan, SYN flood, ICMP flood, DNS spike), and clear user guidance.
4. **Safety in Network Audits**:
   - Any port scanner or active network tool MUST restrict target hosts to RFC1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and Loopback (`127.0.0.0/8`, `localhost`).
   - Require explicit authorization acknowledgement (`authorized=True`).

Refer to `PROJECT_MEMORY.md` and `README.md` for in-depth system architecture and viva concepts.
