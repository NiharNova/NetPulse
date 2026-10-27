# NetPulse: Real-Time Network Traffic Analysis System - Project Memory & Context

## Project Overview
- **Project Name**: NetPulse: Real-Time Network Traffic Analysis System
- **Domain**: Computer Networks / Cyber Security / Network Monitoring
- **Repository Location**: `c:\ComputerNetworksfinal`
- **Application Type**: Full-stack Network Intelligence and Traffic Analysis Platform
- **Design Philosophy**: Dark NOC (Network Operations Center) / Cyber Terminal aesthetic (#05080a background, #0b1215 panels, #00ff9c neon green, #00e5ff cyan, #ffb300 warning amber, #ff3b3b alert red, monospace typography, scanlines, glowing borders).

---

## Technical Stack & Architecture

### 1. Backend (Python 3.10+)
- **Framework**: `FastAPI` with `Uvicorn` ASGI server
- **Protocol Streaming**: Native WebSockets (`/ws/traffic`) pushing 1 Hz real-time traffic telemetry snapshots
- **Packet Capture**: `Scapy` (`sniff()` in a managed background thread)
  - Windows: Utilizes Npcap (WinPcap-compatible mode)
  - Linux / macOS: Native libpcap with raw socket capabilities (`sudo`)
  - Resilience: Automatic fallback to **High-Fidelity Synthetic Traffic Generator** when Npcap/root is unavailable or when Demo Mode is engaged.
- **Data Structures**: Thread-safe in-memory rolling ring-buffers (`collections.deque(maxlen=...)`) for O(1) appending and time-window sliding statistics.
- **Alert Persistence**: Embedded `SQLite` database (`alerts.db`) storing detected security incidents and anomalies, with CSV export capabilities.
- **Port Scanner**: Multi-threaded socket auditor inspired by the open-source **SharkTooth** tool (https://github.com/znakar/SharkTooth) with RFC1918 safety guards.
- **Prometheus Metrics**: `/metrics` endpoint powered by `prometheus_client`.

### 2. Frontend (No Build Step)
- **Structure**: Plain HTML5, semantic structure, responsive grid.
- **Styling**: Vanilla CSS3 implementing a Dark NOC cyber terminal design system (variables, glassmorphic panels, glowing neon accents, matrix scanline overlay, blinking terminal cursor, responsive breakpoints).
- **Interactivity**: Vanilla JavaScript (ES6+), WebSocket client with exponential backoff auto-reconnect.
- **Visualizations**: `Chart.js` loaded via CDN, custom dark cyber theme plugin, smooth animations:
  - Bandwidth timeline (KB/s and packets/sec over 60 seconds)
  - Protocol breakdown doughnut chart (TCP, UDP, ICMP, DNS, HTTP, HTTPS, ARP, Other)
  - Top 10 Talkers (Source IPs by volume) and Top Destination Ports bar charts
  - Real-time animated Network Topology Graph rendered on HTML5 `<canvas>`

---

## File Map & Responsibilities

| File | Purpose |
|------|---------|
| `main.py` | FastAPI application entry point, lifecycle management, CORS, WebSocket `/ws/traffic`, REST endpoints mounting, Prometheus `/metrics` |
| `capture.py` | Scapy packet capture manager, interface enumeration, background thread worker, and realistic Synthetic Traffic Generator with attack simulation (Port Scan, SYN Flood, ICMP Spike, DNS Burst) |
| `analyzer.py` | In-memory rolling statistics (`collections.deque`), protocol counters, top talkers, active connection tracking, live packet ring-buffer (last 50 packets with deep L2-L7 dissection) |
| `anomaly.py` | Statistical anomaly detection (Rolling Mean, Std Dev, Z-Score > 3.0) and Rule-based attack detection (Port scan, SYN flood, ICMP flood, DNS spike). SQLite alert storage and CSV export |
| `scanner.py` | Network Audit module inspired by SharkTooth; RFC 1918 / Loopback IP validation, multi-threaded TCP/UDP port scanner, service detection |
| `tools.py` | Network Toolkit backend logic: Subnet calculator, VLSM planner, IP binary/hex converter, safe Ping, DNS lookup, Traceroute |
| `static/index.html` | Single-page application containing all 7 core sections: Home/Overview, Live Dashboard, Anomaly Alerts, Network Audit, Network Toolkit, Learn & Tools Hub, Architecture/About |
| `static/style.css` | Cyber NOC Dark Terminal styling, neon glow effects, scanlines, responsive layout, mini-Wireshark inspector |
| `static/app.js` | Client-side controller, WebSocket handler, Chart.js instances, packet table filter & inspector, interactive tools, canvas topology animation |
| `requirements.txt` | Python dependency specifications |
| `README.md` | Comprehensive documentation, setup guides (Windows/Linux/macOS), demo guide, and detailed Viva Voce Q&A |
| `PROJECT_MEMORY.md` | This persistent context document for future models and pair programmers |

---

## API Endpoints Reference

### Capture & Telemetry
- `GET /api/interfaces`: Returns list of available network interfaces with friendly names and IPs, plus the Demo Mode interface.
- `POST /api/capture/start`: Start live sniffing on specified interface or launch Demo Mode.
- `POST /api/capture/stop`: Stop current packet capture or demo simulation.
- `GET /api/capture/status`: Returns current capture status (running, interface, packets captured, mode).
- `POST /api/capture/simulate-attack`: Injects specific cyber attack traffic (port_scan, syn_flood, icmp_flood, dns_spike) for demonstrations.
- `WS /ws/traffic`: WebSocket pushing full telemetry snapshot every second (KPIs, bandwidth history, protocol distribution, top talkers, live packets, alert count).

### Anomaly & Alerts
- `GET /api/alerts`: Get recent detected anomalies and security alerts from SQLite (supports limit and severity filtering).
- `GET /api/alerts/export`: Download all detected alerts as a formatted `.csv` file.
- `POST /api/alerts/clear`: Clear alert history in SQLite.

### Network Audit (SharkTooth Module)
- `POST /api/scan`: Initiates a safe multi-threaded TCP/UDP port scan. Requires `authorized=true` and restricts target to loopback (`127.0.0.0/8`, `localhost`) or private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

### Network Toolkit
- `GET /api/tools/ping?host={host}&count={count}`: Safe ICMP/socket ping with latency calculation.
- `GET /api/tools/dns?host={host}&type={type}`: DNS record resolution (A, AAAA, MX, NS, TXT, CNAME, PTR).
- `GET /api/tools/traceroute?host={host}&max_hops={hops}`: Safe network traceroute with hop-by-hop latency.
- `POST /api/tools/subnet`: Subnet calculator (network address, broadcast, netmask, wildcard, usable host range, host count, CIDR).
- `POST /api/tools/vlsm`: Variable Length Subnet Masking (VLSM) hierarchical partition planner.

### Prometheus Metrics
- `GET /metrics`: Standard Prometheus metrics export (`netpulse_packets_total`, `netpulse_bytes_total`, `netpulse_alerts_total`, `netpulse_active_connections`).

---

## Viva Voce Knowledge Digest

1. **How Packet Capture Works**:
   - Network Interface Cards (NIC) normally discard frames not addressed to their MAC address. In *promiscuous mode*, the NIC passes all incoming frames up to the operating system.
   - Raw sockets or kernel drivers (like Npcap on Windows or AF_PACKET on Linux) tap into the network stack at the Data Link Layer (Layer 2), bypassing the kernel's normal TCP/IP handling.
   - Scapy uses Berkeley Packet Filters (BPF) to filter packets at the kernel level before copying them to user space, drastically reducing memory overhead.

2. **Protocol Parsing Engine**:
   - Frames start with Ethernet II header (14 bytes: 6B Dst MAC, 6B Src MAC, 2B EtherType).
   - If EtherType is `0x0800` (IPv4), parse IP header (Version, IHL, Total Length, Protocol, TTL, Src IP, Dst IP).
   - If Protocol is 6 (TCP), unpack Sequence Number, Ack Number, Data Offset, and 6 control flags: `SYN` (synchronize), `ACK` (acknowledge), `FIN` (finish), `RST` (reset), `PSH` (push), `URG` (urgent).
   - If Protocol is 17 (UDP), unpack 8-byte header: Source Port, Destination Port, Length, Checksum.
   - If Protocol is 1 (ICMP), unpack Type (e.g., 8 for Echo Request, 0 for Echo Reply) and Code.

3. **Anomaly Detection Mechanics**:
   - **Z-Score Baseline**: Maintains a rolling FIFO deque of packet and bandwidth rates. Computes Mean $\mu = \frac{1}{N}\sum x_i$ and Standard Deviation $\sigma = \sqrt{\frac{1}{N}\sum(x_i - \mu)^2}$. A current rate $x$ with $Z = \frac{x - \mu}{\sigma} > 3.0$ represents a statistical anomaly occurring with $<0.3\%$ probability under a normal distribution.
   - **Port Scan Detection**: Tracks distinct destination ports targeted by each individual source IP within a rolling time window. If unique port count exceeds threshold (e.g., >15 ports in 5 seconds), a port scan alert is triggered.
   - **SYN Flood Detection**: Monitors TCP SYN flags versus ACK flags. When a host initiates numerous connections (SYN) without completing handshakes (ACKs) exceeding normal ratios, a SYN flood attack is flagged.
