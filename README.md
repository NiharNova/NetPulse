# NetPulse: Real-Time Network Traffic Analysis System

[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://www.python.org)
[![Scapy](https://img.shields.io/badge/Packet_Capture-Scapy-red)](https://scapy.net)
[![WebSockets](https://img.shields.io/badge/Streaming-WebSockets-00e5ff)](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API)
[![License: MIT](https://img.shields.io/badge/License-MIT-00ff9c.svg)](https://opensource.org/licenses/MIT)

> **Computer Networks Final Capstone Project**  
> An enterprise-grade, real-time network intelligence, packet dissection, statistical baseline anomaly detection, and security audit system.

---

## 1. Project Abstract

Modern computer networks generate a continuous and increasing volume of traffic, making it difficult for administrators to monitor communication, identify abnormal activities, and respond to network issues in real time. This project implements a Real-Time Network Traffic Analysis System that captures, analyzes, and visualizes traffic as it occurs, showing source/destination addresses, protocols, packet counts, bandwidth utilization, and traffic patterns, and highlighting significant deviations from established baselines.

**Keywords:** `Real-Time Network Traffic Analysis`, `Network Monitoring`, `Packet Capture`, `Network Security`, `Traffic Visualization`, `Bandwidth Monitoring`, `Anomaly Detection`, `Network Management`.

---

## 2. Core Feature Highlights

- **Dark NOC / Cyber Terminal Aesthetic:** Designed with a Network Operations Center (NOC) dark theme (`#05080a` background, `#0b1215` glassmorphic panels, neon green `#00ff9c`, cyber cyan `#00e5ff`, amber `#ffb300`, and red `#ff3b3b` accents, CRT scanlines, blinking terminal cursor, and pulsating system LED).
- **Interactive Animated Topology:** HTML5 `<canvas>` simulation featuring dynamic nodes (gateway, cloud, servers, workstations, rogue nodes) with traveling packet particles.
- **Layer 2–7 Deep Packet Dissection:** Inspects Ethernet II MAC addresses, ARP frames, IPv4/IPv6 headers, TCP control flags (SYN, ACK, FIN, RST, PSH, URG), UDP datagrams, ICMP echo requests, and DNS query payloads.
- **Wireshark-like Header Inspector:** Click any row in the live packet table to launch an interactive modal showing tree-view header fields and raw hex/ASCII payload dumps.
- **Sub-Second WebSocket Streaming:** Non-blocking 1 Hz WebSocket broadcast pushing rolling 60-second bandwidth timelines, protocol distribution doughnuts, top talkers, and active connection counts.
- **Dual-Engine Anomaly Detection:**
  - *Statistical Baseline Engine:* Rolling mean ($\mu$) and standard deviation ($\sigma$) with Gaussian Z-score deviation triggers ($|Z| > 3.0$).
  - *Heuristic IDS Rules:* Port scan detection ($>15$ ports in 5s), TCP SYN flood detection ($>25$ SYN without ACK), ICMP echo burst detection, DNS tunneling spike detection, and oversized MTU frames.
- **Persistent SQLite Alert Storage & CSV Export:** Security incidents are recorded in `alerts.db` and can be downloaded as a CSV audit report.
- **Network Audit (SharkTooth Module):** Multithreaded TCP/UDP socket scanner inspired by [SharkTooth](https://github.com/znakar/SharkTooth) with RFC1918 private/loopback safety bounds, service mapping, and Prometheus metrics.
- **Integrated Network Toolkit:** Subnet calculator, VLSM hierarchical planner, IP/Binary/Hex converter, plus sanitized Ping, DNS, and Traceroute diagnostic utilities.
- **Zero-Dependency Demo Mode:** High-fidelity multi-protocol synthetic traffic generator with manual attack injection buttons, allowing full demonstrations even without Npcap or administrator privileges!

---

## 3. Technology Stack

| Layer | Component | Technologies |
|---|---|---|
| **Backend API** | ASGI Micro-framework | Python 3.10+, FastAPI, Uvicorn |
| **Packet Engine** | Raw Frame Capture | Scapy 2.5+, Npcap (Windows) / libpcap (Linux/macOS) |
| **Real-Time Pipeline** | Full-Duplex Broadcast | WebSockets (1 Hz JSON snapshots) |
| **Data Buffers** | In-Memory Sliding Windows | `collections.deque(maxlen=...)` (Thread-Safe, $O(1)$) |
| **Database** | Persistent Incident Log | SQLite3 (`alerts.db`) |
| **Telemetry Visuals** | NOC Dashboards | Chart.js 4.4, HTML5 `<canvas>` |
| **Frontend UI** | Zero-Build Web Interface | Vanilla HTML5, Vanilla CSS3, Vanilla ES6 JavaScript |
| **Metrics Exporter**| Prometheus Scraping | `prometheus_client` (`/metrics` endpoint) |

---

## 4. Architecture Pipeline

```
┌─────────────────────────┐          ┌─────────────────────────┐
│ Live Adapter (Scapy)   │          │ Synthetic Generator     │
│ (Promiscuous Mode/Npcap)│          │ (Demo Mode & Attacks)   │
└────────────┬────────────┘          └────────────┬────────────┘
             │                                    │
             └─────────────────┬──────────────────┘
                               │
                               ▼
                ┌──────────────────────────────┐
                │ Thread-Safe Dissection Engine│
                │ (Ethernet -> IP -> L4 -> L7) │
                └──────────────┬───────────────┘
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
                 ▼                           ▼
  ┌──────────────────────────────┐ ┌───────────────────────────┐
  │ TrafficAnalyzer              │ │ AnomalyEngine             │
  │ • 60s Bandwidth Sliding Deque│ │ • Rolling Z-Score Baseline│
  │ • Protocol Counter & Talkers │ │ • Heuristic IDS Rules     │
  │ • Ring Buffer (Last 50 Pkts) │ │ • SQLite Database Log     │
  └──────────────┬───────────────┘ └─────────────┬─────────────┘
                 │                               │
                 └─────────────┬─────────────────┘
                               │
                               ▼
                 ┌───────────────────────────┐
                 │ FastAPI WebSocket (/ws)   │
                 │ 1 Hz Full Snapshot Push   │
                 └─────────────┬─────────────┘
                               │
                               ▼
                 ┌───────────────────────────┐
                 │ Dark NOC Single-Page App  │
                 │ (DOM + Chart.js + Canvas) │
                 └───────────────────────────┘
```

---

## 5. Installation & Setup

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13 installed.
- Git (optional, for cloning).

### Clone or Open the Workspace
```bash
cd c:\ComputerNetworksfinal
```

### Install Python Dependencies
```bash
pip install -r requirements.txt
```

---

### Operating System Specific Setup for Live Packet Sniffing

> [!NOTE]  
> If you do not have administrator rights or Npcap installed, NetPulse will automatically engage **Demo Mode** with realistic enterprise traffic and attack simulations. All features, charts, and tools remain 100% operational!

#### Windows Setup
1. **Download Npcap**: Download and install the Npcap packet capture driver from [npcap.com](https://npcap.com/#download).
2. **Installation Options**: During setup, check:
   - *"Install Npcap in WinPcap API-compatible Mode"*
   - *"Support raw 802.11 traffic"* (optional)
3. **Run as Administrator**: Open your Command Prompt or PowerShell with **"Run as Administrator"** so Scapy can bind to raw network adapters.

#### Linux Setup
1. Install libpcap development headers:
   ```bash
   sudo apt update
   sudo apt install -y libpcap-dev
   ```
2. Grant packet capture capabilities to Python without running as full root (recommended):
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
   ```
   Or run the server using `sudo`:
   ```bash
   sudo python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
   ```

#### macOS Setup
1. Install libpcap via Homebrew (usually preinstalled):
   ```bash
   brew install libpcap
   ```
2. Ensure read/write access to BPF devices:
   ```bash
   sudo chmod 777 /dev/bpf*
   ```

---

## 6. How to Run NetPulse

Start the FastAPI application with Uvicorn:

```bash
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Once started:
- **Web Dashboard**: Open your browser and navigate to `http://localhost:8000`
- **Interactive API Documentation (Swagger)**: `http://localhost:8000/docs`
- **Prometheus Metrics Endpoint**: `http://localhost:8000/metrics`

---

## 7. How to Demo the System in a Viva / Presentation

### Scenario A: Out-of-the-Box Demo Mode (Zero Setup Required)
1. Launch NetPulse (`http://localhost:8000`). By default, NetPulse starts in **Demo Mode**.
2. Navigate to **02 // Live Dashboard**. You will immediately see:
   - 6 KPI cards updating in real time.
   - Bandwidth timeline (KB/s and pps) advancing second-by-second.
   - Protocol doughnut chart showing TCP, UDP, ICMP, DNS, HTTP, and HTTPS traffic.
   - Live packet table populated with dissected frames.
3. **Trigger Attack Vectors Live**:
   - Click **⚡ Attack Simulator: Port Scan**  
     *Result:* Watch 24 distinct destination ports get probed. Switch to **03 // Anomaly & Alerts** to see the `Port Scan Detected` high-severity alert logged with timestamp and source IP!
   - Click **⚡ Attack Simulator: SYN Flood**  
     *Result:* Watch the bandwidth surge and the `SYN Flood Attack` incident triggered in SQLite!
   - Click **⚡ Attack Simulator: ICMP Flood**  
     *Result:* Watch the ICMP protocol slice grow and the `ICMP Echo Flood` alert trigger.
   - Click **⚡ Attack Simulator: DNS Spike**  
     *Result:* Notice the purple DNS spike and the `DNS Query Spike` alert.
4. **Inspect Packets (Mini-Wireshark)**: Click any row in the packet table to inspect its Ethernet II, IP, TCP/UDP headers, and raw hex/ASCII payload.

### Scenario B: Live Network Sniffing (With Npcap & Administrator)
1. Run PowerShell as Administrator.
2. Launch `python -m uvicorn main:app --reload --port 8000`.
3. Select your physical adapter (e.g. `Wi-Fi` or `Ethernet`) in the interface dropdown and click **▶ START CAPTURE**.
4. Generate traffic from your own machine:
   - **Ping Probe:** In another terminal, run:
     ```bash
     ping 8.8.8.8 -n 10
     ```
     *Watch ICMP echo requests appear instantly in the live packet table!*
   - **DNS Queries:** Run:
     ```bash
     nslookup github.com 8.8.8.8
     ```
   - **Local Port Scan (Nmap):** Run against loopback:
     ```bash
     nmap -sS -p 1-100 127.0.0.1
     ```
     *Watch NetPulse detect the reconnaissance scan and flag the anomaly!*

### Scenario C: Network Audit (SharkTooth Module)
1. Navigate to **04 // Network Audit**.
2. Target: `127.0.0.1`, Port Range: `common`, Protocol: `TCP`.
3. Check the legal authorization checkbox and click **▶ EXECUTE AUDIT**.
4. Watch the multithreaded socket engine probe ports in parallel, displaying port states (`OPEN`, `CLOSED`, `FILTERED`), recognized service names, and round-trip latency in milliseconds.
5. Notice that if you attempt to scan an external public IP, NetPulse's RFC1918 compliance guard safely rejects the scan.

### Scenario D: Network Engineering Toolkit
1. Navigate to **05 // Toolkit**.
2. Test the **Subnet Calculator** with `192.168.1.50/24` to view netmask, wildcard mask, host ranges, and binary representations.
3. Test the **VLSM Planner** with `192.168.1.0/24` to automatically allocate variable-length subnets for multiple departments.
4. Test the **Ping Diagnostics** and **DNS Resolver** utilities.

---

## 8. Viva Voce Examination Q&A Guide

### Q1: How does packet capture actually work at the operating system level?
**Answer:**  
In normal operation, a Network Interface Card (NIC) operates in non-promiscuous mode, filtering out all frames whose destination MAC does not match the adapter's physical MAC (or multicast/broadcast). To capture arbitrary traffic, the NIC is switched into **promiscuous mode**.  
Standard operating system sockets (e.g., `SOCK_STREAM`) operate at Layer 4 (Transport) and only deliver data payloads to user-space. NetPulse utilizes raw socket kernel drivers (such as **Npcap** on Windows using NDIS 6 Light-Weight Filters, or `AF_PACKET` on Linux) to capture raw frames directly at Layer 2 (Data Link). Furthermore, Scapy utilizes **Berkeley Packet Filters (BPF)** to execute filtering inside the kernel before copying packet buffers into user-space memory, minimizing CPU overhead and packet loss.

---

### Q2: How does NetPulse dissect packets across the TCP/IP layers?
**Answer:**  
Packet dissection follows the encapsulation hierarchy:
1. **Layer 2 (Data Link):** Reads the 14-byte Ethernet II header (`Destination MAC [6B]`, `Source MAC [6B]`, and `EtherType [2B]`). If EtherType is `0x0806`, it dissects ARP. If `0x0800`, it unpacks IPv4.
2. **Layer 3 (Network):** Reads the IPv4 header, extracting Version, Internet Header Length (IHL), Total Length, TTL, Protocol ID (6 for TCP, 17 for UDP, 1 for ICMP), and Source/Destination IP addresses.
3. **Layer 4 (Transport):**
   - For TCP (Protocol 6): Extracts Source Port, Destination Port, Sequence Number, Acknowledgment Number, and the 6 control flags: `SYN` (Connection Request), `ACK` (Acknowledgment), `FIN` (Graceful Termination), `RST` (Connection Reset), `PSH` (Push Data), and `URG` (Urgent Pointer).
   - For UDP (Protocol 17): Extracts 8-byte header containing Source/Destination Ports and Datagram Length.
   - For ICMP (Protocol 1): Extracts Type (Type 8 = Echo Request, Type 0 = Echo Reply), Code, and Sequence Number.
4. **Layer 7 (Application):** Inspects payloads for well-known protocol signatures: DNS transaction IDs and query names (port 53), HTTP request methods (`GET`, `POST`) and response headers (port 80), and TLS Client Hello / Application Data (port 443).

---

### Q3: How does NetPulse achieve sub-second real-time responsiveness without memory leaks or UI freezes?
**Answer:**  
NetPulse employs a **dual-threaded decoupled architecture**:
1. **Capture Worker Thread:** Runs packet capture independently in a background worker thread. When a frame arrives, it parses the metadata into a lean Python dictionary and pushes it into an in-memory rolling ring buffer (`collections.deque(maxlen=50)`).
2. **O(1) Memory Complexity:** `collections.deque` provides constant-time $O(1)$ append and pop operations. When the buffer reaches 50 packets, the oldest frame is discarded automatically without allocating new memory blocks or causing memory leaks.
3. **Asynchronous WebSocket Broadcaster:** Instead of the frontend polling via HTTP (which creates massive HTTP handshake overhead), a native WebSocket channel (`/ws/traffic`) maintains a persistent TCP full-duplex socket. Once every second, the backend compiles a unified snapshot and pushes it to all connected browser clients.

---

### Q4: How does the statistical baseline anomaly detection work?
**Answer:**  
NetPulse implements a **Rolling Z-Score (Standard Score)** baseline engine:
1. It maintains sliding FIFO buffers of packet rates ($pps$) and bandwidth ($KB/s$) over the last 30–60 seconds.
2. At every 1-second tick, it calculates the rolling Mean ($\mu$) and Standard Deviation ($\sigma$):
   $$\mu = \frac{1}{N} \sum_{i=1}^{N} x_i \qquad \sigma = \sqrt{\frac{1}{N} \sum_{i=1}^{N} (x_i - \mu)^2}$$
3. When a new rate $X$ is measured, the Z-score is computed:
   $$Z = \frac{X - \mu}{\sigma}$$
4. According to Chebyshev's inequality and Gaussian normal distributions, values with $|Z| > 3.0$ have a probability of occurrence under normal conditions of less than $0.27\%$ ($p < 0.003$). When sustained rates exceed $Z > 3.0$, NetPulse flags an anomaly, assigns a severity score, and records the incident in SQLite.

---

### Q5: How do the heuristic IDS rules identify Port Scans and SYN Floods?
**Answer:**  
- **Port Scan Detection:** A sliding window tracks destination ports probed by each unique source IP within a 5-second interval. If an IP probes more than 15 unique destination ports, NetPulse flags a reconnaissance scan.
- **SYN Flood Detection:** In a normal TCP three-way handshake, a `SYN` is followed by a `SYN-ACK` and an `ACK`. During a SYN flood attack, an attacker spams `SYN` packets without completing the handshake, attempting to exhaust the victim's connection backlog table (`TCP half-open connections`). NetPulse tracks the ratio of `SYN` flags to `ACK` flags per source IP; if the SYN count exceeds 25 and the SYN-to-ACK ratio exceeds 5:1, a high-severity SYN flood attack is declared.

---

### Q6: Why is the SharkTooth Network Audit module restricted to RFC1918 private ranges?
**Answer:**  
Port scanning public internet IP addresses without explicit written consent is illegal in most jurisdictions under computer security laws (such as the Computer Fraud and Abuse Act or IT Acts) and is treated as unauthorized reconnaissance.  
To ensure strict ethical and academic safety, NetPulse resolves target hostnames and validates that the destination IP falls strictly within RFC1918 private address spaces (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or loopback (`127.0.0.0/8`). Scans against public IP ranges are automatically blocked.

---

### Q7: How does Prometheus metric integration work?
**Answer:**  
NetPulse exposes a standard `/metrics` endpoint using `prometheus_client`. It tracks cumulative metrics:
- `netpulse_packets_total`: Monotonically increasing counter of all processed packets.
- `netpulse_bytes_total`: Total volume of network traffic processed.
- `netpulse_alerts_total`: Gauge tracking triggered security incidents.
- `netpulse_active_connections`: Gauge tracking concurrent live connections.
- `netpulse_scans_total`: Counter tracking network audit operations.  
Any standard Prometheus instance can scrape `http://localhost:8000/metrics` every 5–15 seconds, and Grafana dashboards can be connected directly to visualize enterprise-wide network health.

---

## 9. File Structure

```
c:\ComputerNetworksfinal\
├── main.py                # FastAPI app, REST endpoints, WebSocket & Prometheus
├── capture.py             # Scapy sniffer, interface discovery, synthetic attack generator
├── analyzer.py            # Rolling deques, protocol counters, top talkers, packet ring buffer
├── anomaly.py             # Z-score statistical baseline, heuristic IDS, SQLite & CSV export
├── scanner.py             # SharkTooth-inspired multithreaded TCP/UDP port scanner
├── tools.py               # Subnet calculator, VLSM, IP converter, Ping, DNS, Traceroute
├── requirements.txt       # Python dependency specifications
├── alerts.db              # SQLite database created automatically for incident logs
├── README.md              # Project documentation, setup, and viva Q&A
├── PROJECT_MEMORY.md      # Persistent project memory and context for AI models
├── AGENTS.md              # Agent guidelines and design constraints
└── static/                # Single-page frontend (No build step)
    ├── index.html         # HTML5 layout with all 7 core sections & modal
    ├── style.css          # Dark NOC cyber terminal theme & scanline overlays
    └── app.js             # Vanilla JS, WebSocket client, Chart.js & canvas animation
```

---

## 10. Verification & Quality Assurance

To test NetPulse's backend modules programmatically:
```bash
python -c "
import analyzer, anomaly, capture, scanner, tools
print('All NetPulse modules imported cleanly!')
"
```

To run the live server:
```bash
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
Open `http://localhost:8000` to access the console.
