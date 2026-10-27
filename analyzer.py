"""
NetPulse - Real-Time Network Traffic Analysis System
analyzer.py - Thread-safe rolling statistics, protocol classification,
active connection tracking, and packet ring-buffer dissection.
"""

import time
import threading
from collections import deque, Counter
from typing import Dict, List, Any, Optional

# Well-known ports mapping for service recognition
WELL_KNOWN_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9090: "Prometheus",
    27017: "MongoDB"
}


class TrafficAnalyzer:
    """
    Maintains real-time sliding window telemetry and packet dissection records.
    Designed for concurrent safety between packet ingestion thread and WebSocket broadcaster.
    """

    def __init__(self, history_seconds: int = 60, packet_buffer_size: int = 50):
        self.history_seconds = history_seconds
        self.lock = threading.RLock()

        # Cumulative counters
        self.total_packets = 0
        self.total_bytes = 0
        self.packet_counter_id = 0

        # One-second interval accumulators
        self.current_sec_packets = 0
        self.current_sec_bytes = 0
        self.last_tick_time = time.time()

        # 60-second time-series rolling deques
        self.timestamps: deque = deque(maxlen=history_seconds)
        self.bandwidth_kbps: deque = deque(maxlen=history_seconds)
        self.packets_rate: deque = deque(maxlen=history_seconds)

        # Initialize with 0s for a full 60-second chart on startup
        now = time.time()
        for i in range(history_seconds):
            t_str = time.strftime("%H:%M:%S", time.localtime(now - (history_seconds - 1 - i)))
            self.timestamps.append(t_str)
            self.bandwidth_kbps.append(0.0)
            self.packets_rate.append(0)

        # Protocol distribution counters
        self.protocol_counts: Counter = Counter({
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "DNS": 0,
            "HTTP": 0,
            "HTTPS": 0,
            "ARP": 0,
            "Other": 0
        })

        # Top talkers (Source IP -> Total Bytes)
        self.ip_bytes_map: Counter = Counter()

        # Top destination ports (Port -> Packet count)
        self.dest_port_counts: Counter = Counter()

        # Active connections tracker: (src_ip, dst_ip, src_port, dst_port, proto) -> last_seen_timestamp
        self.active_connections: Dict[tuple, float] = {}

        # Unique IP set
        self.unique_ips = set()

        # Ring buffer for recent packets (L2-L7 dissected)
        self.recent_packets: deque = deque(maxlen=packet_buffer_size)

        # Session start time
        self.start_time = time.time()

    def reset(self):
        """Reset all counters and rolling windows for a clean session."""
        with self.lock:
            self.total_packets = 0
            self.total_bytes = 0
            self.packet_counter_id = 0
            self.current_sec_packets = 0
            self.current_sec_bytes = 0
            self.last_tick_time = time.time()
            self.timestamps.clear()
            self.bandwidth_kbps.clear()
            self.packets_rate.clear()

            now = time.time()
            for i in range(self.history_seconds):
                t_str = time.strftime("%H:%M:%S", time.localtime(now - (self.history_seconds - 1 - i)))
                self.timestamps.append(t_str)
                self.bandwidth_kbps.append(0.0)
                self.packets_rate.append(0)

            self.protocol_counts = Counter({
                "TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0,
                "HTTP": 0, "HTTPS": 0, "ARP": 0, "Other": 0
            })
            self.ip_bytes_map.clear()
            self.dest_port_counts.clear()
            self.active_connections.clear()
            self.unique_ips.clear()
            self.recent_packets.clear()
            self.start_time = time.time()

    def process_packet(self, pkt_info: Dict[str, Any]):
        """
        Ingest a dissected packet dictionary from capture thread into analyzer buffers.
        """
        with self.lock:
            self.packet_counter_id += 1
            pkt_info["id"] = self.packet_counter_id

            length = pkt_info.get("length", 64)
            proto = pkt_info.get("protocol", "Other")
            src_ip = pkt_info.get("src_ip", "0.0.0.0")
            dst_ip = pkt_info.get("dst_ip", "0.0.0.0")
            dst_port = pkt_info.get("dst_port")
            src_port = pkt_info.get("src_port")

            # Update cumulative counters
            self.total_packets += 1
            self.total_bytes += length
            self.current_sec_packets += 1
            self.current_sec_bytes += length

            # Protocol breakdown classification
            if proto in self.protocol_counts:
                self.protocol_counts[proto] += 1
            else:
                self.protocol_counts["Other"] += 1

            # Top talkers
            if src_ip and src_ip not in ("-", "0.0.0.0"):
                self.ip_bytes_map[src_ip] += length
                self.unique_ips.add(src_ip)
            if dst_ip and dst_ip not in ("-", "0.0.0.0"):
                self.unique_ips.add(dst_ip)

            # Top destination ports
            if dst_port is not None and dst_port > 0:
                self.dest_port_counts[dst_port] += 1

            # Active connections tracking
            if src_ip and dst_ip and src_port is not None and dst_port is not None:
                conn_key = (src_ip, dst_ip, src_port, dst_port, proto)
                self.active_connections[conn_key] = time.time()

            # Live packet table ring buffer
            self.recent_packets.append(pkt_info)

    def tick_second(self) -> Dict[str, Any]:
        """
        Periodic 1-second pulse to calculate rolling rates and prune stale connection states.
        Called on every WebSocket broadcast tick.
        """
        with self.lock:
            now = time.time()
            elapsed = now - self.last_tick_time
            if elapsed < 0.8:
                # Avoid jitter if called too quickly
                elapsed = 1.0

            # Compute rates
            rate_kbps = round((self.current_sec_bytes / 1024.0) / elapsed, 2)
            rate_pps = int(self.current_sec_packets / elapsed)

            # Shift deques
            t_str = time.strftime("%H:%M:%S", time.localtime(now))
            self.timestamps.append(t_str)
            self.bandwidth_kbps.append(rate_kbps)
            self.packets_rate.append(rate_pps)

            # Reset interval accumulators
            self.current_sec_packets = 0
            self.current_sec_bytes = 0
            self.last_tick_time = now

            # Prune inactive connections older than 20 seconds
            stale_threshold = now - 20.0
            self.active_connections = {
                k: v for k, v in self.active_connections.items() if v >= stale_threshold
            }

            return {
                "rate_kbps": rate_kbps,
                "rate_pps": rate_pps,
                "timestamp": t_str
            }

    def get_snapshot(self) -> Dict[str, Any]:
        """
        Generates a complete telemetry snapshot formatted for the WebSocket / dashboard payload.
        """
        with self.lock:
            # Format top 10 talkers
            top_talkers_raw = self.ip_bytes_map.most_common(10)
            top_talkers = [
                {"ip": ip, "bytes": b, "kb": round(b / 1024, 1)}
                for ip, b in top_talkers_raw
            ]

            # Format top 10 destination ports with service names
            top_ports_raw = self.dest_port_counts.most_common(10)
            top_ports = [
                {
                    "port": port,
                    "service": WELL_KNOWN_PORTS.get(port, f"Port {port}"),
                    "count": count
                }
                for port, count in top_ports_raw
            ]

            # Format bandwidth in human-readable notation
            if self.total_bytes >= 1024 * 1024 * 1024:
                formatted_total_bytes = f"{round(self.total_bytes / (1024**3), 2)} GB"
            elif self.total_bytes >= 1024 * 1024:
                formatted_total_bytes = f"{round(self.total_bytes / (1024**2), 2)} MB"
            else:
                formatted_total_bytes = f"{round(self.total_bytes / 1024, 1)} KB"

            # Current bandwidth
            current_kbps = self.bandwidth_kbps[-1] if self.bandwidth_kbps else 0.0
            current_pps = self.packets_rate[-1] if self.packets_rate else 0

            return {
                "kpis": {
                    "total_packets": self.total_packets,
                    "packets_per_sec": current_pps,
                    "bandwidth_kbps": current_kbps,
                    "total_bytes_formatted": formatted_total_bytes,
                    "active_connections": len(self.active_connections),
                    "unique_ips": len(self.unique_ips)
                },
                "charts": {
                    "timeline": {
                        "labels": list(self.timestamps),
                        "bandwidth_kbps": list(self.bandwidth_kbps),
                        "packets_rate": list(self.packets_rate)
                    },
                    "protocols": dict(self.protocol_counts),
                    "top_talkers": top_talkers,
                    "top_ports": top_ports
                },
                "recent_packets": list(self.recent_packets)[-50:]
            }


# Global singleton instance for easy import across modules
global_analyzer = TrafficAnalyzer()
