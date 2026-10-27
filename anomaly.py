"""
NetPulse - Real-Time Network Traffic Analysis System
anomaly.py - Statistical anomaly detection (Z-score baseline)
and heuristic rule-based attack engine with SQLite persistence & CSV export.
"""

import math
import time
import sqlite3
import threading
from io import StringIO
import csv
from collections import deque, defaultdict
from typing import Dict, List, Any, Optional

DB_FILE = "alerts.db"


class AnomalyEngine:
    """
    Combines statistical rolling-window baseline anomaly detection with
    rule-based heuristic IDS (Port Scan, SYN Flood, ICMP Flood, DNS Spike, Jumbo Size).
    """

    def __init__(self, baseline_window: int = 30):
        self.lock = threading.RLock()
        self.baseline_window = baseline_window

        # Rolling history for statistical baseline (last 30-60 1-second ticks)
        self.history_pps: deque = deque(maxlen=baseline_window)
        self.history_bps: deque = deque(maxlen=baseline_window)

        # Rule tracking sliding windows:
        # Port scan tracker: src_ip -> deque of (timestamp, dst_port)
        self.port_scan_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

        # SYN flood tracker: src_ip -> {'syn': count, 'ack': count, 'window_start': time}
        self.syn_tracker: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"syn": 0, "ack": 0, "last_reset": time.time()})

        # ICMP flood tracker: src_ip -> deque of timestamps
        self.icmp_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=150))

        # DNS spike tracker: deque of timestamps for port 53 packets
        self.dns_tracker: deque = deque(maxlen=200)

        # Alert deduplication suppression: (alert_type, src_ip) -> last_alert_time
        self.alert_suppression: Dict[tuple, float] = {}

        # In-memory recent alerts cache
        self.recent_alerts: deque = deque(maxlen=100)
        self.total_alerts_count = 0

        # Initialize SQLite database
        self._init_db()

    def _init_db(self):
        """Initializes the SQLite database table for alert audit logs."""
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    source_ip TEXT,
                    target_ip TEXT,
                    details TEXT NOT NULL,
                    score REAL DEFAULT 0.0
                )
            """)
            conn.commit()

            # Read existing count
            cursor.execute("SELECT COUNT(*) FROM alerts")
            row = cursor.fetchone()
            self.total_alerts_count = row[0] if row else 0

    def log_alert(self, severity: str, alert_type: str, details: str,
                  source_ip: str = "Unknown", target_ip: str = "N/A", score: float = 0.0) -> Optional[Dict[str, Any]]:
        """
        Record an alert into SQLite and memory, with rate suppression to prevent alert flooding.
        """
        now = time.time()
        suppression_key = (alert_type, source_ip)

        # Suppress identical alert types from same source within 3 seconds
        if suppression_key in self.alert_suppression:
            if now - self.alert_suppression[suppression_key] < 3.0:
                return None

        self.alert_suppression[suppression_key] = now
        t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))

        alert_entry = {
            "timestamp": t_str,
            "severity": severity.upper(),
            "alert_type": alert_type,
            "source_ip": source_ip or "Unknown",
            "target_ip": target_ip or "N/A",
            "details": details,
            "score": round(score, 2)
        }

        # Write to SQLite
        try:
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO alerts (timestamp, severity, alert_type, source_ip, target_ip, details, score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_entry["timestamp"],
                    alert_entry["severity"],
                    alert_entry["alert_type"],
                    alert_entry["source_ip"],
                    alert_entry["target_ip"],
                    alert_entry["details"],
                    alert_entry["score"]
                ))
                conn.commit()
                alert_entry["id"] = cursor.lastrowid
        except Exception as e:
            alert_entry["id"] = self.total_alerts_count + 1

        with self.lock:
            self.total_alerts_count += 1
            self.recent_alerts.appendleft(alert_entry)

        return alert_entry

    def update_baseline_tick(self, current_pps: int, current_bps: float) -> Optional[Dict[str, Any]]:
        """
        Called every 1 second with current rates to update baseline and compute Z-score anomalies.
        Formula: Z = (X - Mean) / StdDev. Flags anomaly when |Z| > 3.0.
        """
        alert = None
        with self.lock:
            # Need at least 10 baseline samples before computing statistical significance
            if len(self.history_pps) >= 10:
                mean_pps = sum(self.history_pps) / len(self.history_pps)
                var_pps = sum((x - mean_pps) ** 2 for x in self.history_pps) / len(self.history_pps)
                std_pps = math.sqrt(var_pps)

                mean_bps = sum(self.history_bps) / len(self.history_bps)
                var_bps = sum((x - mean_bps) ** 2 for x in self.history_bps) / len(self.history_bps)
                std_bps = math.sqrt(var_bps)

                # Avoid division by zero or triggers on near-zero idle jitter
                if std_pps > 3.0 and current_pps > 15:
                    z_pps = (current_pps - mean_pps) / std_pps
                    if z_pps > 3.0:
                        alert = self.log_alert(
                            severity="HIGH" if z_pps > 4.5 else "MEDIUM",
                            alert_type="Statistical Packet Rate Spike",
                            details=f"Packet rate surge: {current_pps} pps (baseline mean={round(mean_pps, 1)}, σ={round(std_pps, 1)}, Z-Score={round(z_pps, 2)} > 3.0)",
                            source_ip="Cluster",
                            target_ip="Local Subnet",
                            score=z_pps
                        )

                if std_bps > 50.0 and current_bps > 200.0:
                    z_bps = (current_bps - mean_bps) / std_bps
                    if z_bps > 3.0 and not alert:
                        alert = self.log_alert(
                            severity="HIGH" if z_bps > 4.5 else "MEDIUM",
                            alert_type="Statistical Bandwidth Surge",
                            details=f"Bandwidth surge: {round(current_bps, 1)} KB/s (baseline mean={round(mean_bps, 1)}, σ={round(std_bps, 1)}, Z-Score={round(z_bps, 2)} > 3.0)",
                            source_ip="Cluster",
                            target_ip="Local Subnet",
                            score=z_bps
                        )

            # Append current rate to rolling window
            self.history_pps.append(current_pps)
            self.history_bps.append(current_bps)

        return alert

    def inspect_packet(self, pkt: Dict[str, Any]):
        """
        Examines single packet headers against rule-based IDS heuristics.
        """
        now = time.time()
        proto = pkt.get("protocol", "Other")
        src_ip = pkt.get("src_ip", "")
        dst_ip = pkt.get("dst_ip", "")
        dst_port = pkt.get("dst_port")
        length = pkt.get("length", 0)
        tcp_flags = pkt.get("tcp_flags", [])

        if not src_ip or src_ip in ("0.0.0.0", "-", ""):
            return

        with self.lock:
            # 1. Unusual Packet Size Spike (Jumbo frame or abnormally large L3 payload)
            if length > 1514:
                self.log_alert(
                    severity="LOW",
                    alert_type="Unusual Packet Size",
                    details=f"Oversized frame detected: {length} bytes (exceeds standard Ethernet MTU 1500)",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    score=length / 1500.0
                )

            # 2. Rule: Port Scan Detection
            # One source IP probing > 15 distinct destination ports within a 5-second window
            if dst_port is not None and dst_port > 0:
                tracker = self.port_scan_tracker[src_ip]
                tracker.append((now, dst_port))

                # Prune entries older than 5 seconds
                while tracker and now - tracker[0][0] > 5.0:
                    tracker.popleft()

                distinct_ports = {p for _, p in tracker}
                if len(distinct_ports) >= 15:
                    self.log_alert(
                        severity="HIGH",
                        alert_type="Port Scan Detected",
                        details=f"Host probed {len(distinct_ports)} distinct ports within 5s window (Target: {dst_ip})",
                        source_ip=src_ip,
                        target_ip=dst_ip,
                        score=float(len(distinct_ports))
                    )

            # 3. Rule: TCP SYN Flood Detection
            # Detects high volume of SYN packets without corresponding ACKs
            if proto == "TCP":
                syn_data = self.syn_tracker[src_ip]
                # Reset window every 5 seconds
                if now - syn_data["last_reset"] > 5.0:
                    syn_data["syn"] = 0
                    syn_data["ack"] = 0
                    syn_data["last_reset"] = now

                if "SYN" in tcp_flags and "ACK" not in tcp_flags:
                    syn_data["syn"] += 1
                elif "ACK" in tcp_flags:
                    syn_data["ack"] += 1

                if syn_data["syn"] > 25 and (syn_data["syn"] / max(syn_data["ack"], 1)) > 5.0:
                    self.log_alert(
                        severity="HIGH",
                        alert_type="SYN Flood Attack",
                        details=f"SYN flood signature: {syn_data['syn']} SYN requests with only {syn_data['ack']} ACKs in 5s",
                        source_ip=src_ip,
                        target_ip=dst_ip,
                        score=float(syn_data["syn"])
                    )

            # 4. Rule: ICMP Flood Detection (Ping flood / Smurf attempt)
            if proto == "ICMP":
                icmp_queue = self.icmp_tracker[src_ip]
                icmp_queue.append(now)

                # Prune older than 2 seconds
                while icmp_queue and now - icmp_queue[0] > 2.0:
                    icmp_queue.popleft()

                if len(icmp_queue) > 30:
                    self.log_alert(
                        severity="MEDIUM",
                        alert_type="ICMP Echo Flood",
                        details=f"ICMP flood detected: {len(icmp_queue)} echo packets in 2s window",
                        source_ip=src_ip,
                        target_ip=dst_ip,
                        score=float(len(icmp_queue))
                    )

            # 5. Rule: DNS Spike Detection
            if dst_port == 53 or proto == "DNS":
                self.dns_tracker.append(now)
                while self.dns_tracker and now - self.dns_tracker[0] > 3.0:
                    self.dns_tracker.popleft()

                if len(self.dns_tracker) > 40:
                    self.log_alert(
                        severity="MEDIUM",
                        alert_type="DNS Query Spike",
                        details=f"Abnormal DNS query surge: {len(self.dns_tracker)} queries in 3s (possible amplification or tunneling)",
                        source_ip=src_ip,
                        target_ip=dst_ip,
                        score=float(len(self.dns_tracker))
                    )

    def get_recent_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Fetch alerts from SQLite with optional severity filtering.
        """
        query = "SELECT id, timestamp, severity, alert_type, source_ip, target_ip, details, score FROM alerts"
        params: List[Any] = []
        if severity and severity.upper() in ("LOW", "MEDIUM", "HIGH"):
            query += " WHERE severity = ?"
            params.append(severity.upper())

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        results = []
        try:
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                for row in cursor.fetchall():
                    results.append({
                        "id": row[0],
                        "timestamp": row[1],
                        "severity": row[2],
                        "alert_type": row[3],
                        "source_ip": row[4],
                        "target_ip": row[5],
                        "details": row[6],
                        "score": row[7]
                    })
        except Exception:
            with self.lock:
                results = list(self.recent_alerts)[:limit]

        return results

    def export_alerts_csv(self) -> str:
        """
        Exports all logged alerts from SQLite into a CSV string.
        """
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Timestamp", "Severity", "Alert Type", "Source IP", "Target IP", "Details", "Score"])

        try:
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, timestamp, severity, alert_type, source_ip, target_ip, details, score FROM alerts ORDER BY id ASC")
                for row in cursor.fetchall():
                    writer.writerow(row)
        except Exception as e:
            writer.writerow(["Error reading alerts DB", str(e)])

        return output.getvalue()

    def clear_alerts(self):
        """Purges alerts table and resets internal counters."""
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM alerts")
            conn.commit()

        with self.lock:
            self.recent_alerts.clear()
            self.total_alerts_count = 0
            self.alert_suppression.clear()


# Global singleton instance
global_anomaly_engine = AnomalyEngine()
