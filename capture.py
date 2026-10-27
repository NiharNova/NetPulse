"""
NetPulse - Real-Time Network Traffic Analysis System
capture.py - Scapy packet capture manager, OS network interface discovery,
and high-fidelity synthetic traffic generator with cyber attack simulation.
"""

import time
import random
import threading
import socket
from typing import Dict, List, Any, Optional

import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR

from analyzer import global_analyzer, WELL_KNOWN_PORTS
from anomaly import global_anomaly_engine


def get_network_interfaces() -> List[Dict[str, Any]]:
    """
    Discovers available network interfaces across Windows, Linux, and macOS.
    Prepends the virtual Demo Mode interface.
    """
    interfaces = [
        {
            "id": "demo",
            "name": "⚡ DEMO MODE (Synthetic Live Traffic & Attack Simulator)",
            "description": "High-fidelity simulated corporate network traffic with attack injection",
            "ip": "192.168.1.105",
            "is_demo": True
        }
    ]

    # Windows-specific discovery
    try:
        from scapy.arch.windows import get_windows_if_list
        win_list = get_windows_if_list()
        for iface in win_list:
            name = iface.get("name", "")
            desc = iface.get("description", "")
            guid = iface.get("guid", name)
            ips = iface.get("ips", [])
            mac = iface.get("mac", "")

            # Filter out empty or down adapters if desired, but keep active adapters
            ipv4 = next((ip for ip in ips if "." in ip and not ip.startswith("169.254")), ips[0] if ips else "N/A")

            interfaces.append({
                "id": guid,
                "name": f"{name} ({desc})" if desc and desc != name else name,
                "description": desc,
                "ip": ipv4,
                "mac": mac,
                "is_demo": False
            })
        return interfaces
    except Exception:
        pass

    # Generic Scapy interface fallback (Linux / macOS / generic Windows)
    try:
        for iface_name in scapy.get_if_list():
            interfaces.append({
                "id": iface_name,
                "name": str(iface_name),
                "description": "Network Adapter",
                "ip": "Auto-detect",
                "is_demo": False
            })
    except Exception:
        pass

    return interfaces


def dissect_scapy_packet(pkt: Any) -> Dict[str, Any]:
    """
    Deeply dissects a captured Scapy packet into an analytical dictionary
    suitable for Wireshark-like inspection and anomaly heuristics.
    """
    t_str = time.strftime("%H:%M:%S", time.localtime(pkt.time if hasattr(pkt, 'time') else time.time()))
    ms = int((pkt.time % 1) * 1000) if hasattr(pkt, 'time') else int((time.time() % 1) * 1000)
    timestamp = f"{t_str}.{ms:03d}"

    pkt_len = len(pkt)
    summary = pkt.summary() if hasattr(pkt, 'summary') else "Packet"

    info: Dict[str, Any] = {
        "timestamp": timestamp,
        "length": pkt_len,
        "summary": summary,
        "src_mac": "-",
        "dst_mac": "-",
        "src_ip": "-",
        "dst_ip": "-",
        "protocol": "Other",
        "src_port": None,
        "dst_port": None,
        "service": "-",
        "ttl": None,
        "tcp_flags": [],
        "layers": [],
        "details": {}
    }

    # Layer 2: Ethernet / MAC
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        info["src_mac"] = eth.src
        info["dst_mac"] = eth.dst
        info["layers"].append("Ethernet")
        info["details"]["Ethernet"] = {
            "Source MAC": eth.src,
            "Destination MAC": eth.dst,
            "EtherType": hex(eth.type)
        }

    # Layer 2.5: ARP
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        info["protocol"] = "ARP"
        info["src_ip"] = arp.psrc
        info["dst_ip"] = arp.pdst
        info["layers"].append("ARP")
        op_name = "Request (1)" if arp.op == 1 else "Reply (2)" if arp.op == 2 else str(arp.op)
        info["service"] = "ARP"
        info["details"]["ARP"] = {
            "Operation": op_name,
            "Sender MAC": arp.hwsrc,
            "Sender IP": arp.psrc,
            "Target MAC": arp.hwdst,
            "Target IP": arp.pdst
        }
        return info

    # Layer 3: IPv4
    if pkt.haslayer(IP):
        ip = pkt[IP]
        info["src_ip"] = ip.src
        info["dst_ip"] = ip.dst
        info["ttl"] = ip.ttl
        info["layers"].append("IPv4")
        info["details"]["IPv4"] = {
            "Version": ip.version,
            "Header Length (IHL)": f"{ip.ihl * 4} bytes",
            "Total Length": ip.len,
            "Identification": hex(ip.id),
            "Flags": str(ip.flags),
            "Time to Live (TTL)": ip.ttl,
            "Protocol": ip.proto,
            "Checksum": hex(ip.chksum),
            "Source IP": ip.src,
            "Destination IP": ip.dst
        }
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        info["src_ip"] = ip6.src
        info["dst_ip"] = ip6.dst
        info["ttl"] = ip6.hlim
        info["layers"].append("IPv6")
        info["details"]["IPv6"] = {
            "Version": 6,
            "Traffic Class": ip6.tc,
            "Flow Label": ip6.fl,
            "Payload Length": ip6.plen,
            "Next Header": ip6.nh,
            "Hop Limit": ip6.hlim,
            "Source IP": ip6.src,
            "Destination IP": ip6.dst
        }

    # Layer 4: TCP
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        info["src_port"] = tcp.sport
        info["dst_port"] = tcp.dport
        info["protocol"] = "TCP"
        info["layers"].append("TCP")

        # Parse TCP flags
        flags_str = str(tcp.flags)
        flag_list = []
        if "S" in flags_str: flag_list.append("SYN")
        if "A" in flags_str: flag_list.append("ACK")
        if "F" in flags_str: flag_list.append("FIN")
        if "R" in flags_str: flag_list.append("RST")
        if "P" in flags_str: flag_list.append("PSH")
        if "U" in flags_str: flag_list.append("URG")
        info["tcp_flags"] = flag_list

        svc = WELL_KNOWN_PORTS.get(tcp.dport) or WELL_KNOWN_PORTS.get(tcp.sport)
        if svc:
            info["service"] = svc
            if svc in ("HTTP", "HTTP-Proxy", "HTTP-Alt"):
                info["protocol"] = "HTTP"
            elif svc in ("HTTPS", "HTTPS-Alt"):
                info["protocol"] = "HTTPS"

        info["details"]["TCP"] = {
            "Source Port": tcp.sport,
            "Destination Port": tcp.dport,
            "Sequence Number": tcp.seq,
            "Acknowledgment Number": tcp.ack,
            "Data Offset": f"{tcp.dataofs * 4} bytes",
            "Flags": f"{flags_str} ({', '.join(flag_list) if flag_list else 'None'})",
            "Window Size": tcp.window,
            "Checksum": hex(tcp.chksum),
            "Urgent Pointer": tcp.urgptr
        }

    # Layer 4: UDP
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        info["src_port"] = udp.sport
        info["dst_port"] = udp.dport
        info["protocol"] = "UDP"
        info["layers"].append("UDP")

        svc = WELL_KNOWN_PORTS.get(udp.dport) or WELL_KNOWN_PORTS.get(udp.sport)
        if svc:
            info["service"] = svc
            if svc == "DNS":
                info["protocol"] = "DNS"

        info["details"]["UDP"] = {
            "Source Port": udp.sport,
            "Destination Port": udp.dport,
            "Length": udp.len,
            "Checksum": hex(udp.chksum)
        }

    # Layer 4: ICMP
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        info["protocol"] = "ICMP"
        info["service"] = "ICMP Echo" if icmp.type == 8 else "ICMP Reply" if icmp.type == 0 else f"ICMP Type {icmp.type}"
        info["layers"].append("ICMP")
        info["details"]["ICMP"] = {
            "Type": f"{icmp.type} ({info['service']})",
            "Code": icmp.code,
            "Checksum": hex(icmp.chksum),
            "Identifier": getattr(icmp, "id", None),
            "Sequence": getattr(icmp, "seq", None)
        }

    # Layer 7: DNS
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        info["protocol"] = "DNS"
        info["service"] = "DNS"
        info["layers"].append("DNS")
        qname = ""
        qtype = ""
        if dns.qd and isinstance(dns.qd, DNSQR):
            qname = dns.qd.qname.decode('utf-8', errors='ignore') if hasattr(dns.qd.qname, 'decode') else str(dns.qd.qname)
            qtype = str(dns.qd.qtype)

        info["details"]["DNS"] = {
            "Transaction ID": hex(dns.id),
            "Query/Response": "Response" if dns.qr == 1 else "Query",
            "Opcode": dns.opcode,
            "Question": qname,
            "Question Type": qtype,
            "Answer Count": dns.ancount
        }

    # Raw Payload Hex snippet preview
    if hasattr(pkt, 'load') and pkt.load:
        raw_bytes = pkt.load[:32]
        hex_dump = " ".join(f"{b:02x}" for b in raw_bytes)
        ascii_dump = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes)
        info["details"]["Payload"] = {
            "Length": len(pkt.load),
            "Hex Snippet": hex_dump,
            "ASCII Snippet": ascii_dump
        }

    return info


class PacketCaptureManager:
    """
    Manages live Scapy packet sniffing and the high-fidelity Synthetic Traffic Generator.
    Guarantees thread-safe control, graceful stop, and seamless demo fallbacks.
    """

    def __init__(self):
        self.is_running = False
        self.is_demo = False
        self.current_interface = "demo"
        self.capture_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.error_message: Optional[str] = None
        self.packets_captured = 0

    def start_capture(self, interface: str = "demo") -> Dict[str, Any]:
        """
        Starts live capture or demo mode on the specified interface.
        """
        if self.is_running:
            self.stop_capture()

        self.error_message = None
        self.stop_event.clear()
        self.current_interface = interface
        self.packets_captured = 0

        if interface == "demo" or interface.lower() == "synthetic":
            self.is_demo = True
            self.is_running = True
            self.capture_thread = threading.Thread(target=self._run_synthetic_generator, daemon=True)
            self.capture_thread.start()
            return {
                "status": "started",
                "mode": "demo",
                "interface": "DEMO MODE",
                "message": "Demo Mode active. Generating synthetic multi-protocol network traffic."
            }

        # Attempt Live Scapy sniffing
        self.is_demo = False
        self.is_running = True
        self.capture_thread = threading.Thread(target=self._run_live_sniff, args=(interface,), daemon=True)
        self.capture_thread.start()

        # Give the thread 300ms to detect early runtime error (e.g. missing Npcap)
        time.sleep(0.3)
        if not self.is_running and self.error_message:
            # Fallback to Demo Mode automatically
            self.is_demo = True
            self.is_running = True
            self.current_interface = "demo"
            self.capture_thread = threading.Thread(target=self._run_synthetic_generator, daemon=True)
            self.capture_thread.start()
            return {
                "status": "started_with_fallback",
                "mode": "demo",
                "interface": "DEMO MODE",
                "error": self.error_message,
                "message": f"{self.error_message} Automatically activated Demo Mode so you can test all features!"
            }

        return {
            "status": "started",
            "mode": "live",
            "interface": interface,
            "message": f"Live packet capture active on interface {interface}."
        }

    def stop_capture(self) -> Dict[str, Any]:
        """
        Gracefully halts packet capture or synthetic simulation.
        """
        self.stop_event.set()
        self.is_running = False

        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=1.0)

        return {
            "status": "stopped",
            "interface": self.current_interface,
            "packets_captured": self.packets_captured
        }

    def get_status(self) -> Dict[str, Any]:
        """Returns the current operational status of the capture manager."""
        return {
            "is_running": self.is_running,
            "is_demo": self.is_demo,
            "current_interface": self.current_interface,
            "packets_captured": self.packets_captured,
            "error_message": self.error_message
        }

    def _run_live_sniff(self, interface: str):
        """
        Background worker executing Scapy's native sniff().
        """
        try:
            def packet_handler(pkt):
                if self.stop_event.is_set():
                    return True  # Stop filter returns True to stop sniffing
                try:
                    dissected = dissect_scapy_packet(pkt)
                    global_analyzer.process_packet(dissected)
                    global_anomaly_engine.inspect_packet(dissected)
                    self.packets_captured += 1
                except Exception:
                    pass

            # Sniff with stop_filter condition
            scapy.sniff(
                iface=interface if interface != "auto" else None,
                prn=packet_handler,
                stop_filter=lambda p: self.stop_event.is_set(),
                store=False
            )
        except Exception as e:
            err_str = str(e)
            if "winpcap is not installed" in err_str.lower() or "npcap" in err_str.lower():
                self.error_message = "Npcap driver not detected on Windows. Run as Admin or install Npcap in WinPcap mode."
            elif "permission" in err_str.lower() or "access is denied" in err_str.lower():
                self.error_message = "Administrator / root privileges required for raw packet sniffing."
            else:
                self.error_message = f"Capture initialization error: {err_str}"
            self.is_running = False

    def _run_synthetic_generator(self):
        """
        High-fidelity realistic synthetic network traffic generator.
        Simulates authentic enterprise and web communication across protocols.
        """
        local_ips = [
            "192.168.1.105", "192.168.1.112", "192.168.1.140",
            "192.168.1.155", "192.168.1.189", "10.0.0.12", "10.0.0.45"
        ]
        gateway_ip = "192.168.1.1"
        dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        cloud_servers = [
            ("142.250.190.46", 443, "HTTPS"),
            ("104.244.42.1", 443, "HTTPS"),
            ("151.101.65.140", 80, "HTTP"),
            ("185.199.108.153", 443, "HTTPS"),
            ("198.51.100.22", 22, "SSH"),
            ("192.168.1.200", 3389, "RDP"),
            ("10.0.0.50", 5432, "PostgreSQL")
        ]
        domains = ["google.com", "github.com", "cloudflare.com", "mit.edu", "internal.corp", "api.stripe.com"]

        auto_attack_timer = time.time() + 45.0  # Periodic attack injection every 45s

        while not self.stop_event.is_set():
            # Periodic autonomous attack demo
            now = time.time()
            if now > auto_attack_timer:
                auto_attack_timer = now + 50.0
                attack_type = random.choice(["port_scan", "syn_flood", "icmp_flood", "dns_spike"])
                self.simulate_attack(attack_type)

            # Generate batch of 2-5 realistic packets per cycle
            batch_size = random.randint(2, 6)
            for _ in range(batch_size):
                if self.stop_event.is_set():
                    break

                t_str = time.strftime("%H:%M:%S", time.localtime(now))
                ms = int((now % 1) * 1000)
                timestamp = f"{t_str}.{ms:03d}"

                traffic_category = random.choices(
                    ["https", "dns", "http", "internal_tcp", "icmp", "arp"],
                    weights=[45, 20, 15, 10, 5, 5]
                )[0]

                pkt_dict: Dict[str, Any] = {
                    "timestamp": timestamp,
                    "length": random.randint(64, 1460),
                    "summary": "",
                    "src_mac": "00:50:56:c0:00:08",
                    "dst_mac": "00:50:56:c0:00:01",
                    "src_ip": random.choice(local_ips),
                    "dst_ip": gateway_ip,
                    "protocol": "TCP",
                    "src_port": random.randint(49152, 65535),
                    "dst_port": 443,
                    "service": "HTTPS",
                    "ttl": random.choice([64, 128]),
                    "tcp_flags": ["ACK"],
                    "layers": ["Ethernet", "IPv4", "TCP"],
                    "details": {}
                }

                if traffic_category == "https":
                    server_ip, port, svc = random.choice([c for c in cloud_servers if c[2] == "HTTPS"])
                    pkt_dict["dst_ip"] = server_ip
                    pkt_dict["dst_port"] = port
                    pkt_dict["service"] = svc
                    pkt_dict["protocol"] = "HTTPS"
                    pkt_dict["length"] = random.randint(400, 1480)
                    pkt_dict["tcp_flags"] = random.choice([["ACK"], ["PSH", "ACK"], ["ACK"]])
                    pkt_dict["summary"] = f"HTTPS {pkt_dict['src_ip']}:{pkt_dict['src_port']} -> {server_ip}:443 [{','.join(pkt_dict['tcp_flags'])}] Len={pkt_dict['length']}"
                    pkt_dict["details"] = {
                        "Ethernet": {"Source MAC": "00:50:56:c0:00:08", "Destination MAC": "00:50:56:c0:00:01"},
                        "IPv4": {"Source IP": pkt_dict["src_ip"], "Destination IP": server_ip, "TTL": pkt_dict["ttl"], "Protocol": 6},
                        "TCP": {"Source Port": pkt_dict["src_port"], "Destination Port": 443, "Flags": ",".join(pkt_dict["tcp_flags"])},
                        "TLS": {"Version": "TLSv1.3", "Content Type": "Application Data (23)", "Length": pkt_dict["length"] - 54}
                    }

                elif traffic_category == "dns":
                    server_ip = random.choice(dns_servers)
                    pkt_dict["dst_ip"] = server_ip
                    pkt_dict["dst_port"] = 53
                    pkt_dict["protocol"] = "DNS"
                    pkt_dict["service"] = "DNS"
                    pkt_dict["layers"] = ["Ethernet", "IPv4", "UDP", "DNS"]
                    domain = random.choice(domains)
                    pkt_dict["length"] = random.randint(68, 128)
                    pkt_dict["summary"] = f"DNS Standard query 0x{random.randint(1000, 9999):x} A {domain}"
                    pkt_dict["details"] = {
                        "Ethernet": {"Source MAC": "00:50:56:c0:00:08", "Destination MAC": "00:50:56:c0:00:01"},
                        "IPv4": {"Source IP": pkt_dict["src_ip"], "Destination IP": server_ip, "TTL": 64, "Protocol": 17},
                        "UDP": {"Source Port": pkt_dict["src_port"], "Destination Port": 53, "Length": pkt_dict["length"] - 34},
                        "DNS": {"Query": domain, "Type": "A (Host Address)", "Class": "IN (0x0001)", "QR": "Query"}
                    }

                elif traffic_category == "http":
                    pkt_dict["dst_ip"] = "151.101.65.140"
                    pkt_dict["dst_port"] = 80
                    pkt_dict["protocol"] = "HTTP"
                    pkt_dict["service"] = "HTTP"
                    pkt_dict["length"] = random.randint(250, 900)
                    pkt_dict["tcp_flags"] = ["PSH", "ACK"]
                    pkt_dict["summary"] = f"HTTP GET /api/v1/telemetry HTTP/1.1 from {pkt_dict['src_ip']}"
                    pkt_dict["details"] = {
                        "IPv4": {"Source IP": pkt_dict["src_ip"], "Destination IP": "151.101.65.140", "TTL": 64},
                        "TCP": {"Source Port": pkt_dict["src_port"], "Destination Port": 80, "Flags": "PSH, ACK"},
                        "HTTP": {"Method": "GET", "URI": "/api/v1/telemetry", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                    }

                elif traffic_category == "internal_tcp":
                    server_ip, port, svc = random.choice([c for c in cloud_servers if c[2] in ("SSH", "RDP", "PostgreSQL")])
                    pkt_dict["dst_ip"] = server_ip
                    pkt_dict["dst_port"] = port
                    pkt_dict["service"] = svc
                    pkt_dict["protocol"] = "TCP"
                    pkt_dict["length"] = random.randint(90, 600)
                    pkt_dict["summary"] = f"TCP {pkt_dict['src_ip']}:{pkt_dict['src_port']} -> {server_ip}:{port} [{svc}]"
                    pkt_dict["details"] = {
                        "IPv4": {"Source IP": pkt_dict["src_ip"], "Destination IP": server_ip, "TTL": 64},
                        "TCP": {"Source Port": pkt_dict["src_port"], "Destination Port": port, "Flags": "ACK"}
                    }

                elif traffic_category == "icmp":
                    pkt_dict["dst_ip"] = "8.8.8.8"
                    pkt_dict["protocol"] = "ICMP"
                    pkt_dict["service"] = "ICMP Echo"
                    pkt_dict["layers"] = ["Ethernet", "IPv4", "ICMP"]
                    pkt_dict["length"] = 74
                    pkt_dict["summary"] = f"ICMP Echo (ping) request from {pkt_dict['src_ip']} to 8.8.8.8 id=0x{random.randint(1,999):04x}"
                    pkt_dict["details"] = {
                        "IPv4": {"Source IP": pkt_dict["src_ip"], "Destination IP": "8.8.8.8", "TTL": 64, "Protocol": 1},
                        "ICMP": {"Type": "8 (Echo Request)", "Code": 0, "Sequence": random.randint(1, 100)}
                    }

                elif traffic_category == "arp":
                    pkt_dict["protocol"] = "ARP"
                    pkt_dict["service"] = "ARP"
                    pkt_dict["dst_ip"] = gateway_ip
                    pkt_dict["layers"] = ["Ethernet", "ARP"]
                    pkt_dict["length"] = 60
                    pkt_dict["summary"] = f"ARP Who has {gateway_ip}? Tell {pkt_dict['src_ip']}"
                    pkt_dict["details"] = {
                        "ARP": {"Sender IP": pkt_dict["src_ip"], "Target IP": gateway_ip, "Op": "Request (1)"}
                    }

                global_analyzer.process_packet(pkt_dict)
                global_anomaly_engine.inspect_packet(pkt_dict)
                self.packets_captured += 1

            # Sleep 100ms - 250ms between cycles (yielding ~20-50 packets/sec)
            time.sleep(random.uniform(0.10, 0.22))

    def simulate_attack(self, attack_type: str) -> Dict[str, Any]:
        """
        Manually or autonomously injects attack traffic signatures to demonstrate
        real-time alert triggering and graph deviations.
        """
        attack_type = attack_type.lower()
        now = time.time()
        t_str = time.strftime("%H:%M:%S", time.localtime(now))
        attacker_ip = "192.168.1.189"
        target_ip = "192.168.1.10"

        if attack_type == "port_scan":
            # Rapidly hit 24 distinct destination ports
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9090, 27017]
            for p in ports:
                pkt = {
                    "timestamp": f"{t_str}.{random.randint(100, 999)}",
                    "length": 60,
                    "summary": f"TCP {attacker_ip}:{random.randint(40000, 60000)} -> {target_ip}:{p} [SYN] Port Probe",
                    "src_mac": "00:0c:29:4f:8e:1a",
                    "dst_mac": "00:50:56:c0:00:01",
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "protocol": "TCP",
                    "src_port": random.randint(40000, 60000),
                    "dst_port": p,
                    "service": WELL_KNOWN_PORTS.get(p, f"Port {p}"),
                    "ttl": 64,
                    "tcp_flags": ["SYN"],
                    "layers": ["Ethernet", "IPv4", "TCP"],
                    "details": {
                        "IPv4": {"Source IP": attacker_ip, "Destination IP": target_ip, "TTL": 64},
                        "TCP": {"Destination Port": p, "Flags": "SYN", "Window": 1024}
                    }
                }
                global_analyzer.process_packet(pkt)
                global_anomaly_engine.inspect_packet(pkt)
                self.packets_captured += 1
            return {"status": "success", "attack": "port_scan", "message": "Injected 24-port reconnaissance scan from 192.168.1.189"}

        elif attack_type == "syn_flood":
            # Rapidly fire 45 SYN packets with no ACKs
            for _ in range(45):
                sport = random.randint(30000, 65000)
                pkt = {
                    "timestamp": f"{t_str}.{random.randint(100, 999)}",
                    "length": 60,
                    "summary": f"TCP {attacker_ip}:{sport} -> {target_ip}:80 [SYN] Flood Vector",
                    "src_mac": "00:0c:29:4f:8e:1a",
                    "dst_mac": "00:50:56:c0:00:01",
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "protocol": "TCP",
                    "src_port": sport,
                    "dst_port": 80,
                    "service": "HTTP",
                    "ttl": 64,
                    "tcp_flags": ["SYN"],
                    "layers": ["Ethernet", "IPv4", "TCP"],
                    "details": {
                        "IPv4": {"Source IP": attacker_ip, "Destination IP": target_ip},
                        "TCP": {"Source Port": sport, "Destination Port": 80, "Flags": "SYN"}
                    }
                }
                global_analyzer.process_packet(pkt)
                global_anomaly_engine.inspect_packet(pkt)
                self.packets_captured += 1
            return {"status": "success", "attack": "syn_flood", "message": "Injected 45-packet TCP SYN flood against port 80"}

        elif attack_type == "icmp_flood":
            # Rapidly fire 35 ICMP Echo Requests
            for i in range(35):
                pkt = {
                    "timestamp": f"{t_str}.{random.randint(100, 999)}",
                    "length": 84,
                    "summary": f"ICMP Echo Request flood from {attacker_ip} seq={i}",
                    "src_mac": "00:0c:29:4f:8e:1a",
                    "dst_mac": "00:50:56:c0:00:01",
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "protocol": "ICMP",
                    "src_port": None,
                    "dst_port": None,
                    "service": "ICMP Echo",
                    "ttl": 64,
                    "tcp_flags": [],
                    "layers": ["Ethernet", "IPv4", "ICMP"],
                    "details": {
                        "IPv4": {"Source IP": attacker_ip, "Destination IP": target_ip},
                        "ICMP": {"Type": "8 (Echo Request)", "Sequence": i}
                    }
                }
                global_analyzer.process_packet(pkt)
                global_anomaly_engine.inspect_packet(pkt)
                self.packets_captured += 1
            return {"status": "success", "attack": "icmp_flood", "message": "Injected ICMP echo ping flood from 192.168.1.189"}

        elif attack_type == "dns_spike":
            # Rapidly fire 45 DNS queries
            for i in range(45):
                rnd_sub = f"attack{i}.tunneling.malware.org"
                pkt = {
                    "timestamp": f"{t_str}.{random.randint(100, 999)}",
                    "length": 112,
                    "summary": f"DNS Query {rnd_sub} to 8.8.8.8:53",
                    "src_mac": "00:0c:29:4f:8e:1a",
                    "dst_mac": "00:50:56:c0:00:01",
                    "src_ip": attacker_ip,
                    "dst_ip": "8.8.8.8",
                    "protocol": "DNS",
                    "src_port": random.randint(40000, 60000),
                    "dst_port": 53,
                    "service": "DNS",
                    "ttl": 64,
                    "tcp_flags": [],
                    "layers": ["Ethernet", "IPv4", "UDP", "DNS"],
                    "details": {
                        "IPv4": {"Source IP": attacker_ip, "Destination IP": "8.8.8.8"},
                        "DNS": {"Query": rnd_sub, "Type": "TXT", "QR": "Query"}
                    }
                }
                global_analyzer.process_packet(pkt)
                global_anomaly_engine.inspect_packet(pkt)
                self.packets_captured += 1
            return {"status": "success", "attack": "dns_spike", "message": "Injected 45-query DNS tunneling spike"}

        return {"status": "error", "message": f"Unknown attack type: {attack_type}"}


# Global singleton capture manager
global_capture_manager = PacketCaptureManager()
