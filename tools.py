"""
NetPulse - Real-Time Network Traffic Analysis System
tools.py - Network Toolkit utilities: Subnet Calculator, VLSM Planner,
IP/Binary/Hex Converter, and sanitized Ping, DNS, Traceroute diagnostics.
"""

import re
import socket
import struct
import platform
import subprocess
import ipaddress
from typing import Dict, List, Any, Optional


def sanitize_hostname_or_ip(target: str) -> str:
    """
    Strictly validates and sanitizes a hostname or IP string.
    Rejects any characters that could lead to command injection.
    """
    target = target.strip()
    if not target or len(target) > 253:
        raise ValueError("Invalid target length")

    # Allow only standard hostname and IP characters: a-z, 0-9, dots, hyphens
    if not re.match(r"^[a-zA-Z0-9.\-_]+$", target):
        raise ValueError("Target contains illegal characters. Only alphanumeric, dots, and hyphens are permitted.")

    return target


def calculate_subnet(ip_cidr_or_mask: str) -> Dict[str, Any]:
    """
    Computes comprehensive subnet breakdown, usable range, binary masks, and IP classes.
    Accepts formats like: '192.168.1.50/24' or '10.0.0.1/255.255.0.0'.
    """
    try:
        # Handle slash or space separation
        cleaned = ip_cidr_or_mask.strip()
        if " " in cleaned:
            parts = cleaned.split()
            cleaned = f"{parts[0]}/{parts[1]}"

        # Parse IPv4 network with host bits preserved
        interface = ipaddress.IPv4Interface(cleaned)
        network = interface.network
        ip = interface.ip

        netmask_int = int(network.netmask)
        wildcard_int = ~netmask_int & 0xFFFFFFFF
        wildcard_str = socket.inet_ntoa(struct.pack("!I", wildcard_int))

        total_hosts = network.num_addresses
        usable_hosts = max(0, total_hosts - 2) if network.prefixlen < 31 else (2 if network.prefixlen == 31 else 1)

        first_host = str(network.network_address + 1) if usable_hosts > 0 else str(network.network_address)
        last_host = str(network.broadcast_address - 1) if usable_hosts > 0 else str(network.broadcast_address)

        # Determine IP class
        first_octet = int(str(ip).split(".")[0])
        if first_octet <= 127:
            ip_class = "Class A"
        elif first_octet <= 191:
            ip_class = "Class B"
        elif first_octet <= 223:
            ip_class = "Class C"
        elif first_octet <= 239:
            ip_class = "Class D (Multicast)"
        else:
            ip_class = "Class E (Experimental)"

        # Binary representations
        ip_bin = ".".join(f"{int(octet):08b}" for octet in str(ip).split("."))
        mask_bin = ".".join(f"{int(octet):08b}" for octet in str(network.netmask).split("."))
        wildcard_bin = ".".join(f"{int(octet):08b}" for octet in wildcard_str.split("."))
        net_bin = ".".join(f"{int(octet):08b}" for octet in str(network.network_address).split("."))
        bcast_bin = ".".join(f"{int(octet):08b}" for octet in str(network.broadcast_address).split("."))

        # Hex representations
        ip_hex = f"0x{int(ip):08X}"
        mask_hex = f"0x{netmask_int:08X}"

        return {
            "success": True,
            "ip_address": str(ip),
            "cidr": f"/{network.prefixlen}",
            "netmask": str(network.netmask),
            "wildcard_mask": wildcard_str,
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "usable_host_range": f"{first_host} - {last_host}" if usable_hosts > 1 else str(ip),
            "usable_hosts": usable_hosts,
            "total_hosts": total_hosts,
            "ip_class": ip_class,
            "is_private": ip.is_private,
            "is_loopback": ip.is_loopback,
            "binary": {
                "ip": ip_bin,
                "netmask": mask_bin,
                "wildcard": wildcard_bin,
                "network": net_bin,
                "broadcast": bcast_bin
            },
            "hex": {
                "ip": ip_hex,
                "netmask": mask_hex,
                "integer_val": int(ip)
            }
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Subnet calculation error: {str(e)}"
        }


def plan_vlsm(major_network_str: str, subnets_req: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes optimal Variable Length Subnet Masking (VLSM) allocation.
    subnets_req is a list of {'name': 'Subnet A', 'hosts': 50}.
    """
    try:
        major_net = ipaddress.IPv4Network(major_network_str.strip(), strict=False)

        # Sort subnets descending by host requirements
        sorted_subnets = sorted(
            subnets_req,
            key=lambda x: int(x.get("hosts", 0)),
            reverse=True
        )

        allocated = []
        current_addr = int(major_net.network_address)
        major_end = int(major_net.broadcast_address)

        for item in sorted_subnets:
            name = item.get("name", "Unnamed Subnet")
            needed_hosts = max(1, int(item.get("hosts", 1)))

            # Calculate required host bits h: 2^h - 2 >= needed_hosts
            # For 1 host or 2 hosts, prefixlen 30 gives 2 usable hosts
            h = 2
            while (2 ** h - 2) < needed_hosts:
                h += 1

            prefix = 32 - h
            block_size = 2 ** h

            # Align to subnet boundary
            if current_addr % block_size != 0:
                current_addr = ((current_addr // block_size) + 1) * block_size

            net_addr = ipaddress.IPv4Address(current_addr)
            sub_net = ipaddress.IPv4Network(f"{net_addr}/{prefix}")

            if int(sub_net.broadcast_address) > major_end:
                return {
                    "success": False,
                    "error": f"Address exhaustion: Major network {major_network_str} is too small to accommodate all requested subnets."
                }

            usable_range = f"{sub_net.network_address + 1} - {sub_net.broadcast_address - 1}"
            allocated.append({
                "name": name,
                "needed_hosts": needed_hosts,
                "allocated_hosts": 2 ** h - 2,
                "prefix": f"/{prefix}",
                "netmask": str(sub_net.netmask),
                "network_address": str(sub_net.network_address),
                "usable_range": usable_range,
                "broadcast_address": str(sub_net.broadcast_address)
            })

            current_addr = int(sub_net.broadcast_address) + 1

        return {
            "success": True,
            "major_network": str(major_net),
            "subnets": allocated,
            "total_allocated": len(allocated)
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"VLSM planning error: {str(e)}"
        }


def convert_ip_format(value_str: str) -> Dict[str, Any]:
    """
    Converts between Dotted Decimal, 32-bit Integer, Hexadecimal, and Binary.
    """
    v = value_str.strip()
    try:
        # Check if hex format (e.g. 0xC0A80101 or C0A80101)
        if v.lower().startswith("0x") or (len(v) == 8 and all(c in "0123456789abcdefABCDEF" for c in v)):
            int_val = int(v, 16)
            ip_obj = ipaddress.IPv4Address(int_val)
        # Check if 32-bit integer string
        elif v.isdigit() and int(v) <= 0xFFFFFFFF:
            int_val = int(v)
            ip_obj = ipaddress.IPv4Address(int_val)
        # Check if binary string (32 bits or dot-separated binary octets)
        elif all(c in "01." for c in v) and len(v.replace(".", "")) == 32:
            bits = v.replace(".", "")
            int_val = int(bits, 2)
            ip_obj = ipaddress.IPv4Address(int_val)
        # Standard IPv4 dotted string
        else:
            ip_obj = ipaddress.IPv4Address(v)
            int_val = int(ip_obj)

        octets = str(ip_obj).split(".")
        bin_str = ".".join(f"{int(o):08b}" for o in octets)
        hex_str = f"0x{int_val:08X}"

        return {
            "success": True,
            "dotted_decimal": str(ip_obj),
            "integer_32": int_val,
            "hexadecimal": hex_str,
            "binary_dotted": bin_str,
            "binary_flat": bin_str.replace(".", "")
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"IP conversion failed: {str(e)}"
        }


def run_ping(target_host: str, count: int = 4) -> Dict[str, Any]:
    """
    Executes a sanitized ping command with structured output parsing.
    """
    try:
        sanitized_host = sanitize_hostname_or_ip(target_host)
        count = max(1, min(10, count))

        is_win = platform.system().lower() == "windows"
        cmd = ["ping", "-n", str(count), sanitized_host] if is_win else ["ping", "-c", str(count), sanitized_host]

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
        output = proc.stdout

        # Parse RTT and loss
        loss_match = re.search(r"(\d+)% loss", output, re.IGNORECASE)
        loss_pct = int(loss_match.group(1)) if loss_match else 0

        # Windows latency parsing
        avg_rtt = None
        min_rtt = None
        max_rtt = None
        if is_win:
            rtt_match = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", output)
            if rtt_match:
                min_rtt = int(rtt_match.group(1))
                max_rtt = int(rtt_match.group(2))
                avg_rtt = int(rtt_match.group(3))
        else:
            rtt_match = re.search(r"min/avg/max[^=]*= ([\d.]+)/([\d.]+)/([\d.]+)", output)
            if rtt_match:
                min_rtt = float(rtt_match.group(1))
                avg_rtt = float(rtt_match.group(2))
                max_rtt = float(rtt_match.group(3))

        return {
            "success": proc.returncode == 0 or loss_pct < 100,
            "target": sanitized_host,
            "packet_loss_pct": loss_pct,
            "min_rtt_ms": min_rtt,
            "avg_rtt_ms": avg_rtt,
            "max_rtt_ms": max_rtt,
            "raw_output": output
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Ping execution error: {str(e)}"
        }


def run_dns_lookup(target_host: str, record_type: str = "A") -> Dict[str, Any]:
    """
    Resolves standard DNS records safely using Python's socket interface or dnspython if present.
    """
    try:
        sanitized_host = sanitize_hostname_or_ip(target_host)
        record_type = record_type.upper()

        records = []
        # Standard A record resolution via getaddrinfo
        if record_type in ("A", "ALL"):
            try:
                addr_info = socket.getaddrinfo(sanitized_host, 80, socket.AF_INET, socket.SOCK_STREAM)
                for item in addr_info:
                    ip = item[4][0]
                    if ip not in records:
                        records.append({"type": "A", "value": ip})
            except Exception:
                pass

        if record_type in ("AAAA", "ALL"):
            try:
                addr_info6 = socket.getaddrinfo(sanitized_host, 80, socket.AF_INET6, socket.SOCK_STREAM)
                for item in addr_info6:
                    ip6 = item[4][0]
                    if ip6 not in [r["value"] for r in records]:
                        records.append({"type": "AAAA", "value": ip6})
            except Exception:
                pass

        # Reverse PTR lookup if IP supplied
        try:
            ipaddress.ip_address(sanitized_host)
            host, _, _ = socket.gethostbyaddr(sanitized_host)
            records.append({"type": "PTR", "value": host})
        except Exception:
            pass

        return {
            "success": len(records) > 0,
            "target": sanitized_host,
            "query_type": record_type,
            "records": records if records else [{"type": record_type, "value": "No records found or lookup timed out"}]
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"DNS lookup error: {str(e)}"
        }


def run_traceroute(target_host: str, max_hops: int = 15) -> Dict[str, Any]:
    """
    Executes a sanitized traceroute command with bounded hops.
    """
    try:
        sanitized_host = sanitize_hostname_or_ip(target_host)
        max_hops = max(1, min(20, max_hops))

        is_win = platform.system().lower() == "windows"
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "800", sanitized_host] if is_win else ["traceroute", "-n", "-m", str(max_hops), "-w", "1", sanitized_host]

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        output = proc.stdout

        # Parse hops
        hops = []
        lines = output.splitlines()
        for line in lines:
            # Pattern matching hop lines: e.g. "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
            match = re.search(r"^\s*(\d+)\s+([<\d\s.ms*]+?)\s+([0-9a-fA-F:.]+)\s*$", line)
            if match:
                hop_num = int(match.group(1))
                rtt_part = match.group(2).strip()
                hop_ip = match.group(3).strip()
                hops.append({
                    "hop": hop_num,
                    "ip": hop_ip,
                    "rtt": rtt_part
                })

        return {
            "success": True,
            "target": sanitized_host,
            "max_hops": max_hops,
            "hops": hops,
            "raw_output": output
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Traceroute error: {str(e)}"
        }
