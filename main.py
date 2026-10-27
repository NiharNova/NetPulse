"""
NetPulse - Real-Time Network Traffic Analysis System
main.py - FastAPI application, REST endpoints, WebSocket streaming (/ws/traffic),
Prometheus metrics (/metrics), and static frontend serving.
"""

import os
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, List, Any, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Body, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST

from analyzer import global_analyzer
from anomaly import global_anomaly_engine
from capture import global_capture_manager, get_network_interfaces
from scanner import global_scanner
from tools import (
    calculate_subnet, plan_vlsm, convert_ip_format,
    run_ping, run_dns_lookup, run_traceroute
)

# Prometheus Metrics Definitions
METRIC_PACKETS_TOTAL = Counter("netpulse_packets_total", "Cumulative packets captured or simulated by NetPulse")
METRIC_BYTES_TOTAL = Counter("netpulse_bytes_total", "Cumulative bytes processed by NetPulse")
METRIC_ALERTS_TOTAL = Gauge("netpulse_alerts_total", "Total security alerts and anomalies triggered")
METRIC_CONNECTIONS_ACTIVE = Gauge("netpulse_active_connections", "Number of currently active tracked connections")
METRIC_SCANS_TOTAL = Counter("netpulse_scans_total", "Number of network audit scans initiated")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Initializes Demo Mode on startup so users see active traffic right away.
    """
    # Start in Demo Mode by default for seamless out-of-the-box experience
    global_capture_manager.start_capture("demo")
    yield
    # Graceful shutdown
    global_capture_manager.stop_capture()


app = FastAPI(
    title="NetPulse: Real-Time Network Traffic Analysis System",
    description="Full-stack high-performance Network Monitoring, Packet Capture, and Anomaly Detection System.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request Models
class StartCaptureRequest(BaseModel):
    interface: str = Field(default="demo", description="Interface ID or 'demo'")

class SimulateAttackRequest(BaseModel):
    attack_type: str = Field(default="port_scan", description="port_scan, syn_flood, icmp_flood, dns_spike")

class ScanRequest(BaseModel):
    target_host: str = Field(..., description="Target IP or hostname (RFC1918 or Loopback only)")
    port_range: str = Field(default="common", description="Comma-separated ports or range e.g. 1-100 or 'common'")
    protocol: str = Field(default="TCP", description="TCP or UDP")
    authorized: bool = Field(default=False, description="Verification of ownership/authorization")

class SubnetRequest(BaseModel):
    network: str = Field(..., description="IP/CIDR notation e.g. 192.168.1.50/24")

class VLSMRequest(BaseModel):
    major_network: str = Field(..., description="Major network block e.g. 192.168.1.0/24")
    subnets: List[Dict[str, Any]] = Field(..., description="List of subnets with required hosts")


# --- Static Files & Root Route ---
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=FileResponse)
async def serve_index():
    """Serves the primary single-page application."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return PlainTextResponse("NetPulse Static Frontend index.html initializing...")


# --- Interface & Capture Endpoints ---

@app.get("/api/interfaces")
async def list_interfaces():
    """Returns available OS network adapters and Demo mode option."""
    ifaces = get_network_interfaces()
    return {"interfaces": ifaces}


@app.post("/api/capture/start")
async def start_capture(req: StartCaptureRequest):
    """Starts packet sniffing or synthetic demo generation."""
    res = global_capture_manager.start_capture(req.interface)
    return res


@app.post("/api/capture/stop")
async def stop_capture():
    """Halts current packet sniffing or demo simulation."""
    res = global_capture_manager.stop_capture()
    return res


@app.get("/api/capture/status")
async def get_capture_status():
    """Returns current capture state, interface, and error information."""
    return global_capture_manager.get_status()


@app.post("/api/capture/simulate-attack")
async def inject_attack(req: SimulateAttackRequest):
    """Injects simulated cyber attack vectors to demonstrate real-time alerts."""
    res = global_capture_manager.simulate_attack(req.attack_type)
    return res


# --- Real-Time WebSocket Endpoint ---

@app.websocket("/ws/traffic")
async def websocket_traffic_stream(websocket: WebSocket):
    """
    Streams a comprehensive 1 Hz JSON telemetry snapshot to connected clients:
    KPIs, 60-second time series, protocol breakdown, top talkers, packet ring-buffer,
    and latest anomaly alerts.
    """
    await websocket.accept()
    try:
        while True:
            # Advance 1-second rolling time window
            tick = global_analyzer.tick_second()

            # Statistical baseline anomaly check
            global_anomaly_engine.update_baseline_tick(tick["rate_pps"], tick["rate_kbps"])

            # Compile full snapshot
            snapshot = global_analyzer.get_snapshot()

            # Inject alert counts and recent alert logs
            snapshot["kpis"]["alert_count"] = global_anomaly_engine.total_alerts_count
            snapshot["recent_alerts"] = global_anomaly_engine.get_recent_alerts(limit=15)
            snapshot["capture_status"] = global_capture_manager.get_status()

            # Update Prometheus gauges
            METRIC_ALERTS_TOTAL.set(global_anomaly_engine.total_alerts_count)
            METRIC_CONNECTIONS_ACTIVE.set(snapshot["kpis"]["active_connections"])

            await websocket.send_json(snapshot)
            await asyncio.sleep(1.0)
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception:
        pass


# --- Anomaly & Alert Endpoints ---

@app.get("/api/alerts")
async def get_alerts(limit: int = 50, severity: Optional[str] = None):
    """Fetches persistent anomaly and intrusion alerts from SQLite."""
    alerts = global_anomaly_engine.get_recent_alerts(limit=limit, severity=severity)
    return {"alerts": alerts, "total": global_anomaly_engine.total_alerts_count}


@app.get("/api/alerts/export")
async def export_alerts():
    """Exports SQLite alerts table to downloadable CSV."""
    csv_content = global_anomaly_engine.export_alerts_csv()
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=netpulse_alerts_export.csv"}
    )


@app.post("/api/alerts/clear")
async def clear_alerts():
    """Clears alert database and resets counters."""
    global_anomaly_engine.clear_alerts()
    return {"status": "cleared", "message": "Alert history cleared successfully"}


# --- Network Audit (SharkTooth Module) ---

@app.post("/api/scan")
async def run_network_audit(req: ScanRequest):
    """
    Executes a multithreaded network audit in the style of SharkTooth.
    Strictly enforces RFC1918 private / loopback IP safety boundaries.
    """
    METRIC_SCANS_TOTAL.inc()
    result = global_scanner.run_scan(
        target_host=req.target_host,
        port_spec=req.port_range,
        protocol=req.protocol,
        authorized=req.authorized
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Scan rejected"))
    return result


# --- Network Toolkit Endpoints ---

@app.post("/api/tools/subnet")
async def subnet_calculator(req: SubnetRequest):
    """Computes comprehensive IPv4 subnet parameters."""
    res = calculate_subnet(req.network)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res


@app.post("/api/tools/vlsm")
async def vlsm_planner(req: VLSMRequest):
    """Calculates Variable Length Subnet Masking allocations."""
    res = plan_vlsm(req.major_network, req.subnets)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res


@app.get("/api/tools/convert-ip")
async def convert_ip(value: str = Query(..., description="IP, binary, hex, or integer")):
    """Converts IP representations between formats."""
    res = convert_ip_format(value)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res


@app.get("/api/tools/ping")
async def tool_ping(host: str = Query(..., description="Host to ping"), count: int = 4):
    """Executes a sanitized ping command."""
    res = run_ping(host, count)
    return res


@app.get("/api/tools/dns")
async def tool_dns(host: str = Query(..., description="Host to query"), type: str = "A"):
    """Performs DNS record resolution."""
    res = run_dns_lookup(host, type)
    return res


@app.get("/api/tools/traceroute")
async def tool_traceroute(host: str = Query(..., description="Target host"), max_hops: int = 15):
    """Executes a sanitized traceroute."""
    res = run_traceroute(host, max_hops)
    return res


# --- Prometheus Metrics Endpoint ---

@app.get("/metrics")
async def prometheus_metrics():
    """Exposes Prometheus metrics for Grafana scraping."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
