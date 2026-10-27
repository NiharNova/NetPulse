/**
 * NetPulse: Real-Time Network Traffic Analysis System
 * app.js - Single-Page Application Client Controller
 * Manages WebSockets, Chart.js instances, Packet Inspector, Canvas Topology,
 * Network Audit (SharkTooth), and Toolkit utilities.
 */

// Application State
let ws = null;
let reconnectTimer = null;
let currentPackets = [];
let timelineChart = null;
let protocolChart = null;
let talkersChart = null;
let portsChart = null;
let scanlinesActive = true;

// ==========================================================================
// 1. Navigation & UI Controls
// ==========================================================================
function navigateTo(sectionId) {
  const sections = document.querySelectorAll('.section');
  sections.forEach(sec => sec.classList.remove('active'));

  const targetSec = document.getElementById(`section-${sectionId}`);
  if (targetSec) {
    targetSec.classList.add('active');
  }

  const navLinks = document.querySelectorAll('.nav-link');
  navLinks.forEach(link => {
    link.classList.remove('active');
    if (link.getAttribute('onclick') && link.getAttribute('onclick').includes(sectionId)) {
      link.classList.add('active');
    }
  });

  window.scrollTo({ top: 0, behavior: 'smooth' });

  // If navigating to alerts, refresh alerts list
  if (sectionId === 'alerts') {
    loadAlertsList();
  }
}

function toggleScanlines() {
  scanlinesActive = !scanlinesActive;
  const overlay = document.getElementById('scanlineOverlay');
  const btn = document.getElementById('scanlineBtn');
  if (scanlinesActive) {
    overlay.style.display = 'block';
    btn.textContent = 'SCANLINES [ON]';
    btn.classList.add('btn-cyan');
    btn.classList.remove('btn-danger');
  } else {
    overlay.style.display = 'none';
    btn.textContent = 'CRT SCAN [OFF]';
    btn.classList.remove('btn-cyan');
    btn.classList.add('btn-danger');
  }
}

function switchArchMode(mode) {
  const visualView = document.getElementById('archVisualView');
  const asciiView = document.getElementById('archAsciiView');
  const btnVisual = document.getElementById('btnArchVisual');
  const btnAscii = document.getElementById('btnArchAscii');

  if (mode === 'visual') {
    if (visualView) visualView.style.display = 'flex';
    if (asciiView) asciiView.style.display = 'none';
    if (btnVisual) btnVisual.classList.add('active');
    if (btnAscii) btnAscii.classList.remove('active');
  } else {
    if (visualView) visualView.style.display = 'none';
    if (asciiView) asciiView.style.display = 'block';
    if (btnVisual) btnVisual.classList.remove('active');
    if (btnAscii) btnAscii.classList.add('active');
  }
}

// ==========================================================================
// 2. Interactive Network Topology Hero Animation (HTML5 Canvas)
// ==========================================================================
class TopologySimulation {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.nodes = [];
    this.links = [];
    this.particles = [];
    this.animationFrameId = null;

    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.initTopology();
    this.animate();
  }

  resize() {
    if (!this.canvas) return;
    this.canvas.width = this.canvas.parentElement.clientWidth;
    this.canvas.height = this.canvas.parentElement.clientHeight || 380;
  }

  initTopology() {
    const w = this.canvas.width;
    const h = this.canvas.height;

    // Defined Network Nodes
    this.nodes = [
      { id: 'gateway', label: 'Gateway 192.168.1.1', x: w * 0.5, y: h * 0.45, type: 'core', color: '#00ff9c', radius: 14 },
      { id: 'firewall', label: 'IDS / Firewall', x: w * 0.5, y: h * 0.2, type: 'fw', color: '#00e5ff', radius: 10 },
      { id: 'cloud', label: 'WAN / Cloud Gateway', x: w * 0.5, y: h * 0.08, type: 'cloud', color: '#bd00ff', radius: 11 },
      { id: 'ws1', label: 'Host .105', x: w * 0.18, y: h * 0.35, type: 'host', color: '#00e5ff', radius: 8 },
      { id: 'ws2', label: 'Host .112', x: w * 0.22, y: h * 0.65, type: 'host', color: '#00e5ff', radius: 8 },
      { id: 'ws3', label: 'Host .140', x: w * 0.35, y: h * 0.82, type: 'host', color: '#00e5ff', radius: 8 },
      { id: 'srv1', label: 'DNS Server (53)', x: w * 0.78, y: h * 0.35, type: 'server', color: '#ffb300', radius: 9 },
      { id: 'srv2', label: 'Web Server (443)', x: w * 0.75, y: h * 0.65, type: 'server', color: '#00ff9c', radius: 9 },
      { id: 'db', label: 'Postgres (5432)', x: w * 0.62, y: h * 0.82, type: 'server', color: '#00e5ff', radius: 9 },
      { id: 'attacker', label: 'Rogue Node .189', x: w * 0.12, y: h * 0.85, type: 'threat', color: '#ff3b3b', radius: 8 }
    ];

    // Defined Interconnecting Links
    this.links = [
      ['cloud', 'firewall'],
      ['firewall', 'gateway'],
      ['gateway', 'ws1'],
      ['gateway', 'ws2'],
      ['gateway', 'ws3'],
      ['gateway', 'srv1'],
      ['gateway', 'srv2'],
      ['gateway', 'db'],
      ['srv2', 'db'],
      ['ws1', 'ws2'],
      ['attacker', 'gateway']
    ];

    // Traveling packet particles
    this.particles = [];
    for (let i = 0; i < 28; i++) {
      const link = this.links[Math.floor(Math.random() * this.links.length)];
      this.particles.push({
        sourceId: link[0],
        targetId: link[1],
        progress: Math.random(),
        speed: 0.004 + Math.random() * 0.008,
        color: link[0] === 'attacker' || link[1] === 'attacker' ? '#ff3b3b' : '#00ff9c'
      });
    }
  }

  getNode(id) {
    return this.nodes.find(n => n.id === id);
  }

  animate() {
    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    // Draw Links
    this.ctx.lineWidth = 1;
    for (const [sId, tId] of this.links) {
      const s = this.getNode(sId);
      const t = this.getNode(tId);
      if (!s || !t) continue;

      this.ctx.strokeStyle = sId === 'attacker' || tId === 'attacker' 
        ? 'rgba(255, 59, 59, 0.25)' 
        : 'rgba(0, 229, 255, 0.18)';
      this.ctx.beginPath();
      this.ctx.moveTo(s.x, s.y);
      this.ctx.lineTo(t.x, t.y);
      this.ctx.stroke();
    }

    // Draw Traveling Packet Particles
    for (const p of this.particles) {
      p.progress += p.speed;
      if (p.progress >= 1) {
        p.progress = 0;
        const link = this.links[Math.floor(Math.random() * this.links.length)];
        p.sourceId = link[0];
        p.targetId = link[1];
        p.color = (link[0] === 'attacker' || link[1] === 'attacker') ? '#ff3b3b' : (Math.random() > 0.4 ? '#00ff9c' : '#00e5ff');
      }

      const s = this.getNode(p.sourceId);
      const t = this.getNode(p.targetId);
      if (!s || !t) continue;

      const px = s.x + (t.x - s.x) * p.progress;
      const py = s.y + (t.y - s.y) * p.progress;

      this.ctx.fillStyle = p.color;
      this.ctx.shadowColor = p.color;
      this.ctx.shadowBlur = 8;
      this.ctx.beginPath();
      this.ctx.arc(px, py, 2.8, 0, Math.PI * 2);
      this.ctx.fill();
      this.ctx.shadowBlur = 0;
    }

    // Draw Nodes
    for (const node of this.nodes) {
      // Glow circle
      this.ctx.fillStyle = node.color;
      this.ctx.shadowColor = node.color;
      this.ctx.shadowBlur = 10;
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      this.ctx.fill();
      this.ctx.shadowBlur = 0;

      // Inner core
      this.ctx.fillStyle = '#05080a';
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, node.radius * 0.6, 0, Math.PI * 2);
      this.ctx.fill();

      // Node Label
      this.ctx.font = '10px "JetBrains Mono", monospace';
      this.ctx.fillStyle = '#d1e4eb';
      this.ctx.textAlign = 'center';
      this.ctx.fillText(node.label, node.x, node.y + node.radius + 12);
    }

    this.animationFrameId = requestAnimationFrame(() => this.animate());
  }
}


// ==========================================================================
// 3. Chart.js Initialization & Theme Helpers
// ==========================================================================
const chartFont = {
  family: "'JetBrains Mono', monospace",
  size: 11
};

const chartGridColor = 'rgba(0, 229, 255, 0.08)';

function initCharts() {
  // 1. Timeline Chart (Bandwidth & Packets/s)
  const ctxTimeline = document.getElementById('timelineChart').getContext('2d');
  timelineChart = new Chart(ctxTimeline, {
    type: 'line',
    data: {
      labels: Array(60).fill(''),
      datasets: [
        {
          label: 'Bandwidth (KB/s)',
          data: Array(60).fill(0),
          borderColor: '#00e5ff',
          backgroundColor: 'rgba(0, 229, 255, 0.08)',
          borderWidth: 2,
          fill: true,
          tension: 0.3,
          pointRadius: 0,
          yAxisID: 'y'
        },
        {
          label: 'Packets / Sec',
          data: Array(60).fill(0),
          borderColor: '#00ff9c',
          borderWidth: 1.5,
          borderDash: [4, 4],
          fill: false,
          tension: 0.3,
          pointRadius: 0,
          yAxisID: 'y1'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: {
          labels: { color: '#d1e4eb', font: chartFont }
        }
      },
      scales: {
        x: {
          grid: { color: chartGridColor },
          ticks: { color: '#64818c', font: chartFont, maxTicksLimit: 10 }
        },
        y: {
          type: 'linear',
          display: true,
          position: 'left',
          grid: { color: chartGridColor },
          ticks: { color: '#00e5ff', font: chartFont }
        },
        y1: {
          type: 'linear',
          display: true,
          position: 'right',
          grid: { drawOnChartArea: false },
          ticks: { color: '#00ff9c', font: chartFont }
        }
      }
    }
  });

  // 2. Protocol Doughnut Chart
  const ctxProto = document.getElementById('protocolChart').getContext('2d');
  protocolChart = new Chart(ctxProto, {
    type: 'doughnut',
    data: {
      labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'ARP', 'Other'],
      datasets: [{
        data: [1, 1, 1, 1, 1, 1, 1, 1],
        backgroundColor: [
          '#00e5ff', '#00ff9c', '#ffb300', '#bd00ff',
          '#00b4d8', '#4361ee', '#f72585', '#64818c'
        ],
        borderWidth: 1,
        borderColor: '#0b1215'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: { color: '#d1e4eb', font: chartFont, boxWidth: 12 }
        }
      },
      cutout: '65%'
    }
  });

  // 3. Top Talkers Bar Chart
  const ctxTalkers = document.getElementById('talkersChart').getContext('2d');
  talkersChart = new Chart(ctxTalkers, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Volume (KB)',
        data: [],
        backgroundColor: 'rgba(0, 229, 255, 0.4)',
        borderColor: '#00e5ff',
        borderWidth: 1
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: chartGridColor }, ticks: { color: '#64818c', font: chartFont } },
        y: { grid: { display: false }, ticks: { color: '#d1e4eb', font: chartFont } }
      }
    }
  });

  // 4. Top Destination Ports Bar Chart
  const ctxPorts = document.getElementById('portsChart').getContext('2d');
  portsChart = new Chart(ctxPorts, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Hits',
        data: [],
        backgroundColor: 'rgba(0, 255, 156, 0.4)',
        borderColor: '#00ff9c',
        borderWidth: 1
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: chartGridColor }, ticks: { color: '#64818c', font: chartFont } },
        y: { grid: { display: false }, ticks: { color: '#d1e4eb', font: chartFont } }
      }
    }
  });
}


// ==========================================================================
// 4. WebSocket Streaming Telemetry Connection
// ==========================================================================
function connectWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/traffic`;

  const wsStatusText = document.getElementById('wsStatusText');
  const systemLed = document.getElementById('systemLed');
  const systemStatusText = document.getElementById('systemStatusText');

  try {
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      wsStatusText.textContent = 'CONNECTED (1 Hz)';
      wsStatusText.className = 'text-green';
      systemLed.className = 'status-led';
      systemStatusText.textContent = 'SYSTEM ONLINE';
      if (reconnectTimer) {
        clearInterval(reconnectTimer);
        reconnectTimer = null;
      }
    };

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        handleTelemetrySnapshot(payload);
      } catch (err) {
        console.error('Telemetry parse error:', err);
      }
    };

    ws.onclose = () => {
      wsStatusText.textContent = 'DISCONNECTED (Reconnecting...)';
      wsStatusText.className = 'text-amber';
      systemLed.className = 'status-led warning';
      systemStatusText.textContent = 'OFFLINE / RECONNECTING';
      scheduleReconnect();
    };

    ws.onerror = () => {
      ws.close();
    };
  } catch (err) {
    scheduleReconnect();
  }
}

function scheduleReconnect() {
  if (!reconnectTimer) {
    reconnectTimer = setInterval(() => {
      connectWebSocket();
    }, 3000);
  }
}

function handleTelemetrySnapshot(data) {
  // 1. Update KPI Values
  if (data.kpis) {
    document.getElementById('kpiTotalPackets').textContent = data.kpis.total_packets.toLocaleString();
    document.getElementById('kpiPps').textContent = data.kpis.packets_per_sec;
    document.getElementById('kpiBandwidth').textContent = data.kpis.bandwidth_kbps;
    document.getElementById('kpiTotalBytes').textContent = data.kpis.total_bytes_formatted;
    document.getElementById('kpiActiveConns').textContent = data.kpis.active_connections;
    document.getElementById('kpiAlerts').textContent = data.kpis.alert_count;
  }

  // 2. Update Timeline Chart
  if (data.charts && data.charts.timeline && timelineChart) {
    timelineChart.data.labels = data.charts.timeline.labels;
    timelineChart.data.datasets[0].data = data.charts.timeline.bandwidth_kbps;
    timelineChart.data.datasets[1].data = data.charts.timeline.packets_rate;
    timelineChart.update('none');
  }

  // 3. Update Protocol Doughnut Chart
  if (data.charts && data.charts.protocols && protocolChart) {
    const p = data.charts.protocols;
    protocolChart.data.datasets[0].data = [
      p.TCP || 0, p.UDP || 0, p.ICMP || 0, p.DNS || 0,
      p.HTTP || 0, p.HTTPS || 0, p.ARP || 0, p.Other || 0
    ];
    protocolChart.update('none');
  }

  // 4. Update Top Talkers Chart
  if (data.charts && data.charts.top_talkers && talkersChart) {
    talkersChart.data.labels = data.charts.top_talkers.map(t => t.ip);
    talkersChart.data.datasets[0].data = data.charts.top_talkers.map(t => t.kb);
    talkersChart.update('none');
  }

  // 5. Update Top Ports Chart
  if (data.charts && data.charts.top_ports && portsChart) {
    portsChart.data.labels = data.charts.top_ports.map(p => `${p.port} (${p.service})`);
    portsChart.data.datasets[0].data = data.charts.top_ports.map(p => p.count);
    portsChart.update('none');
  }

  // 6. Update Live Packet Ring Buffer
  if (data.recent_packets) {
    currentPackets = data.recent_packets;
    renderPacketTable();
  }

  // 7. Update Capture Mode & Errors
  if (data.capture_status) {
    const cs = data.capture_status;
    const modeBadge = document.getElementById('modeBadge');
    modeBadge.textContent = cs.is_demo ? 'MODE: DEMO' : 'MODE: LIVE PCAP';
    modeBadge.className = cs.is_demo ? 'tag-badge' : 'tag-badge text-green';

    const banner = document.getElementById('captureAlertBanner');
    const msgSpan = document.getElementById('captureAlertMsg');
    if (cs.error_message) {
      banner.style.display = 'block';
      msgSpan.innerHTML = `<strong>CAPTURE NOTICE:</strong> ${cs.error_message}`;
    } else {
      banner.style.display = 'none';
    }
  }

  // 8. Update Anomaly Z-Score status in Section 3
  if (data.recent_alerts && data.recent_alerts.length > 0) {
    const latest = data.recent_alerts[0];
    const zScoreVal = document.getElementById('zScoreVal');
    const zScoreStatus = document.getElementById('zScoreStatus');
    if (zScoreVal && zScoreStatus) {
      if (latest.score > 3.0) {
        zScoreVal.textContent = `Z = ${latest.score}`;
        zScoreVal.className = 'text-red';
        zScoreStatus.textContent = `CRITICAL DEVIATION DETECTED (${latest.alert_type})`;
        zScoreStatus.className = 'text-red';
      } else {
        zScoreVal.textContent = `Z = ${latest.score || '0.42'}`;
        zScoreVal.className = 'text-green';
        zScoreStatus.textContent = 'NORMAL TRAFFIC (No deviation)';
        zScoreStatus.className = 'text-green';
      }
    }
  }
}


// ==========================================================================
// 5. Live Packet Table Rendering, Filtering & Wireshark Modal
// ==========================================================================
function renderPacketTable() {
  const tbody = document.getElementById('packetTableBody');
  const filterText = document.getElementById('packetFilterInput').value.toLowerCase().trim();
  const filterProto = document.getElementById('packetProtoFilter').value.toUpperCase();

  const filtered = currentPackets.filter(pkt => {
    if (filterProto && pkt.protocol !== filterProto) {
      return false;
    }
    if (filterText) {
      const matchSrc = (pkt.src_ip || '').toLowerCase().includes(filterText);
      const matchDst = (pkt.dst_ip || '').toLowerCase().includes(filterText);
      const matchProto = (pkt.protocol || '').toLowerCase().includes(filterText);
      const matchSummary = (pkt.summary || '').toLowerCase().includes(filterText);
      const matchPort = String(pkt.dst_port || '').includes(filterText) || String(pkt.src_port || '').includes(filterText);
      return matchSrc || matchDst || matchProto || matchSummary || matchPort;
    }
    return true;
  });

  document.getElementById('bufferCountText').textContent = `${filtered.length} of ${currentPackets.length} frames`;

  // Render rows in reverse chronological order (newest first)
  const rows = [...filtered].reverse().slice(0, 50).map(pkt => {
    const protoClass = `proto-${(pkt.protocol || 'other').toLowerCase()}`;
    const flagsStr = (pkt.tcp_flags && pkt.tcp_flags.length > 0) ? pkt.tcp_flags.join(', ') : '-';
    const portService = pkt.dst_port ? `${pkt.dst_port} (${pkt.service || '-'})` : (pkt.service || '-');

    return `
      <tr onclick="inspectPacket(${pkt.id})">
        <td style="color: var(--text-muted);">${pkt.id}</td>
        <td>${pkt.timestamp}</td>
        <td class="text-cyan">${pkt.src_ip}</td>
        <td class="text-bright">${pkt.dst_ip}</td>
        <td><span class="proto-badge ${protoClass}">${pkt.protocol}</span></td>
        <td>${portService}</td>
        <td>${pkt.length} B</td>
        <td style="color: var(--neon-amber);">${flagsStr}</td>
        <td style="color: var(--text-muted); font-size: 0.75rem;">${escapeHtml(pkt.summary)}</td>
      </tr>
    `;
  }).join('');

  tbody.innerHTML = rows || `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No packets matching filter</td></tr>`;
}

function filterPacketTable() {
  renderPacketTable();
}

function resetPacketFilter() {
  document.getElementById('packetFilterInput').value = '';
  document.getElementById('packetProtoFilter').value = '';
  renderPacketTable();
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Packet Inspector Modal
function inspectPacket(packetId) {
  const pkt = currentPackets.find(p => p.id === packetId);
  if (!pkt) return;

  document.getElementById('modalPacketTitle').textContent = `Packet #${pkt.id} Dissection // ${pkt.protocol}`;
  const modalBody = document.getElementById('modalPacketBody');

  let html = `
    <div style="background: rgba(0, 229, 255, 0.05); padding: 10px; border-radius: 4px; border: 1px solid rgba(0,229,255,0.2); margin-bottom: 1rem;">
      <div style="font-weight: 700; color: #fff;">Summary: ${escapeHtml(pkt.summary)}</div>
      <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;">Captured Length: ${pkt.length} bytes | Arrival Time: ${pkt.timestamp}</div>
    </div>
  `;

  // Render Layer Trees
  if (pkt.details) {
    for (const [layerName, fields] of Object.entries(pkt.details)) {
      if (layerName === 'Payload') continue; // Handled separately

      html += `
        <div class="tree-node">
          <div class="tree-header">
            <span>${escapeHtml(layerName)} Protocol Header</span>
          </div>
          <div class="tree-content">
      `;

      for (const [key, val] of Object.entries(fields)) {
        html += `
          <div class="tree-row">
            <span class="tree-key">${escapeHtml(key)}:</span>
            <span class="tree-val">${escapeHtml(String(val))}</span>
          </div>
        `;
      }

      html += `</div></div>`;
    }

    // Render Payload Hex & ASCII
    if (pkt.details.Payload) {
      const p = pkt.details.Payload;
      html += `
        <div class="tree-node">
          <div class="tree-header">
            <span>Payload Data (${p.Length} bytes)</span>
          </div>
          <div class="tree-content">
            <div style="font-size: 0.75rem; color: var(--text-muted);">HEX DISSECTION:</div>
            <div class="hex-dump-box">${escapeHtml(p['Hex Snippet'])}</div>
            <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 6px;">ASCII INTERPRETATION:</div>
            <div class="hex-dump-box" style="color: var(--neon-cyan);">${escapeHtml(p['ASCII Snippet'])}</div>
          </div>
        </div>
      `;
    }
  }

  modalBody.innerHTML = html;
  document.getElementById('packetDetailModal').classList.add('show');
}

function closePacketModal() {
  const modal = document.getElementById('packetDetailModal');
  if (modal) {
    modal.classList.remove('show');
  }
}

// Global Escape key listener to close modal
window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closePacketModal();
  }
});


// ==========================================================================
// 6. Capture Manager & Attack Injections
// ==========================================================================
async function loadInterfaces() {
  try {
    const res = await fetch('/api/interfaces');
    const data = await res.json();
    const select = document.getElementById('ifaceSelect');
    select.innerHTML = '';

    for (const iface of data.interfaces) {
      const opt = document.createElement('option');
      opt.value = iface.id;
      opt.textContent = `${iface.name} [${iface.ip}]`;
      select.appendChild(opt);
    }
  } catch (err) {
    console.error('Failed to load interfaces:', err);
  }
}

async function startCapture() {
  const ifaceId = document.getElementById('ifaceSelect').value;
  try {
    const res = await fetch('/api/capture/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface: ifaceId })
    });
    const data = await res.json();
    if (data.message) {
      const banner = document.getElementById('captureAlertBanner');
      banner.style.display = 'block';
      document.getElementById('captureAlertMsg').textContent = data.message;
    }
  } catch (err) {
    alert('Failed to start capture: ' + err.message);
  }
}

async function stopCapture() {
  try {
    await fetch('/api/capture/stop', { method: 'POST' });
    const banner = document.getElementById('captureAlertBanner');
    banner.style.display = 'block';
    document.getElementById('captureAlertMsg').textContent = 'Capture halted by user.';
  } catch (err) {
    alert('Failed to stop capture: ' + err.message);
  }
}

async function injectAttack(attackType) {
  try {
    const res = await fetch('/api/capture/simulate-attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attack_type: attackType })
    });
    const data = await res.json();
    // Show quick feedback banner
    const banner = document.getElementById('captureAlertBanner');
    banner.style.display = 'block';
    document.getElementById('captureAlertMsg').innerHTML = `<span class="text-amber">⚡ SIMULATION TRIGGERED:</span> ${data.message}`;
  } catch (err) {
    alert('Attack injection failed: ' + err.message);
  }
}


// ==========================================================================
// 7. Anomaly & Alerts Feed
// ==========================================================================
async function loadAlertsList() {
  const filter = document.getElementById('alertSeverityFilter').value;
  let url = '/api/alerts?limit=50';
  if (filter) {
    url += `&severity=${filter}`;
  }

  try {
    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById('alertsTableBody');

    if (!data.alerts || data.alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">No security alerts recorded. Traffic within baseline parameters.</td></tr>`;
      return;
    }

    const rows = data.alerts.map(a => {
      const sevClass = a.severity === 'HIGH' ? 'alert-high' : a.severity === 'MEDIUM' ? 'alert-medium' : 'alert-low';
      return `
        <tr>
          <td style="color: var(--text-muted);">${a.id}</td>
          <td>${a.timestamp}</td>
          <td><span class="alert-badge ${sevClass}">${a.severity}</span></td>
          <td class="text-bright" style="font-weight: 700;">${escapeHtml(a.alert_type)}</td>
          <td class="text-cyan">${escapeHtml(a.source_ip)}</td>
          <td>${escapeHtml(a.target_ip)}</td>
          <td style="font-size: 0.8rem; color: var(--text-main);">${escapeHtml(a.details)}</td>
          <td style="color: var(--neon-amber); font-weight: 700;">${a.score || '-'}</td>
        </tr>
      `;
    }).join('');

    tbody.innerHTML = rows;
  } catch (err) {
    console.error('Failed to load alerts:', err);
  }
}

async function clearAlerts() {
  if (!confirm('Clear all security alerts and anomalies from the SQLite database?')) return;
  try {
    await fetch('/api/alerts/clear', { method: 'POST' });
    loadAlertsList();
  } catch (err) {
    alert('Failed to clear alerts: ' + err.message);
  }
}


// ==========================================================================
// 8. Network Audit (SharkTooth Module)
// ==========================================================================
async function executeScan() {
  const host = document.getElementById('scanTargetInput').value.trim();
  const ports = document.getElementById('scanPortsInput').value.trim();
  const proto = document.getElementById('scanProtocolSelect').value;
  const authorized = document.getElementById('scanAuthCheckbox').checked;
  const statusMsg = document.getElementById('scanStatusMsg');
  const summaryBadge = document.getElementById('scanSummaryBadge');
  const runBtn = document.getElementById('runScanBtn');
  const tbody = document.getElementById('scanResultsBody');

  if (!authorized) {
    statusMsg.innerHTML = '<span class="text-red">ERROR: You must verify ownership/authorization by checking the disclaimer box.</span>';
    return;
  }

  statusMsg.innerHTML = `<span class="text-cyan">Executing multithreaded socket audit on ${host}...</span>`;
  summaryBadge.textContent = 'SCANNING...';
  summaryBadge.className = 'tag-badge text-amber';
  runBtn.disabled = true;

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_host: host,
        port_range: ports,
        protocol: proto,
        authorized: authorized
      })
    });

    const data = await res.json();
    runBtn.disabled = false;

    if (!res.ok) {
      statusMsg.innerHTML = `<span class="text-red">AUDIT BLOCKED: ${data.detail || 'Scan rejected'}</span>`;
      summaryBadge.textContent = 'REJECTED';
      summaryBadge.className = 'tag-badge text-red';
      return;
    }

    statusMsg.innerHTML = `<span class="text-green">Audit completed in ${data.scan_duration_sec}s. Target: ${data.resolved_ip}. Open ports: ${data.open_count} / ${data.total_scanned}</span>`;
    summaryBadge.textContent = `${data.open_count} OPEN PORTS`;
    summaryBadge.className = 'tag-badge text-green';

    if (!data.results || data.results.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No open ports identified.</td></tr>';
      return;
    }

    const rows = data.results.map(r => {
      const stateClass = r.state === 'OPEN' ? 'text-green' : r.state === 'FILTERED' ? 'text-amber' : 'text-muted';
      return `
        <tr>
          <td style="font-weight: 700;">${r.port}</td>
          <td>${r.protocol}</td>
          <td class="${stateClass}" style="font-weight: 700;">${r.state}</td>
          <td class="text-bright">${escapeHtml(r.service)}</td>
          <td>${r.latency_ms} ms</td>
        </tr>
      `;
    }).join('');

    tbody.innerHTML = rows;
  } catch (err) {
    runBtn.disabled = false;
    statusMsg.innerHTML = `<span class="text-red">Scan error: ${err.message}</span>`;
  }
}


// ==========================================================================
// 9. Network Toolkit Tools (Subnet, VLSM, Converter, Ping, DNS, Traceroute)
// ==========================================================================
function switchToolTab(tabName) {
  const btns = document.querySelectorAll('.tab-btn');
  btns.forEach(b => b.classList.remove('active'));

  const panes = document.querySelectorAll('.tool-pane');
  panes.forEach(p => p.classList.remove('active'));

  const targetPane = document.getElementById(`tool-${tabName}`);
  if (targetPane) targetPane.classList.add('active');

  event.target.classList.add('active');
}

async function calculateSubnetTool() {
  const input = document.getElementById('subnetInput').value.trim();
  const box = document.getElementById('subnetResultBox');
  try {
    const res = await fetch('/api/tools/subnet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ network: input })
    });
    const data = await res.json();
    if (!res.ok) {
      box.innerHTML = `<div class="text-red">Error: ${data.detail || 'Calculation failed'}</div>`;
      return;
    }

    box.innerHTML = `
      <div class="result-row"><span class="text-muted">Network Address:</span><span class="text-green">${data.network_address}</span></div>
      <div class="result-row"><span class="text-muted">Broadcast Address:</span><span class="text-amber">${data.broadcast_address}</span></div>
      <div class="result-row"><span class="text-muted">Subnet Mask:</span><span class="text-cyan">${data.netmask} (${data.cidr})</span></div>
      <div class="result-row"><span class="text-muted">Wildcard Mask:</span><span class="text-bright">${data.wildcard_mask}</span></div>
      <div class="result-row"><span class="text-muted">Usable Host Range:</span><span class="text-bright">${data.usable_host_range}</span></div>
      <div class="result-row"><span class="text-muted">Usable Hosts / Total:</span><span class="text-green">${data.usable_hosts.toLocaleString()} / ${data.total_hosts.toLocaleString()}</span></div>
      <div class="result-row"><span class="text-muted">IP Classification:</span><span class="text-purple">${data.ip_class} ${data.is_private ? '(Private RFC1918)' : ''}</span></div>
      <div class="result-row"><span class="text-muted">Binary Netmask:</span><span class="text-bright" style="font-size: 0.75rem;">${data.binary.netmask}</span></div>
    `;
  } catch (err) {
    box.innerHTML = `<div class="text-red">Error: ${err.message}</div>`;
  }
}

function addVlsmRow() {
  const container = document.getElementById('vlsmSubnetsContainer');
  const div = document.createElement('div');
  div.style.display = 'flex';
  div.style.gap = '8px';
  div.style.marginBottom = '6px';
  div.innerHTML = `
    <input type="text" class="form-control vlsm-name" value="New Subnet" placeholder="Name">
    <input type="number" class="form-control vlsm-hosts" value="10" placeholder="Hosts" style="width: 100px;">
  `;
  container.appendChild(div);
}

async function calculateVlsmTool() {
  const majorNet = document.getElementById('vlsmMajorNet').value.trim();
  const names = document.querySelectorAll('.vlsm-name');
  const hosts = document.querySelectorAll('.vlsm-hosts');
  const tbody = document.getElementById('vlsmResultBody');

  const subnetsReq = [];
  for (let i = 0; i < names.length; i++) {
    subnetsReq.push({
      name: names[i].value || `Subnet ${i+1}`,
      hosts: parseInt(hosts[i].value, 10) || 1
    });
  }

  try {
    const res = await fetch('/api/tools/vlsm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ major_network: majorNet, subnets: subnetsReq })
    });
    const data = await res.json();
    if (!res.ok) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-red" style="text-align: center; padding: 1.5rem;">${data.detail || 'VLSM error'}</td></tr>`;
      return;
    }

    const rows = data.subnets.map(s => `
      <tr>
        <td class="text-bright" style="font-weight: 700;">${escapeHtml(s.name)}</td>
        <td>${s.needed_hosts}</td>
        <td class="text-green">${s.allocated_hosts}</td>
        <td class="text-cyan">${s.prefix}</td>
        <td>${s.network_address}</td>
        <td>${s.usable_range}</td>
      </tr>
    `).join('');

    tbody.innerHTML = rows;
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-red" style="text-align: center;">Error: ${err.message}</td></tr>`;
  }
}

async function convertIpTool() {
  const val = document.getElementById('converterInput').value.trim();
  const box = document.getElementById('converterResultBox');
  if (!val) return;

  try {
    const res = await fetch(`/api/tools/convert-ip?value=${encodeURIComponent(val)}`);
    const data = await res.json();
    if (res.ok) {
      box.innerHTML = `
        <div class="result-row"><span class="text-muted">Dotted Decimal:</span><span class="text-bright">${data.dotted_decimal}</span></div>
        <div class="result-row"><span class="text-muted">32-Bit Integer:</span><span class="text-cyan">${data.integer_32}</span></div>
        <div class="result-row"><span class="text-muted">Hexadecimal:</span><span class="text-green">${data.hexadecimal}</span></div>
        <div class="result-row"><span class="text-muted">Dotted Binary:</span><span class="text-amber">${data.binary_dotted}</span></div>
      `;
    }
  } catch (err) {
    // Keep typing without throwing errors
  }
}

async function executePingTool() {
  const host = document.getElementById('pingHostInput').value.trim();
  const count = document.getElementById('pingCountInput').value;
  const box = document.getElementById('pingResultBox');
  box.textContent = `Pinging ${host}...`;

  try {
    const res = await fetch(`/api/tools/ping?host=${encodeURIComponent(host)}&count=${count}`);
    const data = await res.json();
    if (!res.ok) {
      box.textContent = `Ping failed: ${data.detail || 'Error'}`;
      return;
    }
    box.textContent = data.raw_output || `Average RTT: ${data.avg_rtt_ms} ms | Loss: ${data.packet_loss_pct}%`;
  } catch (err) {
    box.textContent = `Ping execution error: ${err.message}`;
  }
}

async function executeDnsTool() {
  const host = document.getElementById('dnsHostInput').value.trim();
  const type = document.getElementById('dnsTypeSelect').value;
  const box = document.getElementById('dnsResultBox');
  box.innerHTML = `<div style="color: var(--neon-cyan);">Resolving ${type} records for ${host}...</div>`;

  try {
    const res = await fetch(`/api/tools/dns?host=${encodeURIComponent(host)}&type=${type}`);
    const data = await res.json();
    if (!res.ok) {
      box.innerHTML = `<div class="text-red">Error: ${data.detail || 'Resolution failed'}</div>`;
      return;
    }

    const rows = data.records.map(r => `
      <div class="result-row">
        <span class="text-cyan">${r.type}</span>
        <span class="text-bright">${escapeHtml(r.value)}</span>
      </div>
    `).join('');

    box.innerHTML = rows;
  } catch (err) {
    box.innerHTML = `<div class="text-red">Error: ${err.message}</div>`;
  }
}

async function executeTraceTool() {
  const host = document.getElementById('traceHostInput').value.trim();
  const hops = document.getElementById('traceHopsInput').value;
  const box = document.getElementById('traceResultBox');
  box.textContent = `Tracing route to ${host} (max ${hops} hops)... This may take 5-10 seconds...`;

  try {
    const res = await fetch(`/api/tools/traceroute?host=${encodeURIComponent(host)}&max_hops=${hops}`);
    const data = await res.json();
    if (!res.ok) {
      box.textContent = `Traceroute failed: ${data.detail || 'Error'}`;
      return;
    }
    box.textContent = data.raw_output || 'Traceroute completed.';
  } catch (err) {
    box.textContent = `Traceroute error: ${err.message}`;
  }
}


// ==========================================================================
// 10. Initialization on DOM Load
// ==========================================================================
window.addEventListener('DOMContentLoaded', () => {
  new TopologySimulation('topologyCanvas');
  initCharts();
  loadInterfaces();
  connectWebSocket();
  loadAlertsList();
  calculateSubnetTool();
});
