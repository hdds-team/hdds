// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// HDDS Debugger Frontend
// Auto-refresh at 10 Hz (100ms interval)

const API_BASE = window.location.origin;
const REFRESH_INTERVAL_MS = 100; // 10 Hz

// Metrics history (for time-series charts)
const metricsHistory = [];
const MAX_HISTORY = 600; // 60 seconds at 10 Hz

// Track mesh epoch to avoid unnecessary simulation restarts
let lastMeshEpoch = -1;

// D3.js Force-Directed Graph Setup
const width = 600;
const height = 400;

const svg = d3.select('#mesh-graph')
  .attr('width', width)
  .attr('height', height);

const simulation = d3.forceSimulation()
  .force('link', d3.forceLink().id(d => d.id).distance(100))
  .force('charge', d3.forceManyBody().strength(-300))
  .force('center', d3.forceCenter(width / 2, height / 2))
  .force('collision', d3.forceCollide().radius(30))
  .alphaMin(0.001) // Stop simulation completely when energy is low
  .alphaDecay(0.02); // Slower decay = smoother stabilization

// Create drag behavior once (not recreated on every update)
const dragBehavior = d3.drag()
  .on('start', function(event) {
    if (!event.active) simulation.alphaTarget(0.1).restart();
    event.subject.fx = event.subject.x;
    event.subject.fy = event.subject.y;
  })
  .on('drag', function(event) {
    event.subject.fx = event.x;
    event.subject.fy = event.y;
  })
  .on('end', function(event) {
    if (!event.active) simulation.alphaTarget(0);
    // Keep fixed position after drag
  });

// Chart.js Setup
const latencyCtx = document.getElementById('latency-chart').getContext('2d');
const latencyChart = new Chart(latencyCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [{
      label: 'Latency p99 (µs)',
      data: [],
      borderColor: '#FF6384',
      backgroundColor: 'rgba(255, 99, 132, 0.1)',
      tension: 0.1,
      pointRadius: 0
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: {
        beginAtZero: true,
        title: { display: true, text: 'µs', color: '#e0e0e0' },
        ticks: { color: '#e0e0e0' },
        grid: { color: '#333' }
      },
      x: {
        display: false
      }
    },
    plugins: {
      legend: { labels: { color: '#e0e0e0' } }
    },
    animation: false
  }
});

const throughputCtx = document.getElementById('throughput-chart').getContext('2d');
const throughputChart = new Chart(throughputCtx, {
  type: 'bar',
  data: {
    labels: ['Sent', 'Received', 'Dropped'],
    datasets: [{
      label: 'Messages',
      data: [0, 0, 0],
      backgroundColor: ['#36A2EB', '#4BC0C0', '#FF6384']
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: {
        beginAtZero: true,
        ticks: { color: '#e0e0e0' },
        grid: { color: '#333' }
      },
      x: {
        ticks: { color: '#e0e0e0' },
        grid: { display: false }
      }
    },
    plugins: {
      legend: { display: false }
    },
    animation: false
  }
});

// Fetch Functions
async function fetchMesh() {
  try {
    const response = await fetch(`${API_BASE}/mesh`);
    const data = await response.json();

    // Only update graph if mesh changed (epoch changed)
    if (data.epoch !== lastMeshEpoch) {
      updateMeshGraph(data);
    }

    updateMeshInfo(data);
    updateStatus(true);
  } catch (error) {
    console.error('Failed to fetch mesh:', error);
    updateStatus(false);
  }
}

async function fetchMetrics() {
  try {
    const response = await fetch(`${API_BASE}/metrics`);
    const data = await response.json();
    updateMetrics(data);
  } catch (error) {
    console.error('Failed to fetch metrics:', error);
  }
}

async function fetchTopics() {
  try {
    const response = await fetch(`${API_BASE}/topics`);
    const data = await response.json();
    updateTopics(data);
  } catch (error) {
    console.error('Failed to fetch topics:', error);
  }
}

// Update Functions
function updateMeshGraph(data) {
  const participants = data.participants || [];

  // Get current nodes to preserve fx/fy positions
  const oldNodes = simulation.nodes();
  const oldPositions = new Map();
  oldNodes.forEach(n => {
    if (n.fx !== undefined || n.fy !== undefined) {
      oldPositions.set(n.id, { fx: n.fx, fy: n.fy, x: n.x, y: n.y });
    }
  });

  // Nodes: participants (preserve fixed positions from drag)
  const nodes = participants.map(p => {
    const node = {
      id: p.guid,
      name: p.name,
      is_local: p.is_local
    };

    // Restore fixed position if it was dragged before
    const oldPos = oldPositions.get(p.guid);
    if (oldPos) {
      node.fx = oldPos.fx;
      node.fy = oldPos.fy;
      node.x = oldPos.x;
      node.y = oldPos.y;
    }

    return node;
  });

  // Links: empty in T0 (no inter-participant topics yet)
  const links = [];

  // Update simulation
  simulation.nodes(nodes);
  simulation.force('link').links(links);

  // Render links (edges)
  const link = svg.selectAll('.link')
    .data(links, d => `${d.source.id}-${d.target.id}`)
    .join('line')
    .attr('class', 'link');

  // Render nodes (participants)
  const node = svg.selectAll('.node')
    .data(nodes, d => d.id)
    .join('circle')
    .attr('class', 'node')
    .attr('r', 20)
    .attr('fill', d => d.is_local ? '#4CAF50' : '#999')
    .call(dragBehavior); // Use pre-created drag behavior

  // Render labels (GUID short)
  const label = svg.selectAll('.label')
    .data(nodes, d => d.id)
    .join('text')
    .attr('class', 'label')
    .text(d => d.name || d.id.substring(0, 8) + '...')
    .attr('dx', 25)
    .attr('dy', 5);

  // Tick handler (update positions)
  simulation.on('tick', () => {
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);

    node
      .attr('cx', d => d.x)
      .attr('cy', d => d.y);

    label
      .attr('x', d => d.x)
      .attr('y', d => d.y);
  });

  // Only restart simulation if mesh changed (epoch changed)
  if (data.epoch !== lastMeshEpoch) {
    console.log(`[D3] Mesh epoch changed: ${lastMeshEpoch} → ${data.epoch}, restarting simulation`);
    lastMeshEpoch = data.epoch;
    simulation.alpha(0.3).restart();
  } else {
    // If mesh hasn't changed, let simulation cool down naturally
    // Don't restart it (alpha will decay to 0 automatically)
  }
}

function updateMeshInfo(data) {
  document.getElementById('participant-count').textContent = (data.participants || []).length;
  document.getElementById('mesh-epoch').textContent = data.epoch || 0;
}

function updateMetrics(data) {
  // Add to history
  metricsHistory.push(data);
  if (metricsHistory.length > MAX_HISTORY) {
    metricsHistory.shift();
  }

  // Update summary
  document.getElementById('msg-sent').textContent = data.messages_sent || 0;
  document.getElementById('msg-recv').textContent = data.messages_received || 0;
  document.getElementById('msg-dropped').textContent = data.messages_dropped || 0;
  document.getElementById('latency-p99').textContent = data.latency_p99_ns || 0;

  // Update charts
  const labels = metricsHistory.map((_, i) => i);
  const latencies = metricsHistory.map(m => (m.latency_p99_ns || 0) / 1000); // ns → µs

  latencyChart.data.labels = labels;
  latencyChart.data.datasets[0].data = latencies;
  latencyChart.update('none');

  const latest = metricsHistory[metricsHistory.length - 1] || {};
  throughputChart.data.datasets[0].data = [
    latest.messages_sent || 0,
    latest.messages_received || 0,
    latest.messages_dropped || 0
  ];
  throughputChart.update('none');
}

function updateTopics(data) {
  const topics = data.topics || [];
  const tbody = document.getElementById('topics-body');

  if (topics.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #999; padding: 2rem;"><strong>📡 Tier 0 Limitation</strong><br/>Topic discovery requires multicast SPDP/SEDP (available in Tier 1+).<br/>Topics are currently visible only within participant processes.</td></tr>';
    return;
  }

  tbody.innerHTML = topics.map(t => `
    <tr>
      <td>${t.name}</td>
      <td>${t.type_name || '-'}</td>
      <td>${t.writers_count || 0}</td>
      <td>${t.readers_count || 0}</td>
    </tr>
  `).join('');
}

function updateStatus(connected) {
  const statusEl = document.getElementById('status');
  if (connected) {
    statusEl.textContent = '● Connected';
    statusEl.className = 'ok';
  } else {
    statusEl.textContent = '● Disconnected';
    statusEl.className = 'error';
  }
}

function updateLastUpdate() {
  const now = new Date();
  const time = now.toLocaleTimeString();
  document.getElementById('last-update').textContent = time;
}

// Auto-Refresh Loop
setInterval(() => {
  fetchMesh();
  fetchMetrics();
  updateLastUpdate();
}, REFRESH_INTERVAL_MS);

// Recenter button handler
document.getElementById('recenter-btn').addEventListener('click', function() {
  console.log('[D3] Recentering nodes...');

  // Release all fixed positions AND reset to center
  const nodes = simulation.nodes();
  const centerX = width / 2;
  const centerY = height / 2;

  nodes.forEach(n => {
    n.fx = null;  // Release fixed position
    n.fy = null;
    n.x = centerX + (Math.random() - 0.5) * 100; // Reset near center with small random offset
    n.y = centerY + (Math.random() - 0.5) * 100;
    n.vx = 0;  // Reset velocity
    n.vy = 0;
  });

  // Restart simulation with high energy to re-layout
  simulation.alpha(0.8).restart();

  console.log('[D3] Nodes recentered, simulation restarted');
});

// Initial Fetch
async function initialize() {
  await fetchMesh(); // First load to initialize graph
  await fetchMetrics();
  await fetchTopics();
  updateLastUpdate();
  console.log('🚀 HDDS Debugger initialized (10 Hz auto-refresh)');
}

initialize();
