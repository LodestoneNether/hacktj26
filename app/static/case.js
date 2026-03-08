const runButton = document.getElementById('run-btn');
const statusLabel = document.getElementById('job-status');
const summaryBox = document.getElementById('summary-box');
const graphBox = document.getElementById('graph-box');
const findingsBox = document.getElementById('findings-box');
const includeFalsePositives = document.getElementById('include-false-positives');
const confidenceSlider = document.getElementById('confidence-slider');
const confidenceValue = document.getElementById('confidence-value');

function token() {
  return localStorage.getItem('token') || '';
}

const map = L.map('map').setView([20, 0], 2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  maxZoom: 19,
  attribution: '&copy; OpenStreetMap',
}).addTo(map);

let markers = [];
let latestGraphData = { nodes: [], links: [] };
let network = null;

function clearMarkers() {
  markers.forEach((m) => map.removeLayer(m));
  markers = [];
}

function plotGraphLocations(graphData) {
  clearMarkers();
  const points = graphData.nodes
    .filter((n) => n.type === 'Location' && Number.isFinite(n.lat) && Number.isFinite(n.lon))
    .map((n) => ({ lat: n.lat, lon: n.lon, label: n.label, method: n.method || 'unknown' }));

  if (!points.length) return;

  points.forEach((p) => {
    const marker = L.marker([p.lat, p.lon]).addTo(map).bindPopup(`${p.label} (${p.method})`);
    markers.push(marker);
  });

  const group = L.featureGroup(markers);
  map.fitBounds(group.getBounds().pad(0.2));
}

function getNodeConfidence(node) {
  if (typeof node.confidence === 'number') return node.confidence;
  if (typeof node.score === 'number') return node.score;
  return 1.0;
}

function renderSocialGraph(graphData) {
  const container = document.getElementById('social-graph');
  if (!container || typeof vis === 'undefined') return;

  const withFalsePositives = includeFalsePositives?.checked ?? false;
  const threshold = Number(confidenceSlider?.value || 0);
  if (confidenceValue) confidenceValue.textContent = threshold.toFixed(2);

  const filteredNodes = graphData.nodes.filter((n) => {
    if (!withFalsePositives && n.type === 'FalsePositiveAccount') return false;
    const nodeConfidence = getNodeConfidence(n);
    const hasConfidence = ['PlatformAccount', 'SimilarAccount', 'FalsePositiveAccount'].includes(n.type);
    return !hasConfidence || nodeConfidence >= threshold;
  });
  const nodeIds = new Set(filteredNodes.map((n) => n.id));
  const filteredEdges = graphData.links.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target));

  const visNodes = new vis.DataSet(
    filteredNodes.map((n) => ({
      id: n.id,
      label: n.label,
      title: `${n.type}${n.url ? `\n${n.url}` : ''}${n.confidence ? `\nconfidence: ${n.confidence}` : ''}`,
      color:
        n.type === 'FalsePositiveAccount'
          ? '#ef4444'
          : n.type === 'PlatformAccount'
            ? '#22c55e'
            : n.type === 'SimilarAccount'
              ? '#3b82f6'
              : '#94a3b8',
      url: n.url,
    }))
  );

  const visEdges = new vis.DataSet(
    filteredEdges.map((e, idx) => ({ id: idx + 1, from: e.source, to: e.target, label: e.label, arrows: 'to' }))
  );

  const data = { nodes: visNodes, edges: visEdges };
  const options = {
    physics: { stabilization: false },
    nodes: { shape: 'dot', size: 12, font: { color: '#e2e8f0' } },
    edges: { color: '#64748b', font: { color: '#94a3b8', size: 10 } },
    interaction: { hover: true },
  };

  if (network) network.destroy();
  network = new vis.Network(container, data, options);
  network.on('click', (params) => {
    if (!params.nodes?.length) return;
    const clicked = visNodes.get(params.nodes[0]);
    if (clicked?.url) {
      window.open(clicked.url, '_blank', 'noopener,noreferrer');
    }
  });
}

async function refreshCaseData(caseId) {
  const [summaryRes, graphRes] = await Promise.all([
    fetch(`/api/cases/${caseId}/summary`, { headers: { Authorization: `Bearer ${token()}` } }),
    fetch(`/api/cases/${caseId}/graph`, { headers: { Authorization: `Bearer ${token()}` } }),
  ]);

  if (summaryRes.ok) {
    const data = await summaryRes.json();
    summaryBox.textContent = data.summary;
  }

  if (graphRes.ok) {
    latestGraphData = await graphRes.json();
    graphBox.textContent = JSON.stringify(latestGraphData, null, 2);
    plotGraphLocations(latestGraphData);
    renderSocialGraph(latestGraphData);
  }
}

if (includeFalsePositives) {
  includeFalsePositives.addEventListener('change', () => renderSocialGraph(latestGraphData));
}
if (confidenceSlider) {
  confidenceSlider.addEventListener('input', () => renderSocialGraph(latestGraphData));
}

if (runButton) {
  runButton.addEventListener('click', async () => {
    const caseId = runButton.dataset.caseId;
    const imagesB64Json = sessionStorage.getItem(`case-images-${caseId}`) || '[]';
    statusLabel.textContent = 'Starting investigation...';

    const body = new FormData();
    body.append('images_b64_json', imagesB64Json);

    const jobRes = await fetch(`/api/cases/${caseId}/investigate`, {
      method: 'POST',
      body,
      headers: { Authorization: `Bearer ${token()}` },
    });

    if (!jobRes.ok) {
      statusLabel.textContent = 'Failed to start investigation.';
      return;
    }

    const { job_id: jobId } = await jobRes.json();
    const poll = setInterval(async () => {
      const statusRes = await fetch(`/api/jobs/${jobId}`, { headers: { Authorization: `Bearer ${token()}` } });
      if (!statusRes.ok) return;
      const job = await statusRes.json();
      statusLabel.textContent = `Latest job: ${job.status}`;
      if (job.status === 'completed') {
        clearInterval(poll);
        findingsBox.textContent = JSON.stringify(job.findings, null, 2);
        await refreshCaseData(caseId);
      }
    }, 800);
  });
}
