const runButton = document.getElementById('run-btn');
const statusLabel = document.getElementById('job-status');
const summaryBox = document.getElementById('summary-box');
const graphBox = document.getElementById('graph-box');
const findingsBox = document.getElementById('findings-box');

function token() {
  return localStorage.getItem('token') || '';
}

const map = L.map('map').setView([20, 0], 2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  maxZoom: 19,
  attribution: '&copy; OpenStreetMap',
}).addTo(map);

const locationCoords = {
  'Austin, TX': [30.2672, -97.7431],
  'San Marcos, TX': [29.8833, -97.9414],
};

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
    const graphData = await graphRes.json();
    graphBox.textContent = JSON.stringify(graphData, null, 2);
    graphData.nodes
      .filter((n) => n.type === 'Location')
      .forEach((n) => {
        const c = locationCoords[n.label];
        if (c) L.marker(c).addTo(map).bindPopup(n.label);
      });
  }
}

if (runButton) {
  runButton.addEventListener('click', async () => {
    const caseId = runButton.dataset.caseId;
    const imageB64 = sessionStorage.getItem(`case-image-${caseId}`) || '';
    statusLabel.textContent = 'Starting investigation...';

    const body = new FormData();
    body.append('image_b64', imageB64);

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
