const runButton = document.getElementById('run-btn');
const statusLabel = document.getElementById('job-status');
const summaryBox = document.getElementById('summary-box');
const graphBox = document.getElementById('graph-box');
const findingsBox = document.getElementById('findings-box');

async function refreshCaseData(caseId) {
  const [summaryRes, graphRes] = await Promise.all([
    fetch(`/api/cases/${caseId}/summary`),
    fetch(`/api/cases/${caseId}/graph`),
  ]);

  if (summaryRes.ok) {
    const data = await summaryRes.json();
    summaryBox.textContent = data.summary;
  }

  if (graphRes.ok) {
    const graphData = await graphRes.json();
    graphBox.textContent = JSON.stringify(graphData, null, 2);
  }
}

if (runButton) {
  runButton.addEventListener('click', async () => {
    const caseId = runButton.dataset.caseId;
    statusLabel.textContent = 'Starting investigation...';
    const jobRes = await fetch(`/api/cases/${caseId}/investigate`, { method: 'POST' });

    if (!jobRes.ok) {
      statusLabel.textContent = 'Failed to start investigation.';
      return;
    }

    const { job_id: jobId } = await jobRes.json();
    statusLabel.textContent = `Job ${jobId} running...`;

    const poll = setInterval(async () => {
      const statusRes = await fetch(`/api/jobs/${jobId}`);
      if (!statusRes.ok) return;
      const job = await statusRes.json();
      statusLabel.textContent = `Latest job: ${job.status}`;

      if (job.status === 'completed') {
        clearInterval(poll);
        findingsBox.textContent = JSON.stringify(job.findings, null, 2);
        await refreshCaseData(caseId);
      }
    }, 700);
  });
}
