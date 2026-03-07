const form = document.getElementById('case-form');
const statusEl = document.getElementById('create-status');

if (form) {
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    statusEl.textContent = 'Creating case...';
    const payload = new FormData(form);

    const response = await fetch('/api/cases', {
      method: 'POST',
      body: payload,
    });

    if (!response.ok) {
      statusEl.textContent = 'Failed to create case.';
      return;
    }

    const data = await response.json();
    statusEl.textContent = `Case created. Redirecting...`;
    window.location.href = `/cases/${data.case_id}`;
  });
}
