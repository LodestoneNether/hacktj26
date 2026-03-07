const authForm = document.getElementById('auth-form');
const authStatus = document.getElementById('auth-status');
const caseForm = document.getElementById('case-form');
const createStatus = document.getElementById('create-status');

function token() {
  return localStorage.getItem('token') || '';
}

if (authForm) {
  authForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = new FormData(authForm);
    const body = new URLSearchParams();
    body.append('username', data.get('username'));
    body.append('password', data.get('password'));

    const res = await fetch('/api/auth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });

    if (!res.ok) {
      authStatus.textContent = 'Login failed';
      return;
    }
    const payload = await res.json();
    localStorage.setItem('token', payload.access_token);
    authStatus.textContent = 'Authenticated';
  });
}

if (caseForm) {
  caseForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    createStatus.textContent = 'Creating case...';
    const payload = new FormData(caseForm);

    const res = await fetch('/api/cases', {
      method: 'POST',
      body: payload,
      headers: { Authorization: `Bearer ${token()}` },
    });

    if (!res.ok) {
      createStatus.textContent = 'Failed to create case (check auth/compliance fields).';
      return;
    }
    const data = await res.json();
    sessionStorage.setItem(`case-image-${data.case_id}`, data.image_b64 || '');
    window.location.href = `/cases/${data.case_id}`;
  });
}
