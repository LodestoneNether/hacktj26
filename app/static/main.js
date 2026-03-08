const authForm = document.getElementById('auth-form');
const authStatus = document.getElementById('auth-status');
const caseForm = document.getElementById('case-form');
const createStatus = document.getElementById('create-status');
const addKnownBtn = document.getElementById('add-known-account');
const knownList = document.getElementById('known-accounts-list');
const knownHidden = document.getElementById('known-accounts-hidden');

function token() {
  return localStorage.getItem('token') || '';
}

function renderKnownRow(platform = 'instagram', handle = '') {
  const row = document.createElement('div');
  row.className = 'known-row';
  row.innerHTML = `
    <select class="known-platform">
      <option value="instagram">instagram</option>
      <option value="x">x</option>
      <option value="github">github</option>
      <option value="reddit">reddit</option>
      <option value="tiktok">tiktok</option>
      <option value="medium">medium</option>
    </select>
    <input class="known-handle" placeholder="username" value="${handle}" />
    <button type="button" class="remove-known">Remove</button>
  `;
  row.querySelector('.known-platform').value = platform;
  row.querySelector('.remove-known').addEventListener('click', () => {
    row.remove();
    syncKnownAccounts();
  });
  row.querySelector('.known-platform').addEventListener('change', syncKnownAccounts);
  row.querySelector('.known-handle').addEventListener('input', syncKnownAccounts);
  knownList.appendChild(row);
}

function syncKnownAccounts() {
  if (!knownList || !knownHidden) return;
  const rows = Array.from(knownList.querySelectorAll('.known-row'));
  const serialized = rows
    .map((row) => {
      const platform = row.querySelector('.known-platform').value.trim();
      const handle = row.querySelector('.known-handle').value.trim();
      if (!handle) return null;
      return `${platform}:${handle}`;
    })
    .filter(Boolean)
    .join(',');
  knownHidden.value = serialized;
}

if (addKnownBtn) {
  addKnownBtn.addEventListener('click', () => {
    renderKnownRow();
    syncKnownAccounts();
  });
  renderKnownRow('instagram', '');
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
    syncKnownAccounts();
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
    sessionStorage.setItem(`case-images-${data.case_id}`, data.images_b64_json || '[]');
    window.location.href = `/cases/${data.case_id}`;
  });
}
