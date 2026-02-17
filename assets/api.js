import { getCurrentUser, getToken, getProfile, setCachedUserInfo } from './state.js';

const USERS_URL = '/api/users';

async function readJson(resp) {
  const data = await resp.json().catch(() => null);
  if (!resp.ok) {
    throw new Error((data && data.error) || 'Request failed');
  }
  return data || {};
}

export async function authSignup(username, password) {
  const resp = await fetch(`${USERS_URL}?action=signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  return await readJson(resp);
}

export async function authLogin(username, password) {
  const resp = await fetch(`${USERS_URL}?action=login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  return await readJson(resp);
}

export async function uploadAvatar(file) {
  const user = getCurrentUser();
  if (!user || !file) return null;
  const reader = new FileReader();
  const dataUrl = await new Promise((resolve, reject) => {
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
  const resp = await fetch('/api/save-lib?action=uploadAvatar', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: user.username, dataUrl })
  });
  return await readJson(resp);
}

let presenceTimer = null;
let refreshTimer = null;
const tabId = `${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;

function presenceHeaders() {
  const token = getToken();
  if (!token) return null;
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  };
}

async function postPresence(action, extra = {}) {
  const headers = presenceHeaders();
  if (!headers) return null;
  const profile = getProfile();
  const resp = await fetch(`${USERS_URL}?action=${action}`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      tabId,
      profile: {
        avatarUrl: profile.avatarUrl,
        pronouns: profile.pronouns,
        bio: profile.bio
      },
      ...extra
    })
  });
  return await readJson(resp);
}

export async function fetchOnlineUsers() {
  const headers = presenceHeaders();
  if (!headers) return [];
  const resp = await fetch(`${USERS_URL}?action=presenceList`, { headers });
  const data = await readJson(resp);
  const users = Array.isArray(data.users) ? data.users : [];
  users.forEach(u => {
    if (u && u.username) {
      setCachedUserInfo(u.username, {
        username: u.username,
        avatarUrl: u.avatarUrl || '',
        pronouns: u.pronouns || '',
        bio: u.bio || ''
      });
    }
  });
  return users;
}

export function startPresence(onUsersUpdate) {
  if (!getCurrentUser()) return;
  const tick = async () => {
    try { await postPresence('presencePing'); } catch (_) {}
  };
  const refresh = async () => {
    try {
      const users = await fetchOnlineUsers();
      if (typeof onUsersUpdate === 'function') onUsersUpdate(users);
    } catch (_) {
      if (typeof onUsersUpdate === 'function') onUsersUpdate([]);
    }
  };

  tick();
  refresh();
  clearInterval(presenceTimer);
  clearInterval(refreshTimer);
  presenceTimer = setInterval(tick, 25000);
  refreshTimer = setInterval(refresh, 8000);

  window.addEventListener('beforeunload', () => {
    const token = getToken();
    if (!token) return;
    try {
      fetch(`${USERS_URL}?action=presenceLeave`, {
        method: 'POST',
        keepalive: true,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ tabId })
      }).catch(() => {});
    } catch (_) {}
  }, { once: true });
}

export function stopPresence() {
  if (presenceTimer) clearInterval(presenceTimer);
  if (refreshTimer) clearInterval(refreshTimer);
  presenceTimer = null;
  refreshTimer = null;
}
