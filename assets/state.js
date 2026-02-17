const AUTH_KEY = 'jjs_token';
const THEME_KEY = 'jjs_theme';
const PROFILE_KEY = 'jjs_profile_v2';
const USER_CACHE_KEY = 'jjs_cached_user_info';

const listeners = new Set();

function notify() {
  const snap = getState();
  listeners.forEach(fn => {
    try { fn(snap); } catch (_) {}
  });
}

function decodeToken(token) {
  if (!token) return null;
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

export function getToken() {
  try { return localStorage.getItem(AUTH_KEY) || ''; } catch (_) { return ''; }
}

export function setToken(token) {
  try {
    if (token) localStorage.setItem(AUTH_KEY, token);
    else localStorage.removeItem(AUTH_KEY);
  } catch (_) {}
  notify();
}

export function getCurrentUser() {
  const token = getToken();
  const payload = decodeToken(token);
  if (!payload || !payload.username) return null;
  return {
    id: payload.id,
    username: payload.username,
    role: payload.role || 'member'
  };
}

export function isAuthenticated() {
  return !!getCurrentUser();
}

export function getTheme() {
  try { return localStorage.getItem(THEME_KEY) || 'dark'; } catch (_) { return 'dark'; }
}

export function applyTheme(theme) {
  const nextTheme = theme === 'light' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', nextTheme);
  try { localStorage.setItem(THEME_KEY, nextTheme); } catch (_) {}
}

export function toggleTheme() {
  const next = getTheme() === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  notify();
}

function defaultProfile() {
  const user = getCurrentUser();
  return {
    username: user?.username || 'Guest',
    pronouns: '',
    bio: '',
    avatarUrl: '',
    bannerUrl: '',
    socialLinks: [
      { label: 'Discord', url: '' },
      { label: 'Reddit', url: '' },
      { label: 'YouTube', url: '' }
    ]
  };
}

export function getProfile() {
  const base = defaultProfile();
  try {
    const raw = JSON.parse(localStorage.getItem(PROFILE_KEY) || '{}');
    const merged = Object.assign(base, raw || {});
    if (!Array.isArray(merged.socialLinks)) merged.socialLinks = base.socialLinks;
    return merged;
  } catch (_) {
    return base;
  }
}

export function setProfile(profilePatch) {
  const next = Object.assign(getProfile(), profilePatch || {});
  try { localStorage.setItem(PROFILE_KEY, JSON.stringify(next)); } catch (_) {}
  const user = getCurrentUser();
  if (user) {
    setCachedUserInfo(user.username, {
      username: user.username,
      avatarUrl: next.avatarUrl,
      pronouns: next.pronouns,
      bio: next.bio,
      bannerUrl: next.bannerUrl
    });
    try {
      const socialKey = 'jjs_social_' + String(user.username).toLowerCase();
      const existingSocial = JSON.parse(localStorage.getItem(socialKey) || '{}') || {};
      const mergedSocial = Object.assign({}, existingSocial, {
        bio: next.bio || existingSocial.bio || '',
        pronouns: next.pronouns || existingSocial.pronouns || '',
        avatar_url: next.avatarUrl || existingSocial.avatar_url || '',
        banner_url: next.bannerUrl || existingSocial.banner_url || '',
        links: Array.isArray(next.socialLinks) ? next.socialLinks.filter(link => link && link.url) : (existingSocial.links || [])
      });
      localStorage.setItem(socialKey, JSON.stringify(mergedSocial));
      localStorage.setItem('jjs_social_' + user.username, JSON.stringify(mergedSocial));
    } catch (_) {}
  }
  notify();
}

export function getCachedUsers() {
  try { return JSON.parse(localStorage.getItem(USER_CACHE_KEY) || '{}') || {}; } catch (_) { return {}; }
}

export function setCachedUserInfo(username, data) {
  if (!username) return;
  const key = String(username).toLowerCase();
  const map = getCachedUsers();
  map[key] = Object.assign({}, map[key] || {}, data || {}, { updatedAt: Date.now() });
  try { localStorage.setItem(USER_CACHE_KEY, JSON.stringify(map)); } catch (_) {}
}

export function getCachedUserInfo(username) {
  if (!username) return null;
  const map = getCachedUsers();
  return map[String(username).toLowerCase()] || null;
}

export function subscribe(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getState() {
  return {
    user: getCurrentUser(),
    theme: getTheme(),
    profile: getProfile()
  };
}
