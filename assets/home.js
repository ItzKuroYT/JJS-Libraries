import { authLogin, authSignup, fetchOnlineUsers, startPresence, stopPresence, uploadAvatar } from './api.js';
import { applyTheme, getCurrentUser, getProfile, getTheme, setProfile, setToken, subscribe, toggleTheme } from './state.js';
import { renderAuthPanel, renderHomeAuthed, renderSettingsModal, renderTopBar } from './components.js';

const topBarRoot = document.getElementById('appTopBar');
const homeRoot = document.getElementById('homeRoot');
const modalRoot = document.getElementById('modalRoot');

let onlineUsers = [];

function fadeNavigate(path) {
  const targets = [document.getElementById('topbarTransition'), document.getElementById('homeTransition')].filter(Boolean);
  targets.forEach(el => el.classList.add('fade-out'));
  setTimeout(() => { window.location.href = path; }, 180);
}

function wireTopBar(isAuthed) {
  const authActions = document.getElementById('topbarAuthActions');
  const settingsBtn = document.getElementById('settingsBtn');
  const themeBtn = document.getElementById('themeToggleBtn');
  const dmBtn = document.getElementById('dmBtn');
  const navMovesets = document.getElementById('navMovesets');
  const navForums = document.getElementById('navForums');

  if (authActions) {
    if (isAuthed) {
      const user = getCurrentUser();
      authActions.innerHTML = `
        <span class="muted">Signed in as <strong>${user.username}</strong></span>
        <button class="btn" id="logoutBtn">Logout</button>
      `;
      const logoutBtn = document.getElementById('logoutBtn');
      if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
          stopPresence();
          setToken('');
        });
      }
    } else {
      authActions.innerHTML = '<span class="muted">Not signed in</span>';
    }
  }

  if (themeBtn) themeBtn.addEventListener('click', () => toggleTheme());
  if (dmBtn) {
    dmBtn.disabled = !isAuthed;
    dmBtn.addEventListener('click', () => {
      if (!isAuthed) return;
      fadeNavigate('Moveset.html');
    });
  }
  if (settingsBtn) {
    settingsBtn.disabled = !isAuthed;
    settingsBtn.addEventListener('click', () => {
      if (!isAuthed) return;
      openSettings();
    });
  }

  if (navMovesets) {
    navMovesets.addEventListener('click', (event) => {
      if (!isAuthed) {
        event.preventDefault();
        return;
      }
      event.preventDefault();
      fadeNavigate('Moveset.html');
    });
  }

  if (navForums) {
    navForums.addEventListener('click', (event) => {
      event.preventDefault();
      alert('Forums page is reserved and will be enabled later.');
    });
  }
}

async function bindAuthActions() {
  const signinBtn = document.getElementById('signinBtn');
  const signupBtn = document.getElementById('signupBtn');
  const status = document.getElementById('authStatus');

  const runAuth = async (mode) => {
    const username = document.getElementById('authUser')?.value?.trim();
    const password = document.getElementById('authPass')?.value || '';
    if (!username || !password) {
      if (status) status.textContent = 'Username and password are required.';
      return;
    }
    try {
      const data = mode === 'signup'
        ? await authSignup(username, password)
        : await authLogin(username, password);
      if (data && data.token) {
        setToken(data.token);
        if (status) status.textContent = '';
      }
    } catch (error) {
      if (status) status.textContent = error.message || 'Authentication failed.';
    }
  };

  if (signinBtn) signinBtn.addEventListener('click', () => runAuth('login'));
  if (signupBtn) signupBtn.addEventListener('click', () => runAuth('signup'));
}

function fileToDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function closeSettings() {
  modalRoot.innerHTML = '';
}

function openSettings() {
  const profile = getProfile();
  modalRoot.innerHTML = renderSettingsModal(profile);

  const modal = document.getElementById('settingsModal');
  const closeBtn = document.getElementById('closeSettingsBtn');
  const saveBtn = document.getElementById('saveSettingsBtn');
  const themeSelect = document.getElementById('setTheme');
  if (themeSelect) themeSelect.value = getTheme();

  if (closeBtn) closeBtn.addEventListener('click', closeSettings);
  if (modal) {
    modal.addEventListener('click', (event) => {
      if (event.target === modal) closeSettings();
    });
  }

  if (saveBtn) {
    saveBtn.addEventListener('click', async () => {
      const nextSocial = (getProfile().socialLinks || []).map((entry, index) => {
        const input = document.querySelector(`[data-social-index="${index}"]`);
        return { label: entry.label, url: input ? input.value.trim() : '' };
      });

      const bannerFile = document.getElementById('setBannerFile')?.files?.[0] || null;
      const avatarFile = document.getElementById('setAvatarFile')?.files?.[0] || null;

      const profilePatch = {
        pronouns: document.getElementById('setPronouns')?.value?.trim() || '',
        bio: document.getElementById('setBio')?.value?.trim() || '',
        socialLinks: nextSocial
      };

      if (bannerFile) {
        try { profilePatch.bannerUrl = await fileToDataUrl(bannerFile); } catch (_) {}
      }

      if (avatarFile) {
        try {
          const uploaded = await uploadAvatar(avatarFile);
          if (uploaded && uploaded.url) profilePatch.avatarUrl = uploaded.url;
          else profilePatch.avatarUrl = await fileToDataUrl(avatarFile);
        } catch (_) {
          try { profilePatch.avatarUrl = await fileToDataUrl(avatarFile); } catch (_) {}
        }
      }

      setProfile(profilePatch);
      applyTheme(document.getElementById('setTheme')?.value || getTheme());
      closeSettings();
      await refreshOnlineUsers();
      render();
    });
  }
}

async function refreshOnlineUsers() {
  if (!getCurrentUser()) {
    onlineUsers = [];
    return;
  }
  try {
    onlineUsers = await fetchOnlineUsers();
  } catch (_) {
    onlineUsers = [];
  }
}

async function render() {
  const user = getCurrentUser();
  const profile = getProfile();
  const isAuthed = !!user;

  topBarRoot.innerHTML = renderTopBar({ isAuthed, currentPage: 'home' });
  wireTopBar(isAuthed);

  if (!isAuthed) {
    stopPresence();
    homeRoot.innerHTML = renderAuthPanel();
    await bindAuthActions();
    return;
  }

  if (!profile.username || profile.username === 'Guest') {
    setProfile({ username: user.username });
  }

  homeRoot.innerHTML = renderHomeAuthed({ profile: getProfile(), user, onlineUsers });
  const openMyProfileBtn = document.getElementById('openMyProfileBtn');
  if (openMyProfileBtn) {
    openMyProfileBtn.addEventListener('click', (event) => {
      event.preventDefault();
      fadeNavigate('profile.html');
    });
  }
  startPresence(async (users) => {
    onlineUsers = users;
    const onlineSlot = document.getElementById('onlineUsersSlot');
    if (onlineSlot) {
      const next = renderHomeAuthed({ profile: getProfile(), user: getCurrentUser(), onlineUsers }).match(/<aside id="onlineUsersSlot">([\s\S]*)<\/aside>/);
      if (next && next[1]) onlineSlot.innerHTML = next[1];
    }
  });
}

applyTheme(getTheme());
await refreshOnlineUsers();
await render();
subscribe(async () => {
  applyTheme(getTheme());
  await refreshOnlineUsers();
  await render();
});
