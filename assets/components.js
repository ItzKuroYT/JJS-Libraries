import { getCachedUserInfo } from './state.js';

const FALLBACK_AVATAR = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96"><rect width="96" height="96" fill="%23202838"/><circle cx="48" cy="34" r="16" fill="%238696ab"/><rect x="22" y="58" width="52" height="24" rx="12" fill="%238696ab"/></svg>';

function safeText(value, fallback = '') {
  return String(value == null ? fallback : value);
}

export function navLink({ href = '#', label = '', active = false, disabled = false, id = '' }) {
  const disabledAttr = disabled ? 'aria-disabled="true"' : '';
  const idAttr = id ? `id="${id}"` : '';
  return `<a ${idAttr} class="nav-link ${active ? 'active' : ''}" href="${href}" ${disabledAttr}>${safeText(label)}</a>`;
}

export function renderTopBar({ isAuthed = false, currentPage = 'home' }) {
  return `
    <div class="topbar page-transition" id="topbarTransition">
      <div class="topbar-left" id="topbarAuthActions"></div>
      <div class="brand-wrap">
        <h1>JJS Libraries</h1>
        <div class="nav-links">
          ${navLink({ href: 'Moveset.html', label: 'Movesets', active: currentPage === 'moveset', disabled: !isAuthed, id: 'navMovesets' })}
          ${navLink({ href: '#', label: 'Skillbuilder Forums', active: currentPage === 'forums', disabled: true, id: 'navForums' })}
        </div>
      </div>
      <div class="topbar-right">
        <button class="btn" id="dmBtn">DMs</button>
        <button class="btn" id="settingsBtn">Settings</button>
        <button class="btn" id="themeToggleBtn">Toggle Theme</button>
      </div>
    </div>
  `;
}

export function renderAuthPanel() {
  return `
    <section class="panel hero">
      <h2>Welcome to JJS Libraries</h2>
      <p class="muted">Sign in to access your profile hub, live online members, and navigation into movesets.</p>
      <form class="auth-form" id="authForm">
        <input id="authUser" minlength="4" maxlength="15" placeholder="Username" required />
        <input id="authPass" type="password" minlength="4" placeholder="Password" required />
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn" type="button" id="signinBtn">Sign in</button>
          <button class="btn primary" type="button" id="signupBtn">Sign up</button>
        </div>
      </form>
      <p class="muted" id="authStatus"></p>
    </section>
  `;
}

export function renderCompactProfileCard(profile, user) {
  const avatar = safeText(profile.avatarUrl || getCachedUserInfo(user?.username)?.avatarUrl || FALLBACK_AVATAR, FALLBACK_AVATAR);
  return `
    <section class="panel profile-card-compact">
      <h3 style="margin-top:0">Profile</h3>
      <div class="profile-row">
        <img class="avatar" src="${avatar}" alt="avatar" />
        <div>
          <div><strong>${safeText(user?.username || 'Unknown')}</strong></div>
          <div class="muted">${safeText(profile.pronouns || 'No pronouns set')}</div>
        </div>
      </div>
      <p class="muted" style="margin-bottom:0">${safeText(profile.bio || 'No bio yet.')}</p>
      <div style="margin-top:10px"><a href="profile.html" id="openMyProfileBtn" class="btn" style="display:inline-block">Open Full Profile</a></div>
    </section>
  `;
}

export function renderFullProfileCard(profile, user) {
  const avatar = safeText(profile.avatarUrl || getCachedUserInfo(user?.username)?.avatarUrl || FALLBACK_AVATAR, FALLBACK_AVATAR);
  const socials = Array.isArray(profile.socialLinks) ? profile.socialLinks.filter(link => link && link.url) : [];
  const iconFor = (label = '') => {
    const key = String(label).toLowerCase();
    if (key.includes('discord')) return '🎮';
    if (key.includes('reddit')) return '👽';
    if (key.includes('youtube')) return '▶️';
    if (key.includes('twitter') || key.includes('x')) return '🐦';
    return '🔗';
  };
  return `
    <section class="panel profile-card-full">
      <div class="profile-banner" style="${profile.bannerUrl ? `background-image:url('${profile.bannerUrl}');background-size:cover;background-position:center;` : ''}"></div>
      <div class="profile-body">
        <img class="profile-avatar-lg" src="${avatar}" alt="profile" />
        <h3>${safeText(user?.username || profile.username || 'User')}</h3>
        <div class="muted">${safeText(profile.pronouns || 'Pronouns not set')}</div>
        <p>${safeText(profile.bio || 'Add a bio in settings to personalize your profile card.')}</p>
        <div class="social-links">
          ${socials.length ? socials.map(link => `<a class="social-chip" href="${safeText(link.url)}" target="_blank" rel="noopener noreferrer">${iconFor(link.label)} ${safeText(link.label || 'Link')}</a>`).join('') : '<span class="muted">No social links set</span>'}
        </div>
      </div>
    </section>
  `;
}

export function renderOnlineUsers(users = []) {
  if (!users.length) {
    return `<section class="panel"><h3 style="margin-top:0">Online Users</h3><p class="muted">No users online right now.</p></section>`;
  }
  return `
    <section class="panel">
      <h3 style="margin-top:0">Online Users (${users.length})</h3>
      <div class="online-list">
        ${users.map(user => {
          const cached = getCachedUserInfo(user.username) || {};
          const avatar = safeText(user.avatarUrl || cached.avatarUrl || FALLBACK_AVATAR, FALLBACK_AVATAR);
          const pronouns = safeText(user.pronouns || cached.pronouns || '');
          const bio = safeText(user.bio || cached.bio || 'No bio provided');
          return `
            <article class="online-item">
              <img class="avatar" src="${avatar}" alt="${safeText(user.username)}" style="width:34px;height:34px"/>
              <div>${safeText(user.username)}</div>
              <span class="online-dot"></span>
              <div class="online-tooltip">
                <strong>${safeText(user.username)}</strong>
                <div class="muted">${pronouns || 'Pronouns not set'}</div>
                <div class="muted">${bio}</div>
              </div>
            </article>
          `;
        }).join('')}
      </div>
    </section>
  `;
}

export function renderHomeAuthed({ profile, user, onlineUsers }) {
  return `
    <section class="home-layout page-transition" id="homeTransition">
      <aside>
        ${renderCompactProfileCard(profile, user)}
      </aside>
      <section>
        <div class="panel hero">
          <h2 style="margin-top:0">Main Hub</h2>
          <p class="muted">Use the top navigation to go to Movesets. Skillbuilder Forums is currently a placeholder.</p>
          <div class="panel" style="margin-top:10px">
            <strong>Quick Actions</strong>
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
              <a class="btn" href="profile.html">View Full Profile</a>
              <a class="btn" href="Moveset.html">Open Movesets</a>
            </div>
          </div>
        </div>
      </section>
      <aside id="onlineUsersSlot">
        ${renderOnlineUsers(onlineUsers)}
      </aside>
    </section>
  `;
}

export function renderSettingsModal(profile) {
  const links = Array.isArray(profile.socialLinks) && profile.socialLinks.length
    ? profile.socialLinks
    : [{ label: 'Discord', url: '' }, { label: 'Reddit', url: '' }, { label: 'YouTube', url: '' }];

  return `
    <div class="modal-backdrop" id="settingsModal">
      <section class="modal-card">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:10px">
          <h3 style="margin:0">Settings</h3>
          <button class="btn" id="closeSettingsBtn">Close</button>
        </div>
        <p class="muted">Customize profile, pronouns, bio, social links, banner, picture, and theme.</p>
        <div class="field-grid">
          <label>Pronouns<input id="setPronouns" value="${safeText(profile.pronouns)}" /></label>
          <label>Theme
            <select id="setTheme" class="btn" style="padding:9px">
              <option value="dark">Dark</option>
              <option value="light">Light</option>
            </select>
          </label>
        </div>
        <div class="field-stack" style="margin-top:10px">
          <label>Bio<textarea id="setBio" rows="3">${safeText(profile.bio)}</textarea></label>
        </div>
        <div class="field-grid" style="margin-top:10px">
          <label>Profile picture upload<input id="setAvatarFile" type="file" accept="image/*" /></label>
          <label>Banner upload<input id="setBannerFile" type="file" accept="image/*" /></label>
        </div>
        <h4>Social Links</h4>
        <div class="field-grid" id="socialRows">
          ${links.map((link, index) => `
            <label>${safeText(link.label || `Link ${index + 1}`)}
              <input data-social-index="${index}" value="${safeText(link.url || '')}" placeholder="https://..." />
            </label>
          `).join('')}
        </div>
        <div style="display:flex;gap:8px;margin-top:12px">
          <button class="btn primary" id="saveSettingsBtn">Save</button>
        </div>
      </section>
    </div>
  `;
}
