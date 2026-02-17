// Serverless user management (Vercel/Netlify compatible)
// Endpoints:
// POST /api/users?action=signup  { username, password }
// POST /api/users?action=login   { username, password }
// GET  /api/users?action=health  -> { configured: true/false }

// Configuration via environment variables (store as secrets):
// GITHUB_TOKEN - PAT with repo contents permissions
// GITHUB_OWNER - repo owner
// GITHUB_REPO  - repo name
// GITHUB_BRANCH - branch to commit to (default: main)
// GITHUB_USERS_PATH - path inside repo for users file (default: users/users.json)
// JWT_SECRET - secret used to sign tokens (set on your host)

const crypto = require('crypto');

let fetchFn = global.fetch;
try{ if(!fetchFn) fetchFn = require('node-fetch'); }catch(e){}

async function readBody(req){
  if (req.body && Object.keys(req.body).length) return req.body;
  if (typeof req.body === 'string'){ try{ return JSON.parse(req.body); }catch(e){} }
  return await new Promise((resolve, reject)=>{
    let data=''; req.on('data',c=>data+=c); req.on('end',()=>{ if(!data) return resolve({}); try{ resolve(JSON.parse(data)); }catch(e){ resolve({}); } }); req.on('error',reject);
  });
}

function sanitizeFilename(name){ return String(name).replace(/[^a-z0-9-_. ]/gi,'_').slice(0,60); }
function toBase64(str){ return Buffer.from(str,'utf8').toString('base64'); }
function fromBase64(str){ return Buffer.from(str,'base64').toString('utf8'); }

function hashPassword(password){
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}$${derived}`;
}

function verifyPassword(password, stored){
  const [salt, derived] = String(stored).split('$');
  if(!salt || !derived) return false;
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(check,'hex'), Buffer.from(derived,'hex'));
}

function signToken(payload, secret){
  const header = { alg: 'HS256', typ: 'JWT' };
  const b64 = (obj)=> Buffer.from(JSON.stringify(obj)).toString('base64url');
  const unsigned = b64(header)+'.'+b64(payload);
  const sig = crypto.createHmac('sha256', secret).update(unsigned).digest('base64url');
  return unsigned + '.' + sig;
}

function verifyToken(token, secret){
  try{
    const parts = token.split('.'); if(parts.length!==3) return null;
    const unsigned = parts[0]+'.'+parts[1];
    const sig = crypto.createHmac('sha256', secret).update(unsigned).digest('base64url');
    if(!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(parts[2]))) return null;
    const payload = JSON.parse(Buffer.from(parts[1],'base64url').toString('utf8'));
    if(payload.exp && Date.now()/1000 > payload.exp) return null;
    return payload;
  }catch(e){ return null; }
}

async function getUsers(token, owner, repo, branch, usersPath){
  const api = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(usersPath)}`;
  const resp = await fetchFn(`${api}?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
  if(resp.status===200){ const data = await resp.json(); const content = fromBase64(data.content); try{ return { users: JSON.parse(content), sha: data.sha }; }catch(e){ return { users: [], sha: data.sha }; } }
  return { users: [], sha: null };
}

async function putUsers(token, owner, repo, branch, usersPath, users, sha){
  const api = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(usersPath)}`;
  const content = toBase64(JSON.stringify(users, null, 2));
  const body = { message: 'Update users', content, branch };
  if(sha) body.sha = sha;
  const resp = await fetchFn(api, { method: 'PUT', headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json', 'Content-Type':'application/json' }, body: JSON.stringify(body) });
  return resp;
}

const OWNER_USERNAME = (process.env.OWNER_USERNAME || 'Kuro').toLowerCase();
const USERNAME_MIN_LENGTH = 4;
const USERNAME_MAX_LENGTH = 15;
const MAX_ACCOUNTS_PER_IP = 2;
const PRESENCE_TTL_MS = 60000;
const presenceStore = new Map();

function cleanupPresence(){
  const now = Date.now();
  for(const [key, entry] of presenceStore.entries()){
    if(!entry || !entry.lastSeen || (now - entry.lastSeen) > PRESENCE_TTL_MS){
      presenceStore.delete(key);
    }
  }
}

function safePresenceProfile(profile){
  const src = profile && typeof profile === 'object' ? profile : {};
  return {
    avatarUrl: String(src.avatarUrl || '').slice(0, 500),
    pronouns: String(src.pronouns || '').slice(0, 60),
    bio: String(src.bio || '').slice(0, 220)
  };
}

function buildPresenceList(){
  cleanupPresence();
  const grouped = new Map();
  for(const entry of presenceStore.values()){
    if(!entry || !entry.username) continue;
    const key = String(entry.username || '').toLowerCase();
    if(!key) continue;
    const current = grouped.get(key);
    if(!current || (entry.lastSeen || 0) > (current.lastSeen || 0)){
      grouped.set(key, entry);
    }
  }
  return Array.from(grouped.values())
    .sort((a,b)=> String(a.username || '').localeCompare(String(b.username || '')))
    .map(entry=>({
      username: entry.username,
      avatarUrl: entry.avatarUrl || '',
      pronouns: entry.pronouns || '',
      bio: entry.bio || '',
      lastSeen: entry.lastSeen || 0
    }));
}

function normalizeIpAddress(ip){
  const raw = String(ip || '').trim();
  if(!raw) return '';
  const noPort = raw.replace(/^\[|\]$/g, '').replace(/:\d+$/, '');
  return noPort.replace(/^::ffff:/i, '').toLowerCase();
}

function getClientIp(req){
  const xff = req.headers['x-forwarded-for'] || req.headers['X-Forwarded-For'];
  if(typeof xff === 'string' && xff.trim()){
    const first = xff.split(',')[0];
    const normalized = normalizeIpAddress(first);
    if(normalized) return normalized;
  }
  const xrip = req.headers['x-real-ip'] || req.headers['X-Real-IP'];
  if(typeof xrip === 'string' && xrip.trim()){
    const normalized = normalizeIpAddress(xrip);
    if(normalized) return normalized;
  }
  const remote = req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : '';
  return normalizeIpAddress(remote);
}

function ensureUserRole(user){
  if(!user) return 'member';
  const normalized = (user.username || '').toLowerCase();
  if(!user.role){
    if(normalized && normalized === OWNER_USERNAME) user.role = 'owner';
    else user.role = 'member';
  }
  return user.role;
}

function buildTokenPayload(user){
  const now = Math.floor(Date.now()/1000);
  return {
    id: user.id,
    username: user.username,
    role: ensureUserRole(user),
    iat: now,
    exp: now + 60*60*24*30
  };
}

function getAuthFromRequest(req, secret){
  if(!secret) return null;
  const header = req.headers['authorization'] || req.headers['Authorization'];
  if(!header || !header.startsWith('Bearer ')) return null;
  const token = header.slice(7).trim();
  if(!token) return null;
  const payload = verifyToken(token, secret);
  if(payload && !payload.role && (payload.username || '').toLowerCase() === OWNER_USERNAME) payload.role = 'owner';
  return payload;
}

function normalizeRoleId(value){
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
}

function normalizeBadgeId(value){
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
}

function normalizeGradientValue(value){
  const text = String(value || '').trim();
  if(!text) return '';
  return /gradient\s*\(/i.test(text) ? text : '';
}

function normalizeRoleRecord(role){
  if(!role) return null;
  const id = normalizeRoleId(role.id || role.name);
  if(!id) return null;
  const rawColor = String(role.color || '#a9b9d3').trim() || '#a9b9d3';
  const gradient = normalizeGradientValue(role.gradient || rawColor);
  return {
    id,
    name: String(role.name || id).trim() || id,
    color: gradient ? '#a9b9d3' : rawColor,
    gradient,
    icon: String(role.icon || '').trim(),
    priority: Number.isFinite(Number(role.priority)) ? Number(role.priority) : 10,
    permissions: Array.isArray(role.permissions) ? role.permissions.map(v=>String(v).trim()).filter(Boolean) : []
  };
}

function normalizeBadgeRecord(badge){
  if(!badge) return null;
  const id = normalizeBadgeId(badge.id || badge.name);
  if(!id) return null;
  const rawColor = String(badge.color || '#a9b9d3').trim() || '#a9b9d3';
  const gradient = normalizeGradientValue(badge.gradient || rawColor);
  return {
    id,
    name: String(badge.name || id).trim() || id,
    icon: String(badge.icon || '🏅').trim() || '🏅',
    color: gradient ? '#a9b9d3' : rawColor,
    gradient,
    tooltip: String(badge.tooltip || '').trim(),
    showInComments: badge.showInComments !== false
  };
}

function normalizeUniqueList(list, normalizer){
  const raw = Array.isArray(list) ? list : [];
  const seen = new Set();
  const out = [];
  raw.forEach(item=>{
    const v = normalizer(item);
    if(!v || seen.has(v)) return;
    seen.add(v);
    out.push(v);
  });
  return out;
}

function defaultOwnerControlRoles(){
  return [
    { id:'owner', name:'Owner', color:'#f5c77d', gradient:'', icon:'👑', priority:1000, permissions:['owner.panel','moderation.access','moderation.tools','roles.manage','badges.manage','commands.run'] },
    { id:'moderator', name:'Moderator', color:'#85c6ff', gradient:'', icon:'🛡', priority:700, permissions:['moderation.access','moderation.tools'] },
    { id:'member', name:'Member', color:'#a9b9d3', gradient:'', icon:'', priority:10, permissions:[] }
  ];
}

function normalizeOwnerControlMeta(meta){
  const roles = Array.isArray(meta && meta.roles) ? meta.roles.map(normalizeRoleRecord).filter(Boolean) : [];
  const badges = Array.isArray(meta && meta.badges) ? meta.badges.map(normalizeBadgeRecord).filter(Boolean) : [];
  if(!roles.some(r=>r.id==='owner')) roles.push(defaultOwnerControlRoles()[0]);
  if(!roles.some(r=>r.id==='moderator')) roles.push(defaultOwnerControlRoles()[1]);
  if(!roles.some(r=>r.id==='member')) roles.push(defaultOwnerControlRoles()[2]);
  roles.sort((a,b)=> Number(b.priority || 0) - Number(a.priority || 0));
  return { roles, badges, updatedAt: Date.now() };
}

function userKey(username){
  return String(username || '').trim().toLowerCase();
}

function buildOwnerControlState(users, meta){
  const normalizedMeta = normalizeOwnerControlMeta(meta || {});
  const userRoles = {};
  const userBadges = {};
  (Array.isArray(users) ? users : []).forEach(u=>{
    if(!u || !u.username) return;
    const key = userKey(u.username);
    const roles = normalizeUniqueList(u.roles, normalizeRoleId);
    const badges = normalizeUniqueList(u.badges, normalizeBadgeId);
    const roleLower = String(u.role || '').toLowerCase();
    if(roleLower === 'owner' && !roles.includes('owner')) roles.push('owner');
    if(roleLower === 'moderator' && !roles.includes('moderator')) roles.push('moderator');
    if(!roles.length) roles.push('member');
    userRoles[key] = roles;
    if(badges.length) userBadges[key] = badges;
  });
  return { roles: normalizedMeta.roles, badges: normalizedMeta.badges, userRoles, userBadges, updatedAt: Date.now() };
}

function applyOwnerControlStateToUsers(users, state){
  const normalizedUsers = Array.isArray(users) ? users : [];
  const roleMap = state && state.userRoles && typeof state.userRoles === 'object' ? state.userRoles : {};
  const badgeMap = state && state.userBadges && typeof state.userBadges === 'object' ? state.userBadges : {};
  normalizedUsers.forEach(u=>{
    if(!u || !u.username) return;
    const key = userKey(u.username);
    const roles = normalizeUniqueList(roleMap[key], normalizeRoleId);
    const badges = normalizeUniqueList(badgeMap[key], normalizeBadgeId);
    u.roles = roles;
    u.badges = badges;
    if(key === OWNER_USERNAME || roles.includes('owner')) u.role = 'owner';
    else if(roles.includes('moderator')) u.role = 'moderator';
    else u.role = 'member';
  });
}

async function getJsonAtPath(token, owner, repo, branch, path){
  const api = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`;
  const resp = await fetchFn(`${api}?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
  if(resp.status === 404) return { data: null, sha: null };
  if(resp.status !== 200){ const text = await resp.text(); throw new Error(`Read failed (${resp.status}): ${text}`); }
  const body = await resp.json();
  let data = null;
  try{ data = JSON.parse(fromBase64(body.content || '')); }catch(_e){ data = null; }
  return { data, sha: body.sha || null };
}

async function putJsonAtPath(token, owner, repo, branch, path, data, sha, message){
  const api = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`;
  const content = toBase64(JSON.stringify(data, null, 2));
  const body = { message: message || 'Update json', content, branch };
  if(sha) body.sha = sha;
  return await fetchFn(api, { method:'PUT', headers:{ Authorization:`token ${token}`, Accept:'application/vnd.github.v3+json', 'Content-Type':'application/json' }, body: JSON.stringify(body) });
}

async function deleteJsonAtPath(token, owner, repo, branch, path, sha, message){
  const api = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`;
  const body = { message: message || `Delete ${path}`, sha, branch };
  return await fetchFn(api, { method:'DELETE', headers:{ Authorization:`token ${token}`, Accept:'application/vnd.github.v3+json', 'Content-Type':'application/json' }, body: JSON.stringify(body) });
}

async function listDirectory(token, owner, repo, branch, path){
  const api = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`;
  const resp = await fetchFn(`${api}?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
  if(resp.status === 404) return [];
  if(resp.status !== 200){
    const text = await resp.text();
    throw new Error(`List failed (${resp.status}): ${text}`);
  }
  const body = await resp.json();
  return Array.isArray(body) ? body : [];
}

async function readRoleBadgeCatalogFromLibs(token, owner, repo, branch, rolesDirPath, badgesDirPath){
  const roles = [];
  const badges = [];
  const roleFiles = await listDirectory(token, owner, repo, branch, rolesDirPath).catch(()=>[]);
  for(const file of roleFiles){
    if(!file || file.type !== 'file' || !String(file.name || '').endsWith('.json')) continue;
    const data = await getJsonAtPath(token, owner, repo, branch, file.path).catch(()=>({ data:null }));
    const normalized = normalizeRoleRecord(data.data);
    if(normalized) roles.push(normalized);
  }
  const badgeFiles = await listDirectory(token, owner, repo, branch, badgesDirPath).catch(()=>[]);
  for(const file of badgeFiles){
    if(!file || file.type !== 'file' || !String(file.name || '').endsWith('.json')) continue;
    const data = await getJsonAtPath(token, owner, repo, branch, file.path).catch(()=>({ data:null }));
    const normalized = normalizeBadgeRecord(data.data);
    if(normalized) badges.push(normalized);
  }
  return normalizeOwnerControlMeta({ roles, badges });
}

async function saveRoleBadgeCatalogToLibs(token, owner, repo, branch, rolesDirPath, badgesDirPath, meta){
  const normalizedMeta = normalizeOwnerControlMeta(meta || {});
  const existingRoleFiles = await listDirectory(token, owner, repo, branch, rolesDirPath).catch(()=>[]);
  const existingBadgeFiles = await listDirectory(token, owner, repo, branch, badgesDirPath).catch(()=>[]);

  const existingRoleById = new Map(
    existingRoleFiles
      .filter(f=>f && f.type === 'file' && String(f.name || '').endsWith('.json'))
      .map(f=>[String(f.name).replace(/\.json$/i,''), { path:f.path, sha:f.sha }])
  );
  const existingBadgeById = new Map(
    existingBadgeFiles
      .filter(f=>f && f.type === 'file' && String(f.name || '').endsWith('.json'))
      .map(f=>[String(f.name).replace(/\.json$/i,''), { path:f.path, sha:f.sha }])
  );

  const nextRoleIds = new Set();
  for(const role of normalizedMeta.roles){
    const roleId = normalizeRoleId(role.id);
    if(!roleId) continue;
    nextRoleIds.add(roleId);
    const path = `${rolesDirPath}/${roleId}.json`;
    const existing = existingRoleById.get(roleId);
    const resp = await putJsonAtPath(token, owner, repo, branch, path, role, existing ? existing.sha : null, `Save role ${roleId}`);
    if(!resp.ok){ const text = await resp.text(); throw new Error(`Failed to save role ${roleId}: ${text}`); }
  }

  const nextBadgeIds = new Set();
  for(const badge of normalizedMeta.badges){
    const badgeId = normalizeBadgeId(badge.id);
    if(!badgeId) continue;
    nextBadgeIds.add(badgeId);
    const path = `${badgesDirPath}/${badgeId}.json`;
    const existing = existingBadgeById.get(badgeId);
    const resp = await putJsonAtPath(token, owner, repo, branch, path, badge, existing ? existing.sha : null, `Save badge ${badgeId}`);
    if(!resp.ok){ const text = await resp.text(); throw new Error(`Failed to save badge ${badgeId}: ${text}`); }
  }

  for(const [roleId, info] of existingRoleById.entries()){
    if(nextRoleIds.has(roleId)) continue;
    if(!info || !info.sha) continue;
    await deleteJsonAtPath(token, owner, repo, branch, info.path, info.sha, `Delete role ${roleId}`);
  }
  for(const [badgeId, info] of existingBadgeById.entries()){
    if(nextBadgeIds.has(badgeId)) continue;
    if(!info || !info.sha) continue;
    await deleteJsonAtPath(token, owner, repo, branch, info.path, info.sha, `Delete badge ${badgeId}`);
  }

  return normalizedMeta;
}

module.exports = async (req,res) => {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if(req.method==='OPTIONS') return res.status(200).end();

  const token = process.env.GITHUB_TOKEN;
  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  const branch = process.env.GITHUB_BRANCH || 'main';
  const libsBasePath = (process.env.GITHUB_PATH || 'libs').replace(/^\/+|\/+$/g,'');
  const rolesDirPath = `${libsBasePath}/roles`;
  const badgesDirPath = `${libsBasePath}/badges`;
  const usersPath = (process.env.GITHUB_USERS_PATH || 'users/users.json').replace(/^\/+|\/+$/g,'');
  const ownerControlMetaPath = (process.env.GITHUB_OWNER_CONTROL_META_PATH || 'users/owner-control-meta.json').replace(/^\/+|\/+$/g,'');
  const jwtSecret = process.env.JWT_SECRET || null;
  const query = req.query || new URL(req.url, 'http://localhost').searchParams;
  const getAction = (q)=>{
    if(!q) return 'health';
    if(typeof q.get === 'function') return q.get('action') || 'health';
    return q.action || 'health';
  };

  if(req.method==='GET'){
    const action = getAction(query);
    if(action === 'list'){
      if(!token || !owner || !repo) return res.status(500).json({ error:'Server not configured for users. Set GITHUB_TOKEN/GITHUB_OWNER/GITHUB_REPO.' });
      const { users } = await getUsers(token, owner, repo, branch, usersPath);
      return res.status(200).json({ ok:true, count: users.length });
    }
    if(action === 'staff'){
      if(!token || !owner || !repo) return res.status(500).json({ error:'Server not configured for users. Set GITHUB_TOKEN/GITHUB_OWNER/GITHUB_REPO.' });
      const { users } = await getUsers(token, owner, repo, branch, usersPath);
      users.forEach(ensureUserRole);
      const ownerUser = users.find(u=>u.role==='owner') || null;
      const moderators = users.filter(u=>u.role==='moderator').map(u=>({ id:u.id, username:u.username, createdAt:u.createdAt }));
      return res.status(200).json({ ok:true, owner: ownerUser ? { id: ownerUser.id, username: ownerUser.username } : null, moderators });
    }
    if(action === 'ownerControlGet'){
      if(!token || !owner || !repo) return res.status(500).json({ error:'Server not configured for users. Set GITHUB_TOKEN/GITHUB_OWNER/GITHUB_REPO.' });
      const { users } = await getUsers(token, owner, repo, branch, usersPath);
      let catalog = await readRoleBadgeCatalogFromLibs(token, owner, repo, branch, rolesDirPath, badgesDirPath).catch(()=>null);
      if(!catalog || (!catalog.roles.length && !catalog.badges.length)){
        const metaResp = await getJsonAtPath(token, owner, repo, branch, ownerControlMetaPath).catch(()=>({ data:null, sha:null }));
        catalog = normalizeOwnerControlMeta(metaResp && metaResp.data ? metaResp.data : {});
      }
      const state = buildOwnerControlState(users, catalog || {});
      return res.status(200).json({ ok:true, state });
    }
    if(action === 'presenceList'){
      if(!jwtSecret) return res.status(500).json({ error:'Server not configured for presence. Set JWT_SECRET.' });
      const auth = getAuthFromRequest(req, jwtSecret);
      if(!auth || !auth.username) return res.status(401).json({ error:'Unauthorized' });
      const users = buildPresenceList();
      return res.status(200).json({ ok:true, users });
    }
    return res.status(200).json({ ok:true, configured: !!(token && owner && repo && jwtSecret), owner: owner||null, repo: repo||null, usersPath });
  }

  if(req.method!=='POST') return res.status(405).json({ error:'Method Not Allowed' });

  const action = (query.get && query.get('action')) || (query.action) || 'health';

  const body = await readBody(req);

  if(action === 'presencePing'){
    if(!jwtSecret) return res.status(500).json({ error:'Server not configured for presence. Set JWT_SECRET.' });
    const auth = getAuthFromRequest(req, jwtSecret);
    if(!auth || !auth.username) return res.status(401).json({ error:'Unauthorized' });
    const tabId = String(body.tabId || '').trim().slice(0, 80);
    if(!tabId) return res.status(400).json({ error:'tabId required' });
    const profile = safePresenceProfile(body.profile);
    const key = `${String(auth.username).toLowerCase()}::${tabId}`;
    presenceStore.set(key, {
      username: String(auth.username),
      tabId,
      avatarUrl: profile.avatarUrl,
      pronouns: profile.pronouns,
      bio: profile.bio,
      lastSeen: Date.now()
    });
    cleanupPresence();
    return res.status(200).json({ ok:true });
  }

  if(action === 'presenceLeave'){
    if(!jwtSecret) return res.status(500).json({ error:'Server not configured for presence. Set JWT_SECRET.' });
    const auth = getAuthFromRequest(req, jwtSecret);
    if(!auth || !auth.username) return res.status(401).json({ error:'Unauthorized' });
    const tabId = String(body.tabId || '').trim().slice(0, 80);
    if(tabId){
      const key = `${String(auth.username).toLowerCase()}::${tabId}`;
      presenceStore.delete(key);
    }
    cleanupPresence();
    return res.status(200).json({ ok:true });
  }

  if(action==='signup'){
    if(!token || !owner || !repo || !jwtSecret) return res.status(500).json({ error:'Server not configured for users. Set GITHUB_TOKEN/GITHUB_OWNER/GITHUB_REPO/JWT_SECRET.' });
    const rawUsername = body.username;
    const username = String(rawUsername || '').trim();
    const password = body.password;
    if(!username || !password) return res.status(400).json({ error:'username and password required' });
    if(username.length < USERNAME_MIN_LENGTH || username.length > USERNAME_MAX_LENGTH){
      return res.status(400).json({ error:`username must be ${USERNAME_MIN_LENGTH}-${USERNAME_MAX_LENGTH} characters` });
    }
    const { users, sha } = await getUsers(token, owner, repo, branch, usersPath);
    if(users.some(u=>u.username.toLowerCase()===username.toLowerCase())) return res.status(409).json({ error:'Username taken' });
    const clientIp = getClientIp(req);
    if(clientIp){
      const existingFromIp = users.filter(u=> normalizeIpAddress(u && u.createdIp) === clientIp).length;
      if(existingFromIp >= MAX_ACCOUNTS_PER_IP){
        return res.status(429).json({ error:`Only ${MAX_ACCOUNTS_PER_IP} accounts are allowed per IP` });
      }
    }
    const id = Date.now().toString();
    const passwordHash = hashPassword(password);
    const user = { id, username, passwordHash, createdAt: new Date().toISOString(), createdIp: clientIp || null, role: username.toLowerCase()===OWNER_USERNAME ? 'owner' : 'member' };
    users.push(user);
    const putResp = await putUsers(token, owner, repo, branch, usersPath, users, sha);
    if(!putResp.ok) { const txt = await putResp.text(); return res.status(500).json({ error:'Failed to save users', detail: txt }); }
    const payload = buildTokenPayload(user);
    const tok = signToken(payload, jwtSecret);
    return res.status(200).json({ ok:true, token: tok, user: { id:user.id, username:user.username, role: user.role } });
  }

  if(action==='login'){
    if(!token || !owner || !repo || !jwtSecret) return res.status(500).json({ error:'Server not configured for users. Set GITHUB_TOKEN/GITHUB_OWNER/GITHUB_REPO/JWT_SECRET.' });
    const { username, password } = body;
    if(!username || !password) return res.status(400).json({ error:'username and password required' });
    const { users, sha } = await getUsers(token, owner, repo, branch, usersPath);
    let usersMutated = false;
    const user = users.find(u=>u.username.toLowerCase()===username.toLowerCase());
    if(!user) return res.status(401).json({ error:'Invalid credentials' });
    if(!verifyPassword(password, user.passwordHash)) return res.status(401).json({ error:'Invalid credentials' });
    const previousRole = user.role;
    ensureUserRole(user);
    if(previousRole !== user.role){ usersMutated = true; }
    if(usersMutated){ await putUsers(token, owner, repo, branch, usersPath, users, sha); }
    const payload = buildTokenPayload(user);
    const tok = signToken(payload, jwtSecret);
    return res.status(200).json({ ok:true, token: tok, user: { id:user.id, username:user.username, role: user.role } });
  }

  if(action==='addModerator'){
    if(!token || !owner || !repo || !jwtSecret) return res.status(500).json({ error:'Server not configured for users. Set GITHUB_TOKEN/GITHUB_OWNER/GITHUB_REPO/JWT_SECRET.' });
    const auth = getAuthFromRequest(req, jwtSecret);
    if(!auth || auth.role !== 'owner') return res.status(403).json({ error:'Only the owner can modify staff.' });
    const targetUsername = (body.username || '').trim();
    if(!targetUsername) return res.status(400).json({ error:'username required' });
    const normalizedTarget = targetUsername.toLowerCase();
    const { users, sha } = await getUsers(token, owner, repo, branch, usersPath);
    const target = users.find(u=>u.username.toLowerCase()===normalizedTarget);
    if(!target) return res.status(404).json({ error:'User not found' });
    ensureUserRole(target);
    if(target.role === 'owner') return res.status(400).json({ error:'Owner is already highest role.' });
    if(target.role === 'moderator') return res.status(200).json({ ok:true, user: { id: target.id, username: target.username, role: target.role } });
    target.role = 'moderator';
    const putResp = await putUsers(token, owner, repo, branch, usersPath, users, sha);
    if(!putResp.ok){ const txt = await putResp.text(); return res.status(500).json({ error:'Failed to save users', detail: txt }); }
    return res.status(200).json({ ok:true, user: { id: target.id, username: target.username, role: target.role } });
  }

  if(action==='removeModerator'){
    if(!token || !owner || !repo || !jwtSecret) return res.status(500).json({ error:'Server not configured for users. Set GITHUB_TOKEN/GITHUB_OWNER/GITHUB_REPO/JWT_SECRET.' });
    const auth = getAuthFromRequest(req, jwtSecret);
    if(!auth || auth.role !== 'owner') return res.status(403).json({ error:'Only the owner can modify staff.' });
    const targetUsername = (body.username || '').trim();
    if(!targetUsername) return res.status(400).json({ error:'username required' });
    const normalizedTarget = targetUsername.toLowerCase();
    const { users, sha } = await getUsers(token, owner, repo, branch, usersPath);
    const target = users.find(u=>u.username.toLowerCase()===normalizedTarget);
    if(!target) return res.status(404).json({ error:'User not found' });
    ensureUserRole(target);
    if(target.role === 'owner') return res.status(400).json({ error:'Cannot change owner role.' });
    if(target.role !== 'moderator') return res.status(200).json({ ok:true, user: { id: target.id, username: target.username, role: target.role } });
    target.role = 'member';
    const putResp = await putUsers(token, owner, repo, branch, usersPath, users, sha);
    if(!putResp.ok){ const txt = await putResp.text(); return res.status(500).json({ error:'Failed to save users', detail: txt }); }
    return res.status(200).json({ ok:true, user: { id: target.id, username: target.username, role: target.role } });
  }

  if(action==='ownerControlSave'){
    if(!token || !owner || !repo || !jwtSecret) return res.status(500).json({ error:'Server not configured for users. Set GITHUB_TOKEN/GITHUB_OWNER/GITHUB_REPO/JWT_SECRET.' });
    const auth = getAuthFromRequest(req, jwtSecret);
    const isOwner = !!(auth && ((String(auth.role || '').toLowerCase() === 'owner') || (String(auth.username || '').toLowerCase() === OWNER_USERNAME)));
    if(!isOwner) return res.status(403).json({ error:'Only owner can update owner panel data.' });

    const incoming = body && body.state ? body.state : body;
    let normalizedMeta = normalizeOwnerControlMeta(incoming || {});
    const roleMap = incoming && incoming.userRoles && typeof incoming.userRoles === 'object' ? incoming.userRoles : {};
    const badgeMap = incoming && incoming.userBadges && typeof incoming.userBadges === 'object' ? incoming.userBadges : {};

    const { users, sha } = await getUsers(token, owner, repo, branch, usersPath);
    const stateForUsers = {
      roles: normalizedMeta.roles,
      badges: normalizedMeta.badges,
      userRoles: roleMap,
      userBadges: badgeMap
    };
    applyOwnerControlStateToUsers(users, stateForUsers);
    const putUsersResp = await putUsers(token, owner, repo, branch, usersPath, users, sha);
    if(!putUsersResp.ok){ const txt = await putUsersResp.text(); return res.status(500).json({ error:'Failed to save users', detail: txt }); }

    normalizedMeta = await saveRoleBadgeCatalogToLibs(token, owner, repo, branch, rolesDirPath, badgesDirPath, normalizedMeta);

    const existingMeta = await getJsonAtPath(token, owner, repo, branch, ownerControlMetaPath).catch(()=>({ data:null, sha:null }));
    const putMetaResp = await putJsonAtPath(token, owner, repo, branch, ownerControlMetaPath, normalizedMeta, existingMeta.sha, 'Update owner control meta');
    if(!putMetaResp.ok){ const txt = await putMetaResp.text(); return res.status(500).json({ error:'Failed to save owner control meta', detail: txt }); }

    const nextState = buildOwnerControlState(users, normalizedMeta);
    return res.status(200).json({ ok:true, state: nextState });
  }

  return res.status(400).json({ error:'Unknown action' });
};
