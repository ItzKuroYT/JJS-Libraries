const crypto = require('crypto');

let fetchFn = global.fetch;
try{ if(!fetchFn) fetchFn = require('node-fetch'); }catch(_e){}

async function readBody(req){
  if(req.body && typeof req.body === 'object' && Object.keys(req.body).length) return req.body;
  if(typeof req.body === 'string'){ try{ return JSON.parse(req.body); }catch(_e){} }
  return await new Promise((resolve, reject)=>{
    let data = '';
    req.on('data', c=> data += c);
    req.on('end', ()=>{
      if(!data) return resolve({});
      try{ resolve(JSON.parse(data)); }catch(_e){ resolve({}); }
    });
    req.on('error', reject);
  });
}

function verifyToken(token, secret){
  try{
    if(!token || !secret) return null;
    const parts = token.split('.');
    if(parts.length !== 3) return null;
    const unsigned = parts[0] + '.' + parts[1];
    const sig = crypto.createHmac('sha256', secret).update(unsigned).digest('base64url');
    if(!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(parts[2]))) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if(payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  }catch(_e){
    return null;
  }
}

function getAuthFromRequest(req, secret){
  const header = req.headers['authorization'] || req.headers['Authorization'] || '';
  if(!header.startsWith('Bearer ')) return null;
  const token = header.slice(7).trim();
  return verifyToken(token, secret);
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
    permissions: Array.isArray(role.permissions) ? role.permissions.filter(Boolean).map(v=>String(v).trim()) : []
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

function normalizeMappingObject(raw, normalizer){
  if(!raw || typeof raw !== 'object') return {};
  const out = {};
  Object.keys(raw).forEach(username=>{
    const userKey = String(username || '').trim().toLowerCase();
    if(!userKey) return;
    const list = Array.isArray(raw[username]) ? raw[username] : [];
    const seen = new Set();
    const clean = [];
    list.forEach(item=>{
      const v = normalizer(item);
      if(!v || seen.has(v)) return;
      seen.add(v);
      clean.push(v);
    });
    if(clean.length) out[userKey] = clean;
  });
  return out;
}

function normalizeOwnerControlState(payload){
  const roles = Array.isArray(payload && payload.roles) ? payload.roles.map(normalizeRoleRecord).filter(Boolean) : [];
  const badges = Array.isArray(payload && payload.badges) ? payload.badges.map(normalizeBadgeRecord).filter(Boolean) : [];
  const userRoles = normalizeMappingObject(payload && payload.userRoles, normalizeRoleId);
  const userBadges = normalizeMappingObject(payload && payload.userBadges, normalizeBadgeId);

  if(!roles.some(r=>r.id === 'owner')){
    roles.push({ id:'owner', name:'Owner', color:'#f5c77d', gradient:'', icon:'👑', priority:1000, permissions:['owner.panel','moderation.access','moderation.tools','roles.manage','badges.manage','commands.run'] });
  }
  if(!roles.some(r=>r.id === 'moderator')){
    roles.push({ id:'moderator', name:'Moderator', color:'#85c6ff', gradient:'', icon:'🛡', priority:700, permissions:['moderation.access','moderation.tools'] });
  }
  if(!roles.some(r=>r.id === 'member')){
    roles.push({ id:'member', name:'Member', color:'#a9b9d3', gradient:'', icon:'', priority:10, permissions:[] });
  }

  roles.sort((a,b)=> Number(b.priority || 0) - Number(a.priority || 0));
  return { roles, badges, userRoles, userBadges, updatedAt: Date.now() };
}

function ghHeaders(token){
  return {
    Authorization: `token ${token}`,
    Accept: 'application/vnd.github.v3+json'
  };
}

function safePathJoin(base, leaf){
  if(!base) return String(leaf || '').replace(/^\/+/, '');
  return `${base.replace(/\/+$/,'')}/${String(leaf || '').replace(/^\/+/, '')}`;
}

function userFileName(username){
  return String(username || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '_');
}

async function getJsonFile(token, owner, repo, branch, filePath){
  const api = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(filePath)}`;
  const resp = await fetchFn(api + `?ref=${encodeURIComponent(branch)}`, { headers: ghHeaders(token) });
  if(resp.status === 404) return { data: null, sha: null };
  if(resp.status !== 200){
    const text = await resp.text();
    throw new Error(`GitHub read failed (${resp.status}): ${text}`);
  }
  const body = await resp.json();
  let parsed = null;
  try{ parsed = JSON.parse(Buffer.from(body.content || '', 'base64').toString('utf8')); }catch(_e){ parsed = null; }
  return { data: parsed, sha: body.sha || null };
}

async function putJsonFile(token, owner, repo, branch, filePath, data, sha, message){
  const api = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(filePath)}`;
  const content = Buffer.from(JSON.stringify(data, null, 2), 'utf8').toString('base64');
  const payload = { message: message || 'Update owner control state', content, branch };
  if(sha) payload.sha = sha;
  const resp = await fetchFn(api, {
    method: 'PUT',
    headers: Object.assign({ 'Content-Type': 'application/json' }, ghHeaders(token)),
    body: JSON.stringify(payload)
  });
  if(!resp.ok){
    const text = await resp.text();
    throw new Error(`GitHub write failed (${resp.status}): ${text}`);
  }
  return await resp.json();
}

async function deleteFile(token, owner, repo, branch, filePath, sha, message){
  const api = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(filePath)}`;
  const payload = { message: message || `Delete ${filePath}`, sha, branch };
  const resp = await fetchFn(api, {
    method: 'DELETE',
    headers: Object.assign({ 'Content-Type': 'application/json' }, ghHeaders(token)),
    body: JSON.stringify(payload)
  });
  if(!resp.ok){
    const text = await resp.text();
    throw new Error(`GitHub delete failed (${resp.status}): ${text}`);
  }
  return await resp.json();
}

async function listDirectory(token, owner, repo, branch, dirPath){
  const api = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(dirPath)}`;
  const resp = await fetchFn(api + `?ref=${encodeURIComponent(branch)}`, { headers: ghHeaders(token) });
  if(resp.status === 404) return [];
  if(resp.status !== 200){
    const text = await resp.text();
    throw new Error(`GitHub list failed (${resp.status}): ${text}`);
  }
  const body = await resp.json();
  return Array.isArray(body) ? body : [];
}

async function readAllJsonFilesInDir(token, owner, repo, branch, dirPath){
  const files = await listDirectory(token, owner, repo, branch, dirPath);
  const results = [];
  for(const item of files){
    if(!item || item.type !== 'file' || !String(item.name || '').endsWith('.json')) continue;
    const parsed = await getJsonFile(token, owner, repo, branch, item.path);
    if(parsed && parsed.data) results.push({ path: item.path, name: item.name, sha: item.sha || parsed.sha, data: parsed.data });
  }
  return results;
}

async function readStateFromStructuredFiles(token, owner, repo, branch, paths){
  const roleFiles = await readAllJsonFilesInDir(token, owner, repo, branch, paths.rolesDir);
  const badgeFiles = await readAllJsonFilesInDir(token, owner, repo, branch, paths.badgesDir);
  const userFiles = await readAllJsonFilesInDir(token, owner, repo, branch, paths.usersDir);

  const roles = roleFiles.map(file=> normalizeRoleRecord(file.data)).filter(Boolean);
  const badges = badgeFiles.map(file=> normalizeBadgeRecord(file.data)).filter(Boolean);
  const userRoles = {};
  const userBadges = {};

  userFiles.forEach(file=>{
    const record = file.data && typeof file.data === 'object' ? file.data : {};
    const username = String(record.username || file.name.replace(/\.json$/i,'')).trim().toLowerCase();
    if(!username) return;
    const rolesList = normalizeMappingObject({ [username]: record.roles || [] }, normalizeRoleId)[username] || [];
    const badgesList = normalizeMappingObject({ [username]: record.badges || [] }, normalizeBadgeId)[username] || [];
    if(rolesList.length) userRoles[username] = rolesList;
    if(badgesList.length) userBadges[username] = badgesList;
  });

  return normalizeOwnerControlState({ roles, badges, userRoles, userBadges });
}

async function saveStateToStructuredFiles(token, owner, repo, branch, paths, state){
  const normalized = normalizeOwnerControlState(state || {});

  const existingRoleFiles = await readAllJsonFilesInDir(token, owner, repo, branch, paths.rolesDir);
  const existingBadgeFiles = await readAllJsonFilesInDir(token, owner, repo, branch, paths.badgesDir);
  const existingUserFiles = await readAllJsonFilesInDir(token, owner, repo, branch, paths.usersDir);

  const existingRoleMap = new Map(existingRoleFiles.map(f=>[f.name.replace(/\.json$/i,''), f]));
  const existingBadgeMap = new Map(existingBadgeFiles.map(f=>[f.name.replace(/\.json$/i,''), f]));
  const existingUserMap = new Map(existingUserFiles.map(f=>[f.name.replace(/\.json$/i,''), f]));

  const nextRoleIds = new Set();
  for(const role of normalized.roles){
    const id = normalizeRoleId(role.id);
    if(!id) continue;
    nextRoleIds.add(id);
    const filePath = safePathJoin(paths.rolesDir, `${id}.json`);
    const existing = existingRoleMap.get(id);
    await putJsonFile(token, owner, repo, branch, filePath, role, existing ? existing.sha : null, `Save role ${id}`);
  }

  const nextBadgeIds = new Set();
  for(const badge of normalized.badges){
    const id = normalizeBadgeId(badge.id);
    if(!id) continue;
    nextBadgeIds.add(id);
    const filePath = safePathJoin(paths.badgesDir, `${id}.json`);
    const existing = existingBadgeMap.get(id);
    await putJsonFile(token, owner, repo, branch, filePath, badge, existing ? existing.sha : null, `Save badge ${id}`);
  }

  const nextUsers = new Set();
  const allUsers = new Set([...Object.keys(normalized.userRoles || {}), ...Object.keys(normalized.userBadges || {})]);
  for(const username of allUsers){
    const key = userFileName(username);
    if(!key) continue;
    const roles = Array.isArray(normalized.userRoles[username]) ? normalized.userRoles[username] : [];
    const badges = Array.isArray(normalized.userBadges[username]) ? normalized.userBadges[username] : [];
    if(!roles.length && !badges.length) continue;
    nextUsers.add(key);
    const filePath = safePathJoin(paths.usersDir, `${key}.json`);
    const existing = existingUserMap.get(key);
    const payload = { username: username.toLowerCase(), roles, badges, updatedAt: Date.now() };
    await putJsonFile(token, owner, repo, branch, filePath, payload, existing ? existing.sha : null, `Save user roles/badges ${username}`);
  }

  for(const [id, existing] of existingRoleMap.entries()){
    if(nextRoleIds.has(id)) continue;
    await deleteFile(token, owner, repo, branch, existing.path, existing.sha, `Delete role ${id}`);
  }

  for(const [id, existing] of existingBadgeMap.entries()){
    if(nextBadgeIds.has(id)) continue;
    await deleteFile(token, owner, repo, branch, existing.path, existing.sha, `Delete badge ${id}`);
  }

  for(const [id, existing] of existingUserMap.entries()){
    if(nextUsers.has(id)) continue;
    await deleteFile(token, owner, repo, branch, existing.path, existing.sha, `Delete user role/badge file ${id}`);
  }

  return normalized;
}

module.exports = async (req, res)=>{
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if(req.method === 'OPTIONS') return res.status(200).end();

  const token = process.env.GITHUB_TOKEN;
  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  const branch = process.env.GITHUB_BRANCH || 'main';

  const configuredPath = (process.env.GITHUB_OWNER_CONTROL_BASE_PATH || process.env.GITHUB_OWNER_CONTROL_PATH || 'users/owner-control').replace(/^\/+|\/+$/g, '');
  const basePath = configuredPath.endsWith('.json') ? configuredPath.replace(/\.json$/i, '') : configuredPath;
  const legacyFilePath = configuredPath.endsWith('.json') ? configuredPath : `${configuredPath}.json`;

  const paths = {
    basePath,
    rolesDir: safePathJoin(basePath, 'roles'),
    badgesDir: safePathJoin(basePath, 'badges'),
    usersDir: safePathJoin(basePath, 'users'),
    legacyFilePath
  };

  const jwtSecret = process.env.JWT_SECRET || '';
  const ownerUsername = (process.env.OWNER_USERNAME || 'Kuro').toLowerCase();

  if(!token || !owner || !repo){
    return res.status(500).json({ error:'Server not configured. Set GITHUB_TOKEN/GITHUB_OWNER/GITHUB_REPO.' });
  }

  const query = req.query || new URL(req.url, 'http://localhost').searchParams;
  const action = (typeof query.get === 'function' ? query.get('action') : query.action) || 'get';

  try{
    if(req.method === 'GET'){
      if(action === 'health'){
        return res.status(200).json({ ok:true, configured:true, basePath: paths.basePath, rolesDir: paths.rolesDir, badgesDir: paths.badgesDir, usersDir: paths.usersDir, legacyFilePath: paths.legacyFilePath });
      }

      let state = await readStateFromStructuredFiles(token, owner, repo, branch, paths);
      const hasStructuredData = state.roles.length > 3 || state.badges.length > 0 || Object.keys(state.userRoles).length > 0 || Object.keys(state.userBadges).length > 0;

      if(!hasStructuredData){
        const legacy = await getJsonFile(token, owner, repo, branch, paths.legacyFilePath);
        if(legacy && legacy.data){
          state = normalizeOwnerControlState(legacy.data);
        }
      }

      return res.status(200).json({ ok:true, state });
    }

    if(req.method !== 'POST') return res.status(405).json({ error:'Method Not Allowed' });
    if(action !== 'save') return res.status(400).json({ error:'Unknown action' });

    if(!jwtSecret) return res.status(500).json({ error:'Server not configured. Set JWT_SECRET.' });
    const auth = getAuthFromRequest(req, jwtSecret);
    const isOwner = !!(auth && ((String(auth.role || '').toLowerCase() === 'owner') || (String(auth.username || '').toLowerCase() === ownerUsername)));
    if(!isOwner) return res.status(403).json({ error:'Only owner can update owner-control state.' });

    const body = await readBody(req);
    const incoming = body && body.state ? body.state : body;
    const normalized = await saveStateToStructuredFiles(token, owner, repo, branch, paths, incoming || {});

    return res.status(200).json({ ok:true, state: normalized });
  }catch(err){
    return res.status(500).json({ error:'owner-control request failed', detail: String(err && err.message ? err.message : err) });
  }
};
