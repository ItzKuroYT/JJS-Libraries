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
    roles.push({ id:'owner', name:'Owner', color:'#f5c77d', icon:'👑', priority:1000, permissions:['owner.panel','moderation.access','moderation.tools','roles.manage','badges.manage','commands.run'] });
  }
  if(!roles.some(r=>r.id === 'moderator')){
    roles.push({ id:'moderator', name:'Moderator', color:'#85c6ff', icon:'🛡', priority:700, permissions:['moderation.access','moderation.tools'] });
  }
  if(!roles.some(r=>r.id === 'member')){
    roles.push({ id:'member', name:'Member', color:'#a9b9d3', icon:'', priority:10, permissions:[] });
  }

  roles.sort((a,b)=> Number(b.priority || 0) - Number(a.priority || 0));
  return { roles, badges, userRoles, userBadges, updatedAt: Date.now() };
}

async function getJsonFile(token, owner, repo, branch, filePath){
  const api = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(filePath)}`;
  const resp = await fetchFn(api + `?ref=${encodeURIComponent(branch)}`, {
    headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' }
  });
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

async function putJsonFile(token, owner, repo, branch, filePath, data, sha){
  const api = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(filePath)}`;
  const content = Buffer.from(JSON.stringify(data, null, 2), 'utf8').toString('base64');
  const payload = { message: 'Update owner control state', content, branch };
  if(sha) payload.sha = sha;
  const resp = await fetchFn(api, {
    method: 'PUT',
    headers: {
      Authorization: `token ${token}`,
      Accept: 'application/vnd.github.v3+json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });
  if(!resp.ok){
    const text = await resp.text();
    throw new Error(`GitHub write failed (${resp.status}): ${text}`);
  }
  return await resp.json();
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
  const filePath = (process.env.GITHUB_OWNER_CONTROL_PATH || 'users/owner-control.json').replace(/^\/+|\/+$/g, '');
  const jwtSecret = process.env.JWT_SECRET || '';
  const ownerUsername = (process.env.OWNER_USERNAME || 'Kuro').toLowerCase();

  if(!token || !owner || !repo){
    return res.status(500).json({ error:'Server not configured. Set GITHUB_TOKEN/GITHUB_OWNER/GITHUB_REPO.' });
  }

  const query = req.query || new URL(req.url, 'http://localhost').searchParams;
  const action = (typeof query.get === 'function' ? query.get('action') : query.action) || 'get';

  try{
    if(req.method === 'GET'){
      if(action === 'health') return res.status(200).json({ ok:true, configured:true, filePath });
      const { data } = await getJsonFile(token, owner, repo, branch, filePath);
      const normalized = normalizeOwnerControlState(data || {});
      return res.status(200).json({ ok:true, state: normalized });
    }

    if(req.method !== 'POST') return res.status(405).json({ error:'Method Not Allowed' });
    if(action !== 'save') return res.status(400).json({ error:'Unknown action' });

    if(!jwtSecret) return res.status(500).json({ error:'Server not configured. Set JWT_SECRET.' });
    const auth = getAuthFromRequest(req, jwtSecret);
    const isOwner = !!(auth && ((String(auth.role || '').toLowerCase() === 'owner') || (String(auth.username || '').toLowerCase() === ownerUsername)));
    if(!isOwner) return res.status(403).json({ error:'Only owner can update owner-control state.' });

    const body = await readBody(req);
    const incoming = body && body.state ? body.state : body;
    const normalized = normalizeOwnerControlState(incoming || {});

    const existing = await getJsonFile(token, owner, repo, branch, filePath);
    await putJsonFile(token, owner, repo, branch, filePath, normalized, existing.sha);
    return res.status(200).json({ ok:true, state: normalized });
  }catch(err){
    return res.status(500).json({ error:'owner-control request failed', detail: String(err && err.message ? err.message : err) });
  }
};
