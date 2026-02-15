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

module.exports = async (req,res) => {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if(req.method==='OPTIONS') return res.status(200).end();

  const token = process.env.GITHUB_TOKEN;
  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  const branch = process.env.GITHUB_BRANCH || 'main';
  const usersPath = (process.env.GITHUB_USERS_PATH || 'users/users.json').replace(/^\/+|\/+$/g,'');
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
    return res.status(200).json({ ok:true, configured: !!(token && owner && repo && jwtSecret), owner: owner||null, repo: repo||null, usersPath });
  }

  if(req.method!=='POST') return res.status(405).json({ error:'Method Not Allowed' });

  const action = (query.get && query.get('action')) || (query.action) || 'health';

  const body = await readBody(req);

  if(action==='signup'){
    if(!token || !owner || !repo || !jwtSecret) return res.status(500).json({ error:'Server not configured for users. Set GITHUB_TOKEN/GITHUB_OWNER/GITHUB_REPO/JWT_SECRET.' });
    const { username, password } = body;
    if(!username || !password) return res.status(400).json({ error:'username and password required' });
    const { users, sha } = await getUsers(token, owner, repo, branch, usersPath);
    if(users.some(u=>u.username.toLowerCase()===username.toLowerCase())) return res.status(409).json({ error:'Username taken' });
    const id = Date.now().toString();
    const passwordHash = hashPassword(password);
    const user = { id, username, passwordHash, createdAt: new Date().toISOString(), role: username.toLowerCase()===OWNER_USERNAME ? 'owner' : 'member' };
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

  return res.status(400).json({ error:'Unknown action' });
};
