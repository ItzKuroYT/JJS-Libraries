// Serverless function (Vercel / Netlify compatible) to save a library JSON into a GitHub repo.
// Configuration via environment variables:
// GITHUB_TOKEN - a PAT with repo contents permissions (store as a secret in your host)
// GITHUB_OWNER - repo owner
// GITHUB_REPO - repo name
// GITHUB_BRANCH - branch to commit to (default: main)
// GITHUB_PATH - path inside repo to save files (default: libs)

const { URL } = require('url');

// Try to use global fetch (Node 18+ / modern runtimes). Fallback to node-fetch if available.
let fetchFn = (typeof globalThis !== 'undefined' && globalThis.fetch) ? globalThis.fetch : null;
if(!fetchFn){
  try{
    const nf = require('node-fetch');
    fetchFn = nf && nf.default ? nf.default : nf;
  }catch(e){
    try{
      // If node-fetch v3 (ESM) is installed, import dynamically
      fetchFn = (...args) => import('node-fetch').then(m=>m.default(...args));
    }catch(e2){
      fetchFn = null;
    }
  }
}

async function readBody(req){
  if (req.body && Object.keys(req.body).length) return req.body;
  // If body is raw string (some platforms), try to parse
  if (typeof req.body === 'string'){
    try{ return JSON.parse(req.body); }catch(e){ /* fallthrough */ }
  }
  // Otherwise, collect stream
  return await new Promise((resolve, reject)=>{
    let data = '';
    req.on('data', chunk=> data += chunk);
    req.on('end', ()=>{
      if(!data) return resolve({});
      try{ resolve(JSON.parse(data)); }catch(e){ resolve({}); }
    });
    req.on('error', reject);
  });
}

function sanitizeDmUser(username){
  return String(username || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
}

function buildConvId(userA, userB){
  const clean = [sanitizeDmUser(userA), sanitizeDmUser(userB)].filter(Boolean);
  if(clean.length < 2) return null;
  clean.sort((a,b)=>a.localeCompare(b));
  return `${clean[0]}__${clean[1]}`;
}

function resolveConvId(input){
  if(!input) return null;
  if(Array.isArray(input.participants) && input.participants.length === 2){
    return buildConvId(input.participants[0], input.participants[1]);
  }
  if(input.userA && input.userB){
    return buildConvId(input.userA, input.userB);
  }
  if(input.convId){
    const parts = input.convId.split('__');
    if(parts.length === 2) return buildConvId(parts[0], parts[1]);
  }
  if(input.conv){
    const parts = input.conv.split('__');
    if(parts.length === 2) return buildConvId(parts[0], parts[1]);
  }
  return null;
}

module.exports = async (req, res) => {
  // Basic CORS support
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // Lightweight health/check endpoint - does NOT expose secrets
  if (req.method === 'GET'){
    // support a lightweight social fetch: ?action=getSocial&username=...
    try{
      const urlObj = new URL(req.url, 'http://localhost');
      const action = urlObj.searchParams.get('action');
      if(action === 'getSocial'){
        const username = (urlObj.searchParams.get('username')||'').replace(/[^a-z0-9_-]/gi,'_');
        if(!username) return res.status(400).json({ error: 'username required' });
        const basePath = (process.env.GITHUB_PATH || 'libs').replace(/^\/+|\/+$/g, '');
        const socialPath = basePath ? `${basePath}/social/${username}.json` : `social/${username}.json`;
        const api = `https://api.github.com/repos/${process.env.GITHUB_OWNER}/${process.env.GITHUB_REPO}/contents/${encodeURIComponent(socialPath)}`;
        const getResp = await fetchFn(api + `?ref=${encodeURIComponent(process.env.GITHUB_BRANCH || 'main')}`, { headers: { Accept: 'application/vnd.github.v3+json', Authorization: `token ${process.env.GITHUB_TOKEN}` } });
        if(getResp && getResp.status === 200){ const d = await getResp.json(); try{ const json = JSON.parse(Buffer.from(d.content, 'base64').toString('utf8')); return res.status(200).json({ ok:true, social: json }); }catch(e){ return res.status(200).json({ ok:true, social: {} }); } }
        return res.status(200).json({ ok:true, social: {} });
      }
    }catch(e){ /* fall back to generic */ }
    return res.status(200).json({ ok: true, configured: !!(process.env.GITHUB_OWNER && process.env.GITHUB_REPO && process.env.GITHUB_TOKEN), owner: process.env.GITHUB_OWNER||null, repo: process.env.GITHUB_REPO||null, branch: process.env.GITHUB_BRANCH||'main', path: process.env.GITHUB_PATH||'libs' });
  }

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

  const token = process.env.GITHUB_TOKEN;
  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  const branch = process.env.GITHUB_BRANCH || 'main';
  const basePath = (process.env.GITHUB_PATH || 'libs').replace(/^\/+|\/+$/g, '');
  const dmBase = basePath ? `${basePath}/dm` : 'dm';

  if (!token || !owner || !repo) {
    console.error('Missing GITHUB_TOKEN/OWNER/REPO env vars');
    return res.status(500).json({ error: 'Server not configured. Set GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO.' });
  }

  let payload;
  // Support multipart/form-data for avatar upload
  const contentType = req.headers['content-type'] || req.headers['Content-Type'] || '';
  if(contentType.startsWith('multipart/form-data')){
    // Use busboy to parse multipart
    const Busboy = require('busboy');
    payload = {};
    await new Promise((resolve, reject) => {
      const busboy = new Busboy({ headers: req.headers });
      busboy.on('file', (fieldname, file, filename, encoding, mimetype) => {
        let buffers = [];
        file.on('data', data => buffers.push(data));
        file.on('end', () => {
          payload.file = Buffer.concat(buffers);
          payload.mime = mimetype;
          payload.ext = filename.split('.').pop() || 'png';
        });
      });
      busboy.on('field', (fieldname, val) => {
        payload[fieldname] = val;
      });
      busboy.on('finish', resolve);
      busboy.on('error', reject);
      req.pipe(busboy);
    });
  }else{
    try { payload = await readBody(req); } catch (e) { console.error('Body parse error', e); return res.status(400).json({ error: 'Invalid JSON' }); }
  }

  // Only require lib for library save/delete
  let lib, filename, path, apiUrl;

  try {
    // parse action from querystring (e.g., ?action=delete or uploadAvatar or saveDM)
    const urlObj = new URL(req.url, 'http://localhost');
    const action = urlObj.searchParams.get('action');

    // Helper to get file sha if exists
    async function getShaForPath(p){
      const api = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(p)}`;
      const r = await fetchFn(api + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
      if(r && r.status === 200){ const d = await r.json(); return d.sha; }
      return null;
    }

    // handle avatar upload
    if(action === 'uploadAvatar'){
      // Accepts payload.file (Buffer, base64, or raw binary), or payload.dataUrl, and payload.username
      let fileBuffer = null, mime = 'image/png', ext = 'png';
      const username = (payload.username || (payload.lib && payload.lib.username) || 'anonymous').replace(/[^a-z0-9_-]/gi,'_');
      try {
        if(payload.file){
          // If file is a Buffer
          if(Buffer.isBuffer(payload.file)){
            fileBuffer = payload.file;
          }else if(typeof payload.file === 'string'){
            // If base64 string, decode
            fileBuffer = Buffer.from(payload.file, 'base64');
          }else if(payload.file instanceof Uint8Array){
            fileBuffer = Buffer.from(payload.file);
          }
          // Optionally allow mime/ext in payload
          if(payload.mime) mime = payload.mime;
          if(payload.ext) ext = payload.ext;
        }else if(payload.dataUrl || (payload.lib && payload.lib.dataUrl)){
          const dataUrl = payload.dataUrl || (payload.lib && payload.lib.dataUrl);
          const m = dataUrl.match(/^data:(image\/[^;]+);base64,(.+)$/);
          if(!m) throw new Error('Invalid dataUrl');
          mime = m[1];
          fileBuffer = Buffer.from(m[2], 'base64');
          ext = mime.split('/')[1].split('+')[0] || 'png';
        }else{
          throw new Error('Missing file or dataUrl');
        }
        // Fallback: try to guess mime/ext if not provided
        if(!mime || !ext){
          mime = 'image/png'; ext = 'png';
        }
        // Convert to base64 for GitHub
        const b64 = fileBuffer.toString('base64');
        const avBase = basePath ? `${basePath}/avatars` : 'avatars';
        const avPath = `${avBase}/${username}.${ext}`;
        const apiAvatar = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(avPath)}`;
        const sha = await getShaForPath(avPath);
        const putBody = { message: `Upload avatar for ${username}`, content: b64, branch };
        if(sha) putBody.sha = sha;
        const putResp = await fetchFn(apiAvatar, { method: 'PUT', headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json', 'Content-Type': 'application/json' }, body: JSON.stringify(putBody) });
        if(!putResp.ok){ const txt = await putResp.text(); return res.status(putResp.status).json({ error: 'GitHub avatar upload error', detail: txt }); }
        const result = await putResp.json();
        // update social record for user to include avatar url (best-effort)
        try{
          const socialBase = basePath ? `${basePath}/social` : 'social';
          const socialPath = `${socialBase}/${username}.json`;
          const apiSocial = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(socialPath)}`;
          let existing = {};
          const getS = await fetchFn(apiSocial + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
          let sSha = null;
          if(getS && getS.status === 200){ const d = await getS.json(); sSha = d.sha; try{ existing = JSON.parse(Buffer.from(d.content,'base64').toString('utf8')); }catch(e){ existing = {}; } }
          existing.avatar_url = result.content && result.content.download_url;
          const socContent = Buffer.from(JSON.stringify(existing, null, 2), 'utf8').toString('base64');
          const socPut = { message: `Update social for ${username} (avatar)`, content: socContent, branch };
          if(sSha) socPut.sha = sSha;
          await fetchFn(apiSocial, { method: 'PUT', headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json', 'Content-Type': 'application/json' }, body: JSON.stringify(socPut) }).catch(()=>{});
        }catch(e){ /* non-fatal */ }
        return res.status(200).json({ ok: true, result, url: result.content && result.content.download_url });
      } catch (err) {
        console.error('Avatar upload error:', err);
        return res.status(400).json({ error: 'Avatar upload failed', detail: String(err) });
      }
    }

    // handle DM saves
    if(action === 'saveDM'){
      const entry = payload.entry || (payload.lib && payload.lib.entry);
      const convId = resolveConvId({
        convId: payload.convId || payload.conv || (payload.lib && (payload.lib.convId || payload.lib.conv)),
        participants: payload.participants || (payload.lib && payload.lib.participants) || (entry ? [entry.from, entry.to] : null)
      });
      if(!convId || !entry) return res.status(400).json({ error: 'Missing conversation or entry' });
      entry.message = String(entry.message || '').slice(0, 500);
      entry.t = entry.t || Date.now();
      const dmPath = `${dmBase}/${convId}.json`;
      const apiDm = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(dmPath)}`;
      let existing = [];
      const getResp = await fetchFn(apiDm + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
      let sha = null;
      if(getResp && getResp.status === 200){
        const data = await getResp.json();
        sha = data.sha;
        try{ existing = JSON.parse(Buffer.from(data.content, 'base64').toString('utf8')); if(!Array.isArray(existing)) existing = []; }
        catch(e){ existing = []; }
      }
      existing.push(entry);
      const content = Buffer.from(JSON.stringify(existing, null, 2), 'utf8').toString('base64');
      const putBody = { message: `Save DM convo ${convId}`, content, branch };
      if(sha) putBody.sha = sha;
      const putResp = await fetchFn(apiDm, { method: 'PUT', headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json', 'Content-Type': 'application/json' }, body: JSON.stringify(putBody) });
      if(!putResp.ok){ const txt = await putResp.text(); return res.status(putResp.status).json({ error: 'GitHub DM save error', detail: txt }); }
      const result = await putResp.json();
      return res.status(200).json({ ok: true, result });
    }

    if(action === 'getDMConversation'){
      const convId = resolveConvId({
        convId: urlObj.searchParams.get('convId') || (payload && (payload.convId || payload.conv)),
        participants: payload && payload.participants
      });
      if(!convId) return res.status(400).json({ error: 'Missing conversation id' });
      const dmPath = `${dmBase}/${convId}.json`;
      const apiDm = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(dmPath)}`;
      const getResp = await fetchFn(apiDm + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
      if(getResp && getResp.status === 404) return res.status(200).json({ ok:true, messages: [] });
      if(!getResp || getResp.status !== 200){
        const txt = getResp ? await getResp.text() : 'No response';
        return res.status(getResp ? getResp.status : 500).json({ error: 'Failed to load conversation', detail: txt });
      }
      const data = await getResp.json();
      let messages = [];
      try{ messages = JSON.parse(Buffer.from(data.content, 'base64').toString('utf8')); if(!Array.isArray(messages)) messages = []; }
      catch(e){ messages = []; }
      return res.status(200).json({ ok:true, messages });
    }

    if(action === 'listDMs'){
      const usernameRaw = (payload && payload.username) || urlObj.searchParams.get('username');
      if(!usernameRaw) return res.status(400).json({ error: 'username required' });
      const usernameKey = sanitizeDmUser(usernameRaw);
      if(!usernameKey) return res.status(400).json({ error: 'username required' });
      const apiDir = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(dmBase)}`;
      const dirResp = await fetchFn(apiDir + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
      if(dirResp && dirResp.status === 404) return res.status(200).json({ ok:true, conversations: [] });
      if(!dirResp || dirResp.status !== 200){
        const txt = dirResp ? await dirResp.text() : 'No response';
        return res.status(dirResp ? dirResp.status : 500).json({ error: 'Failed to list DMs', detail: txt });
      }
      const files = await dirResp.json();
      const conversations = [];
      if(Array.isArray(files)){
        for(const file of files){
          if(file.type !== 'file' || !file.name.endsWith('.json')) continue;
          const convFile = file.name.replace(/\.json$/,'');
          const parts = convFile.split('__');
          if(parts.length !== 2) continue;
          const [a,b] = parts;
          if(a !== usernameKey && b !== usernameKey) continue;
          let otherDisplay = a === usernameKey ? b : a;
          let lastMessage = null;
          if(file.url){
            try{
              const fileResp = await fetchFn(file.url + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
              if(fileResp && fileResp.status === 200){
                const fileData = await fileResp.json();
                const text = Buffer.from(fileData.content || '', 'base64').toString('utf8');
                const arr = JSON.parse(text);
                if(Array.isArray(arr) && arr.length){
                  const last = arr[arr.length - 1];
                  if(last){
                    lastMessage = { from: last.from || null, message: last.message || '', t: last.t || null };
                    if(last.from && sanitizeDmUser(last.from) !== usernameKey) otherDisplay = last.from;
                    else if(last.to) otherDisplay = last.to;
                  }
                }
              }
            }catch(e){ /* ignore parse errors */ }
          }
          conversations.push({ convId: convFile, participants: [a,b], withUser: otherDisplay, lastMessage });
        }
      }
      return res.status(200).json({ ok:true, conversations });
    }

    // handle updateSocial (save full social object for user)
    if(action === 'updateSocial'){
      const username = (payload.username || (payload.lib && payload.lib.username) || '').replace(/[^a-z0-9_-]/gi,'_');
      const social = payload.social || (payload.lib && payload.lib.social) || null;
      if(!username || !social) return res.status(400).json({ error: 'Missing username or social object' });
      const socialBase = basePath ? `${basePath}/social` : 'social';
      const socialPath = `${socialBase}/${username}.json`;
      const apiSocial = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(socialPath)}`;
      // get existing
      let sSha = null;
      const getS = await fetchFn(apiSocial + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
      if(getS && getS.status === 200){ const d = await getS.json(); sSha = d.sha; }
      const content = Buffer.from(JSON.stringify(social, null, 2), 'utf8').toString('base64');
      const putBody = { message: `Update social for ${username}`, content, branch };
      if(sSha) putBody.sha = sSha;
      const putResp = await fetchFn(apiSocial, { method: 'PUT', headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json', 'Content-Type': 'application/json' }, body: JSON.stringify(putBody) });
      if(!putResp.ok){ const txt = await putResp.text(); return res.status(putResp.status).json({ error: 'GitHub social save error', detail: txt }); }
      const result = await putResp.json();
      return res.status(200).json({ ok: true, result });
    }

    // --- COMMENTS SYSTEM (simple, robust) ---
    // GET comments for a library: ?action=getComments&libId=...
    if(action === 'getComments'){
      const libId = urlObj.searchParams.get('libId') || (payload && (payload.libId || (payload.lib && (payload.lib.id || payload.lib.libId))));
      if(!libId) return res.status(400).json({ error: 'Missing libId' });
      let libPath = `${basePath}/${libId}.json`;
      let apiLib = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(libPath)}`;
      let libData = null;
      let timedOut = false;
      try {
        let getResp = await fetchWithTimeout(apiLib + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } }, 10000);
        if(getResp && getResp.status === 200){
          const d = await getResp.json();
          try{ libData = JSON.parse(Buffer.from(d.content, 'base64').toString('utf8')); }
          catch(e){ libData = null; }
        }
        // Only fallback if id.json not found
        if(!libData){
          // fallback: try id-*.json
          const apiDir = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(basePath)}`;
          const dirResp = await fetchWithTimeout(apiDir + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } }, 10000);
          if(dirResp && dirResp.status === 200){
            const files = await dirResp.json();
            const match = files.find(f=>f.name.startsWith(libId+'-') && f.name.endsWith('.json'));
            if(match){
              libPath = `${basePath}/${match.name}`;
              apiLib = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(libPath)}`;
              getResp = await fetchWithTimeout(apiLib + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } }, 10000);
              if(getResp && getResp.status === 200){
                const d = await getResp.json();
                try{ libData = JSON.parse(Buffer.from(d.content, 'base64').toString('utf8')); }
                catch(e){ libData = null; }
              }
            }
          }
        }
      } catch (err) {
        timedOut = true;
      }
      if(libData && Array.isArray(libData.comments)){
        return res.status(200).json({ ok:true, comments: libData.comments });
      }
      if(timedOut){
        return res.status(504).json({ ok:false, comments: [], error: 'Timeout loading comments' });
      }
      return res.status(200).json({ ok:true, comments: [] });
    }

    if(action === 'rate'){
      const libId = payload.libId || (payload.lib && (payload.lib.id || payload.lib.libId));
      const usernameRaw = payload.username || (payload.lib && payload.lib.username);
      const ratingValue = Number(payload.rating);
      const username = String(usernameRaw || '').trim().slice(0, 60);
      if(!libId || !username) return res.status(400).json({ error: 'Missing libId or username' });
      if(!Number.isFinite(ratingValue)) return res.status(400).json({ error: 'Invalid rating value' });
      const value = Math.min(5, Math.max(1, Math.round(ratingValue)));
      const providedPathRaw = payload.path || (payload.lib && (payload.lib.__path || payload.lib.path));
      const normalizedProvidedPath = providedPathRaw ? normalizeRelativePath(providedPathRaw) : null;
      let libPath = normalizedProvidedPath ? ensureBasePath(normalizedProvidedPath, basePath) : null;
      if(!libPath){
        libPath = `${basePath}/${libId}.json`;
      }
      let apiLib = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(libPath)}`;
      let libData = null;
      let sha = null;
      let getResp = await fetchWithTimeout(apiLib + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } }, 12000);
      if(getResp && getResp.status === 200){
        const d = await getResp.json();
        sha = d.sha;
        try{ libData = JSON.parse(Buffer.from(d.content, 'base64').toString('utf8')); }
        catch(e){ libData = null; }
      }
      if(!libData && !normalizedProvidedPath){
        const apiDir = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(basePath)}`;
        const dirResp = await fetchWithTimeout(apiDir + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } }, 12000);
        if(dirResp && dirResp.status === 200){
          const files = await dirResp.json();
          const match = files.find(f=>f.name.startsWith(libId+'-') && f.name.endsWith('.json'));
          if(match){
            libPath = `${basePath}/${match.name}`;
            apiLib = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(libPath)}`;
            getResp = await fetchWithTimeout(apiLib + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } }, 12000);
            if(getResp && getResp.status === 200){
              const d = await getResp.json();
              sha = d.sha;
              try{ libData = JSON.parse(Buffer.from(d.content, 'base64').toString('utf8')); }
              catch(e){ libData = null; }
            }
          }
        }
      }
      if(!libData) return res.status(404).json({ error: 'Library not found' });
      const authorName = typeof libData.author === 'string' ? libData.author.trim().toLowerCase() : '';
      if(authorName && authorName === normalizedUser){
        return res.status(403).json({ error: 'Authors cannot rate their own posts' });
      }
      const ratings = Array.isArray(libData.ratings) ? libData.ratings : [];
      const normalizedUser = username.toLowerCase();
      const now = Date.now();
      const newEntry = { user: username, value, t: now };
      const existingIdx = ratings.findIndex(r => r && String(r.user || '').toLowerCase() === normalizedUser);
      if(existingIdx >= 0){
        ratings[existingIdx] = { ...ratings[existingIdx], ...newEntry };
      }else{
        ratings.push(newEntry);
      }
      libData.ratings = ratings;
      const calcStats = (list)=>{
        const values = list
          .map(entry => {
            if(!entry) return null;
            const num = Number(entry.value);
            if(!Number.isFinite(num)) return null;
            return Math.min(5, Math.max(1, num));
          })
          .filter(val => typeof val === 'number');
        if(!values.length) return { avg: 0, percent: 0, count: 0 };
        const sum = values.reduce((acc, val)=> acc + val, 0);
        const avg = sum / values.length;
        const percent = Math.round(((avg - 1) / 4) * 100);
        const clampedPercent = Math.max(0, Math.min(100, percent));
        return { avg, percent: clampedPercent, count: values.length };
      };
      const stats = calcStats(ratings);
      const content = toBase64(JSON.stringify(libData, null, 2));
      const putBody = { message: `Update rating for ${libId}`, content, branch };
      if(sha) putBody.sha = sha;
      const putResp = await fetchWithTimeout(apiLib, { method: 'PUT', headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json', 'Content-Type': 'application/json' }, body: JSON.stringify(putBody) }, 12000);
      if(!putResp.ok){
        const txt = await putResp.text();
        return res.status(putResp.status).json({ error: 'GitHub rating save error', detail: txt });
      }
      return res.status(200).json({ ok: true, ratings, stats });
    }

    // POST add a comment: ?action=addComment, body: { libId, comment: { author, text, parentId (optional) } }
    if(action === 'addComment'){
      const libId = payload.libId;
      const comment = payload.comment;
      if(!libId || !comment || !comment.author || !comment.text) return res.status(400).json({ error: 'Missing libId, author, or text' });
      if(comment.text.length > 200) return res.status(400).json({ error: 'Comment too long (max 200)' });
      // Try id.json and id-title.json
      let libPath = `${basePath}/${libId}.json`;
      let apiLib = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(libPath)}`;
      let getResp = await fetchFn(apiLib + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
      let libData = null;
      let sha = null;
      if(getResp && getResp.status === 200){
        const d = await getResp.json(); sha = d.sha;
        try{ libData = JSON.parse(Buffer.from(d.content, 'base64').toString('utf8')); }catch(e){ libData = null; }
      }
      if(!libData){
        // fallback: try id-*.json
        const apiDir = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(basePath)}`;
        const dirResp = await fetchFn(apiDir + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
        if(dirResp && dirResp.status === 200){
          const files = await dirResp.json();
          const match = files.find(f=>f.name.startsWith(libId+'-') && f.name.endsWith('.json'));
          if(match){
            libPath = `${basePath}/${match.name}`;
            apiLib = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(libPath)}`;
            getResp = await fetchFn(apiLib + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
            if(getResp && getResp.status === 200){
              const d = await getResp.json(); sha = d.sha;
              try{ libData = JSON.parse(Buffer.from(d.content, 'base64').toString('utf8')); }catch(e){ libData = null; }
            }
          }
        }
      }
      if(!libData) return res.status(404).json({ error: 'Library not found' });
      if(!Array.isArray(libData.comments)) libData.comments = [];
      // create new comment object
      const newComment = { id: Date.now().toString(36) + Math.random().toString(36).slice(2,8), author: comment.author, text: comment.text.slice(0,200), t: Date.now(), replies: [] };
      if(comment.parentId){
        // find parent and add as reply (recursive)
        function addReply(arr){
          for(const c of arr){
            if(c.id === comment.parentId){ c.replies = c.replies || []; c.replies.push(newComment); return true; }
            if(c.replies && addReply(c.replies)) return true;
          }
          return false;
        }
        if(!addReply(libData.comments)) return res.status(404).json({ error: 'Parent comment not found' });
      }else{
        libData.comments.push(newComment);
      }
      const content = Buffer.from(JSON.stringify(libData, null, 2), 'utf8').toString('base64');
      const putBody = { message: `Add comment to ${libId}`, content, branch };
      if(sha) putBody.sha = sha;
      const putResp = await fetchFn(apiLib, { method: 'PUT', headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json', 'Content-Type': 'application/json' }, body: JSON.stringify(putBody) });
      if(!putResp.ok){ const txt = await putResp.text(); return res.status(putResp.status).json({ error: 'GitHub comment save error', detail: txt }); }
      const result = await putResp.json();
      return res.status(200).json({ ok:true, result, comment: newComment });
    }

    // Default: save library JSON (existing logic)
    // check existing file to get sha
    if(action === 'delete' || !action){
      lib = payload.lib;
      const providedPath = normalizeRelativePath(payload.path);
      filename = payload.filename || null;
      if(providedPath){
        path = ensureBasePath(providedPath, basePath);
        if(!filename){
          const parts = providedPath.split('/');
          filename = parts[parts.length - 1] || null;
        }
      }
      if(!path){
        if(!lib || !lib.title){
          return res.status(400).json({ error: 'Missing lib object or title' });
        }
        filename = filename || `${lib.id || Date.now()}-${sanitizeFilename(lib.title)}.json`;
        path = ensureBasePath(filename, basePath) || filename;
      }
      if(!path){
        return res.status(400).json({ error: 'Unable to resolve path for library' });
      }
      if(!filename){
        const segments = path.split('/');
        filename = segments[segments.length - 1] || 'library.json';
      }
      if(action !== 'delete' && (!lib || !lib.title)){
        return res.status(400).json({ error: 'Missing lib object or title' });
      }

      apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`;

      const getResp = await fetchFn(`${apiUrl}?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
      let sha = null;
      if (getResp && getResp.status === 200) {
        const data = await getResp.json(); sha = data.sha;
      }

      if(action === 'delete'){
        if(!sha) return res.status(404).json({ error: 'File not found' });
        const delResp = await fetchFn(apiUrl, { method: 'DELETE', headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json', 'Content-Type': 'application/json' }, body: JSON.stringify({ message: `Delete library ${filename}`, sha: sha, branch }) });
        if(!delResp.ok){ const txt = await delResp.text(); return res.status(delResp.status).json({ error: 'GitHub API delete error', detail: txt }); }
        const result = await delResp.json();
        return res.status(200).json({ ok: true, result });
      }

      const content = toBase64(JSON.stringify(lib, null, 2));
      const body = { message: `Add/Update library ${lib.title}`, content, branch };
      if (sha) body.sha = sha;

      const putResp = await fetchFn(apiUrl, { method: 'PUT', headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json', 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!putResp.ok) {
        const txt = await putResp.text();
        console.error('GitHub API error', putResp.status, txt);
        return res.status(putResp.status).json({ error: 'GitHub API error', detail: txt });
      }
      const result = await putResp.json();
      console.log('GitHub put result:', result.content && result.content.path);
      return res.status(200).json({ ok: true, result });
    }
  } catch (err) {
    console.error('Internal error', err);
    return res.status(500).json({ error: 'Internal Server Error', detail: String(err) });
  }
};

function sanitizeFilename(name){
  return String(name).replace(/[^a-z0-9-_. ]/gi,'_').slice(0,60);
}

function fetchWithTimeout(url, opts = {}, ms = 10000){
  if(!fetchFn) throw new Error('fetch not available');
  return new Promise((resolve, reject)=>{
    let settled = false;
    const timer = setTimeout(()=>{
      if(settled) return;
      settled = true;
      reject(new Error('timeout'));
    }, ms);
    fetchFn(url, opts)
      .then(res=>{
        if(settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(res);
      })
      .catch(err=>{
        if(settled) return;
        settled = true;
        clearTimeout(timer);
        reject(err);
      });
  });
}

function toBase64(str){
  try{ return Buffer.from(str, 'utf8').toString('base64'); }catch(e){ return Buffer.from(String(str)).toString('base64'); }
}

function normalizeRelativePath(input){
  if(!input) return null;
  return String(input)
    .replace(/\\/g,'/')
    .split('/')
    .map(seg => seg.trim())
    .filter(seg => seg && seg !== '.' && seg !== '..')
    .join('/');
}

function ensureBasePath(relPath, basePath){
  if(!relPath) return null;
  const cleanBase = (basePath || '').replace(/^\/+/,'').replace(/\/+$/,'');
  const cleanRel = relPath.replace(/^\/+/,'');
  if(!cleanBase) return cleanRel;
  const prefix = cleanBase + '/';
  if(cleanRel === cleanBase || cleanRel.startsWith(prefix)){
    return cleanRel;
  }
  return `${cleanBase}/${cleanRel}`;
}
