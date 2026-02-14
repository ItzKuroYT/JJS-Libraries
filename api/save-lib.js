// Serverless function (Vercel / Netlify compatible) to save a library JSON into a GitHub repo.
// Configuration via environment variables:
// GITHUB_TOKEN - a PAT with repo contents permissions (store as a secret in your host)
// GITHUB_OWNER - repo owner
// GITHUB_REPO - repo name
// GITHUB_BRANCH - branch to commit to (default: main)
// GITHUB_PATH - path inside repo to save files (default: libs)

const { URL } = require('url');

// Try to use global fetch (Node 18+ / modern runtimes). Fallback to node-fetch if available.
let fetchFn = global.fetch;
try{ if(!fetchFn) fetchFn = require('node-fetch'); }catch(e){}

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

  if (!token || !owner || !repo) {
    console.error('Missing GITHUB_TOKEN/OWNER/REPO env vars');
    return res.status(500).json({ error: 'Server not configured. Set GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO.' });
  }

  let payload;
  try { payload = await readBody(req); } catch (e) { console.error('Body parse error', e); return res.status(400).json({ error: 'Invalid JSON' }); }

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
      const conv = payload.conv || (payload.lib && payload.lib.conv);
      const entry = payload.entry || (payload.lib && payload.lib.entry);
      if(!conv || !entry) return res.status(400).json({ error: 'Missing conv or entry' });
      const dmBase = basePath ? `${basePath}/dms` : 'dms';
      const dmPath = `${dmBase}/${conv}.json`;
      const apiDm = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(dmPath)}`;
      // get existing
      let existing = [];
      const getResp = await fetchFn(apiDm + `?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
      let sha = null;
      if(getResp && getResp.status === 200){ const data = await getResp.json(); sha = data.sha; try{ existing = JSON.parse(Buffer.from(data.content, 'base64').toString('utf8')); if(!Array.isArray(existing)) existing = []; }catch(e){ existing = []; } }
      existing.push(entry);
      const content = Buffer.from(JSON.stringify(existing, null, 2), 'utf8').toString('base64');
      const putBody = { message: `Save DM convo ${conv}`, content, branch };
      if(sha) putBody.sha = sha;
      const putResp = await fetchFn(apiDm, { method: 'PUT', headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json', 'Content-Type': 'application/json' }, body: JSON.stringify(putBody) });
      if(!putResp.ok){ const txt = await putResp.text(); return res.status(putResp.status).json({ error: 'GitHub DM save error', detail: txt }); }
      const result = await putResp.json();
      return res.status(200).json({ ok: true, result });
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
      const libId = urlObj.searchParams.get('libId');
      if(!libId) return res.status(400).json({ error: 'Missing libId' });
      let libPath = `${basePath}/${libId}.json`;
      let apiLib = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(libPath)}`;
      let libData = null;
      let timedOut = false;
      // Helper to fetch with timeout
      async function fetchWithTimeout(url, opts, ms=10000){
        return Promise.race([
          fetchFn(url, opts),
          new Promise((_, reject)=>setTimeout(()=>reject(new Error('timeout')), ms))
        ]);
      }
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
      if (!lib || !lib.title) return res.status(400).json({ error: 'Missing lib object or title' });
      filename = payload.filename || `${lib.id || Date.now()}-${sanitizeFilename(lib.title)}.json`;
      path = basePath ? `${basePath}/${filename}` : filename;
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

function toBase64(str){
  try{ return Buffer.from(str, 'utf8').toString('base64'); }catch(e){ return Buffer.from(String(str)).toString('base64'); }
}
