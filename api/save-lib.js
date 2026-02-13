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

  const lib = payload.lib;
  if (!lib || !lib.title) return res.status(400).json({ error: 'Missing lib object or title' });

  const filename = payload.filename || `${lib.id || Date.now()}-${sanitizeFilename(lib.title)}.json`;
  const path = basePath ? `${basePath}/${filename}` : filename;

  const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`;

  try {
    // check existing file to get sha
    console.log('Checking existing file at', apiUrl, 'branch', branch);
    const getResp = await fetchFn(`${apiUrl}?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
    let sha = null;
    if (getResp && getResp.status === 200) {
      const data = await getResp.json(); sha = data.sha;
      console.log('Existing file sha:', sha);
    } else {
      console.log('File does not exist or cannot be read', getResp && getResp.status);
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
