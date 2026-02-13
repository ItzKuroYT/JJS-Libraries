// Serverless function (Vercel / Netlify compatible) to save a library JSON into a GitHub repo.
// Configuration via environment variables:
// GITHUB_TOKEN - a PAT with repo contents permissions (store as a secret in your host)
// GITHUB_OWNER - repo owner
// GITHUB_REPO - repo name
// GITHUB_BRANCH - branch to commit to (default: main)
// GITHUB_PATH - path inside repo to save files (default: libs)

const { URL } = require('url');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

  const token = process.env.GITHUB_TOKEN;
  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  const branch = process.env.GITHUB_BRANCH || 'main';
  const basePath = (process.env.GITHUB_PATH || 'libs').replace(/^\/+|\/+$/g, '');

  let payload;
  try { payload = req.body; } catch (e) { return res.status(400).json({ error: 'Invalid JSON' }); }

  const lib = payload.lib;
  if (!lib || !lib.title) return res.status(400).json({ error: 'Missing lib object or title' });

  const filename = payload.filename || `${lib.id || Date.now()}-${sanitizeFilename(lib.title)}.json`;
  const path = basePath ? `${basePath}/${filename}` : filename;

  const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`;

  try {
    // check existing file to get sha
    const getResp = await fetch(`${apiUrl}?ref=${encodeURIComponent(branch)}`, { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } });
    let sha = null;
    if (getResp.status === 200) {
      const data = await getResp.json(); sha = data.sha;
    }

    const content = toBase64(JSON.stringify(lib, null, 2));
    const body = { message: `Add/Update library ${lib.title}`, content, branch };
    if (sha) body.sha = sha;

    const putResp = await fetch(apiUrl, { method: 'PUT', headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json', 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!putResp.ok) {
      const txt = await putResp.text();
      return res.status(putResp.status).json({ error: 'GitHub API error', detail: txt });
    }
    const result = await putResp.json();
    return res.status(200).json({ ok: true, result });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal Server Error', detail: String(err) });
  }
};

function sanitizeFilename(name){
  return String(name).replace(/[^a-z0-9-_. ]/gi,'_').slice(0,60);
}

function toBase64(str){
  try{ return Buffer.from(str, 'utf8').toString('base64'); }catch(e){ return Buffer.from(String(str)).toString('base64'); }
}
