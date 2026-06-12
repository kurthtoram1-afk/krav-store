/**
 * KrAV — Game Currency Store backend (deploy-ready version)
 *
 * Storage modes (automatic):
 *  - If MONGODB_URI env var is set  -> uses MongoDB Atlas (for online hosting; data is permanent)
 *  - If not set                     -> uses local data.json file (for testing on your own PC)
 *
 * Run locally:   node server.js
 * On Render:     set env vars MONGODB_URI and ADMIN_PASSWORD
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const DEFAULT_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'krav-admin';
const MONGODB_URI = process.env.MONGODB_URI || '';

/* ================= storage layer ================= */
let store; // { get(key), set(key,value), del(key), list(prefix), getMeta(), setMeta() }

function fileStore() {
  let DB = { kv: {}, _adminPassword: DEFAULT_ADMIN_PASSWORD };
  try {
    if (fs.existsSync(DATA_FILE)) {
      DB = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      if (!DB.kv) DB.kv = {};
      if (!DB._adminPassword) DB._adminPassword = DEFAULT_ADMIN_PASSWORD;
    }
  } catch (e) { console.error('load data.json failed:', e); }
  const save = () => { try { fs.writeFileSync(DATA_FILE, JSON.stringify(DB, null, 2)); } catch (e) { console.error('save failed:', e); } };
  save();
  return {
    mode: 'file',
    async get(k) { return Object.prototype.hasOwnProperty.call(DB.kv, k) ? DB.kv[k] : null; },
    async has(k) { return Object.prototype.hasOwnProperty.call(DB.kv, k); },
    async set(k, v) { DB.kv[k] = v; save(); },
    async del(k) { delete DB.kv[k]; save(); },
    async list(prefix) { const out = []; for (const k in DB.kv) if (k.startsWith(prefix)) out.push(DB.kv[k]); return out; },
    async getPassword() { return DB._adminPassword; },
    async setPassword(p) { DB._adminPassword = p; save(); }
  };
}

async function mongoStore(uri) {
  const { MongoClient } = require('mongodb'); // installed automatically on the host via package.json
  const client = new MongoClient(uri);
  await client.connect();
  const col = client.db('krav').collection('kv');
  await col.createIndex({ _id: 1 });
  // ensure password doc exists
  const meta = await col.findOne({ _id: '_meta' });
  if (!meta) await col.insertOne({ _id: '_meta', password: DEFAULT_ADMIN_PASSWORD });
  console.log('Connected to MongoDB Atlas ✓');
  return {
    mode: 'mongo',
    async get(k) { const d = await col.findOne({ _id: k }); return d ? d.value : null; },
    async has(k) { return !!(await col.findOne({ _id: k }, { projection: { _id: 1 } })); },
    async set(k, v) { await col.updateOne({ _id: k }, { $set: { value: v } }, { upsert: true }); },
    async del(k) { await col.deleteOne({ _id: k }); },
    async list(prefix) {
      const docs = await col.find({ _id: { $regex: '^' + prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') } }).toArray();
      return docs.filter(d => d._id !== '_meta').map(d => d.value);
    },
    async getPassword() { const d = await col.findOne({ _id: '_meta' }); return (d && d.password) || DEFAULT_ADMIN_PASSWORD; },
    async setPassword(p) { await col.updateOne({ _id: '_meta' }, { $set: { password: p } }, { upsert: true }); }
  };
}

/* ================= admin tokens ================= */
const TOKENS = new Set();
function issueToken() { const t = crypto.randomBytes(24).toString('hex'); TOKENS.add(t); return t; }
function isAdmin(req) { const t = req.headers['x-admin-token']; return !!(t && TOKENS.has(t)); }

/* ================= helpers ================= */
function send(res, code, body, type = 'application/json') {
  const data = type === 'application/json' ? JSON.stringify(body) : body;
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(data);
}
function readBody(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', c => { b += c; if (b.length > 5e6) req.destroy(); });
    req.on('end', () => { try { resolve(b ? JSON.parse(b) : {}); } catch { resolve({}); } });
  });
}
const MIME = { '.html':'text/html','.css':'text/css','.js':'text/javascript','.json':'application/json',
  '.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml','.ico':'image/x-icon','.txt':'text/plain','.xml':'application/xml','.webp':'image/webp' };

function canWrite(key, exists, admin) {
  if (key === 'krav:config') return admin;
  if (key.startsWith('krav:order:'))  return exists ? admin : true;
  if (key.startsWith('krav:ticket:')) return exists ? admin : true;
  if (key.startsWith('krav:review:')) return true;
  if (key.startsWith('krav:conv:'))   return true;
  return admin;
}

async function buildStats() {
  const orders = await store.list('krav:order:');
  const reviews = await store.list('krav:review:');
  const delivered = orders.filter(o => o && o.status === 'delivered');
  delivered.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  const recent = delivered.slice(0, 8).map(o => {
    const ign = String(o.ign || '');
    const mask = ign.length > 3 ? ign.slice(0, 3) + '***' : ign + '***';
    const it = (o.items && o.items[0]) || {};
    return { ign: mask, label: it.label || '', currency: it.currency || '' };
  });
  const avg = reviews.length ? reviews.reduce((s, r) => s + (r.rating || 0), 0) / reviews.length : null;
  return { delivered: delivered.length, avgRating: avg ? Number(avg.toFixed(1)) : null, recent };
}

/* ================= server ================= */
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://${req.headers.host}`);
  const p = u.pathname;
  try {
    if (p.startsWith('/api/')) {
      if (p === '/api/admin/login' && req.method === 'POST') {
        const body = await readBody(req);
        const pw = await store.getPassword();
        if (String(body.password || '') === String(pw)) return send(res, 200, { token: issueToken() });
        return send(res, 401, { error: 'invalid' });
      }
      if (p === '/api/admin/password' && req.method === 'POST') {
        if (!isAdmin(req)) return send(res, 403, { error: 'forbidden' });
        const body = await readBody(req);
        if (body.newPassword && String(body.newPassword).trim()) {
          await store.setPassword(String(body.newPassword).trim());
          return send(res, 200, { ok: true });
        }
        return send(res, 400, { error: 'bad' });
      }
      if (p === '/api/stats' && req.method === 'GET') {
        return send(res, 200, await buildStats());
      }
      if (p === '/api/kv/list' && req.method === 'GET') {
        const prefix = u.searchParams.get('prefix') || '';
        const publicList = prefix.startsWith('krav:review:');
        if (!publicList && !isAdmin(req)) return send(res, 403, { error: 'forbidden' });
        return send(res, 200, { values: await store.list(prefix) });
      }
      if (p === '/api/kv' && req.method === 'GET') {
        const key = u.searchParams.get('key') || '';
        let val = await store.get(key);
        if (key === 'krav:config' && val && val.store) { const c = { ...val, store: { ...val.store } }; delete c.store.adminPass; val = c; }
        return send(res, 200, { value: val });
      }
      if (p === '/api/kv' && req.method === 'POST') {
        const body = await readBody(req);
        const key = String(body.key || '');
        if (!key || key === '_meta') return send(res, 400, { error: 'bad key' });
        const exists = await store.has(key);
        if (!canWrite(key, exists, isAdmin(req))) return send(res, 403, { error: 'forbidden' });
        let value = body.value;
        if (key === 'krav:config' && value && value.store && 'adminPass' in value.store) {
          value = { ...value, store: { ...value.store } }; delete value.store.adminPass;
        }
        await store.set(key, value);
        return send(res, 200, { ok: true });
      }
      if (p === '/api/kv' && req.method === 'DELETE') {
        if (!isAdmin(req)) return send(res, 403, { error: 'forbidden' });
        await store.del(u.searchParams.get('key') || '');
        return send(res, 200, { ok: true });
      }
      return send(res, 404, { error: 'not found' });
    }

    /* static files */
    let file = p === '/' ? '/index.html' : decodeURIComponent(p);
    const full = path.join(PUBLIC_DIR, path.normalize(file).replace(/^(\.\.[/\\])+/, ''));
    if (!full.startsWith(PUBLIC_DIR)) return send(res, 403, 'Forbidden', 'text/plain');
    fs.readFile(full, (err, data) => {
      if (err) {
        return fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (e2, d2) => {
          if (e2) return send(res, 404, 'Not found', 'text/plain');
          send(res, 200, d2, 'text/html');
        });
      }
      send(res, 200, data, MIME[path.extname(full)] || 'application/octet-stream');
    });
  } catch (e) {
    console.error(e);
    send(res, 500, { error: 'server error' });
  }
});

/* ================= start ================= */
(async () => {
  try {
    store = MONGODB_URI ? await mongoStore(MONGODB_URI) : fileStore();
  } catch (e) {
    console.error('MongoDB connection failed, falling back to file storage:', e.message);
    store = fileStore();
  }
  server.listen(PORT, () => console.log(`KrAV server running on port ${PORT} (storage: ${store.mode})`));
})();
