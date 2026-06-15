/**
 * KrAV — Game Currency Store backend v3
 * Adds: user accounts (email+password), escrow order flow (Binance P2P style),
 *       per-order buyer<->seller chat, proof-of-payment upload.
 *
 * Storage: MongoDB Atlas if MONGODB_URI set, else local data.json (for testing).
 * No external packages except mongodb. Passwords hashed with scrypt (built-in).
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
const BODY_LIMIT = 8e6; // ~8MB (allows a compressed proof screenshot)

const STATUSES = ['awaiting_payment','proof_submitted','payment_verified','delivered','completed','cancelled'];

/* ================= storage layer (file or mongo) ================= */
let store;
function fileStore() {
  let DB = { kv: {}, _adminPassword: DEFAULT_ADMIN_PASSWORD };
  try { if (fs.existsSync(DATA_FILE)) { DB = JSON.parse(fs.readFileSync(DATA_FILE,'utf8')); DB.kv = DB.kv||{}; DB._adminPassword = DB._adminPassword||DEFAULT_ADMIN_PASSWORD; } } catch(e){ console.error(e); }
  const save = () => { try { fs.writeFileSync(DATA_FILE, JSON.stringify(DB,null,2)); } catch(e){ console.error(e); } };
  save();
  return {
    mode:'file',
    async get(k){ return Object.prototype.hasOwnProperty.call(DB.kv,k)?DB.kv[k]:null; },
    async has(k){ return Object.prototype.hasOwnProperty.call(DB.kv,k); },
    async set(k,v){ DB.kv[k]=v; save(); },
    async del(k){ delete DB.kv[k]; save(); },
    async list(prefix){ const o=[]; for(const k in DB.kv) if(k.startsWith(prefix)) o.push(DB.kv[k]); return o; },
    async getPassword(){ return DB._adminPassword; },
    async setPassword(p){ DB._adminPassword=p; save(); }
  };
}
async function mongoStore(uri){
  const { MongoClient } = require('mongodb');
  const client = new MongoClient(uri); await client.connect();
  const col = client.db('krav').collection('kv');
  const meta = await col.findOne({_id:'_meta'});
  if(!meta) await col.insertOne({_id:'_meta', password:DEFAULT_ADMIN_PASSWORD});
  console.log('Connected to MongoDB Atlas \u2713');
  return {
    mode:'mongo',
    async get(k){ const d=await col.findOne({_id:k}); return d?d.value:null; },
    async has(k){ return !!(await col.findOne({_id:k},{projection:{_id:1}})); },
    async set(k,v){ await col.updateOne({_id:k},{$set:{value:v}},{upsert:true}); },
    async del(k){ await col.deleteOne({_id:k}); },
    async list(prefix){ const docs=await col.find({_id:{$regex:'^'+prefix.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}}).toArray(); return docs.filter(d=>d._id!=='_meta').map(d=>d.value); },
    async getPassword(){ const d=await col.findOne({_id:'_meta'}); return (d&&d.password)||DEFAULT_ADMIN_PASSWORD; },
    async setPassword(p){ await col.updateOne({_id:'_meta'},{$set:{password:p}},{upsert:true}); }
  };
}

/* ================= security: tokens & passwords ================= */
let SECRET = null;
let ADMIN_EPOCH = 1; // bumping this invalidates all existing admin sessions
async function ensureSecret(){
  let s = await store.get('krav:_secret');
  if(!s){ s = crypto.randomBytes(32).toString('hex'); await store.set('krav:_secret', s); }
  SECRET = s;
  ADMIN_EPOCH = Number(await store.get('krav:_adminEpoch')) || 1;
}
async function bumpAdminEpoch(){ ADMIN_EPOCH = (Number(await store.get('krav:_adminEpoch'))||1) + 1; await store.set('krav:_adminEpoch', ADMIN_EPOCH); return ADMIN_EPOCH; }
function b64u(buf){ return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function signToken(payload, days=30){
  const body = { ...payload, exp: Date.now() + days*864e5 };
  const p = b64u(JSON.stringify(body));
  const sig = b64u(crypto.createHmac('sha256', SECRET).update(p).digest());
  return p + '.' + sig;
}
function verifyToken(token){
  if(typeof token!=='string' || token.indexOf('.')<0) return null;
  const parts = token.split('.'); if(parts.length!==2) return null;
  const [p, sig] = parts;
  const expect = b64u(crypto.createHmac('sha256', SECRET).update(p).digest());
  const a=Buffer.from(sig), e=Buffer.from(expect);
  if(a.length!==e.length || !crypto.timingSafeEqual(a,e)) return null;
  try{ const body = JSON.parse(Buffer.from(p.replace(/-/g,'+').replace(/_/g,'/'),'base64').toString()); if(!body || typeof body!=='object' || body.exp < Date.now()) return null; return body; }catch(e){ return null; }
}
function isAdmin(req){ const t=verifyToken(req.headers['x-admin-token']); return !!(t && t.role==='admin' && t.ep===ADMIN_EPOCH); }
function userEmail(req){ const t=verifyToken(req.headers['x-auth-token']); return (t && t.role==='user') ? t.sub : null; }

function scryptAsync(pw,salt){ return new Promise((res,rej)=>crypto.scrypt(pw,salt,64,(e,k)=>e?rej(e):res(k))); }
async function hashPw(pw){ const salt=crypto.randomBytes(16).toString('hex'); const h=(await scryptAsync(pw,salt)).toString('hex'); return salt+':'+h; }
async function verifyPw(pw, stored){
  if(!stored || typeof stored!=='string' || stored.indexOf(':')<0) return false;
  const [salt,h]=stored.split(':');
  let a; try{ a=Buffer.from(h,'hex'); }catch(e){ return false; }
  const b=await scryptAsync(pw,salt);
  return a.length===b.length && crypto.timingSafeEqual(a,b);
}
function looksHashed(s){ return typeof s==='string' && /^[0-9a-f]{32}:[0-9a-f]{128}$/.test(s); }
// migrate any legacy plaintext admin password to a salted scrypt hash
async function ensureAdminPassword(){
  const cur = await store.getPassword();
  if(!looksHashed(cur)){
    const plain = (typeof cur==='string' && cur) ? cur : DEFAULT_ADMIN_PASSWORD;
    await store.setPassword(await hashPw(plain));
  }
}

/* ===== TOTP (Google Authenticator) 2FA ===== */
const B32='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buf){ let bits='',out=''; for(const b of buf) bits+=b.toString(2).padStart(8,'0'); for(let i=0;i+5<=bits.length;i+=5) out+=B32[parseInt(bits.substr(i,5),2)]; const rem=bits.length%5; if(rem) out+=B32[parseInt(bits.substr(bits.length-rem).padEnd(5,'0'),2)]; return out; }
function base32Decode(str){ let bits=''; for(const c of String(str).replace(/=+$/,'').toUpperCase()){ const v=B32.indexOf(c); if(v<0) continue; bits+=v.toString(2).padStart(5,'0'); } const bytes=[]; for(let i=0;i+8<=bits.length;i+=8) bytes.push(parseInt(bits.substr(i,8),2)); return Buffer.from(bytes); }
function totpByCounter(secret, counter){ const buf=Buffer.alloc(8); let c=counter; for(let i=7;i>=0;i--){ buf[i]=c&0xff; c=Math.floor(c/256); } const hmac=crypto.createHmac('sha1',base32Decode(secret)).update(buf).digest(); const off=hmac[hmac.length-1]&0xf; const code=((hmac[off]&0x7f)<<24)|((hmac[off+1]&0xff)<<16)|((hmac[off+2]&0xff)<<8)|(hmac[off+3]&0xff); return (code%1000000).toString().padStart(6,'0'); }
// returns the matched 30s counter window (for replay protection), or -1 if no match (±1 window tolerance)
function matchTotpCounter(secret, token){ if(!secret||!token) return -1; token=String(token).trim(); if(!/^[0-9]{6}$/.test(token)) return -1; const base=Math.floor(Date.now()/1000/30); for(let w=-1;w<=1;w++){ if(totpByCounter(secret, base+w)===token) return base+w; } return -1; }
function verifyTotp(secret, token){ return matchTotpCounter(secret, token) >= 0; }

/* ===== generic per-IP rate limiting (in-memory) ===== */
const ipHits = new Map();
function clientIp(req){ return (String(req.headers['x-forwarded-for']||'').split(',')[0].trim()) || (req.socket && req.socket.remoteAddress) || 'unknown'; }
function rateOk(req, bucket, max, windowMs){
  const key=bucket+':'+clientIp(req); const now=Date.now();
  let e=ipHits.get(key);
  if(!e || now>e.reset){ e={count:0,reset:now+windowMs}; ipHits.set(key,e); }
  e.count++; return e.count<=max;
}
setInterval(()=>{ const now=Date.now(); for(const [k,v] of ipHits){ if(now>v.reset) ipHits.delete(k); } }, 10*60000);
// reasonable byte cap for anything the public can store (reviews, support chats, tickets)
const PUBLIC_KV_LIMIT = 120000; // ~120KB
function isPlainObject(v){ return v && typeof v==='object' && !Array.isArray(v); }

/* ================= helpers ================= */
const SECURITY_HEADERS={
  'X-Content-Type-Options':'nosniff',
  'X-Frame-Options':'DENY',
  'Referrer-Policy':'no-referrer',
  'Permissions-Policy':'geolocation=(), microphone=(), camera=()',
  'Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
};
function send(res,code,body,type='application/json'){ const d=type==='application/json'?JSON.stringify(body):body; res.writeHead(code,{'Content-Type':type,'Cache-Control':'no-store',...SECURITY_HEADERS}); res.end(d); }
function readBody(req){
  return new Promise(resolve=>{
    let b=''; let done=false;
    const finish=v=>{ if(done) return; done=true; resolve(v); };
    req.on('data',c=>{ if(done) return; b+=c; if(b.length>BODY_LIMIT){ finish({}); try{ req.destroy(); }catch(e){} } });
    req.on('end',()=>{ try{ finish(b?JSON.parse(b):{}); }catch{ finish({}); } });
    req.on('error',()=>finish({}));
    req.on('aborted',()=>finish({}));
    req.on('close',()=>finish({}));
  });
}
const MIME={'.html':'text/html','.css':'text/css','.js':'text/javascript','.json':'application/json','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml','.ico':'image/x-icon','.txt':'text/plain','.xml':'application/xml','.webp':'image/webp'};
const uid = p => p + crypto.randomBytes(4).toString('hex');
const orderId = () => 'KRAV-' + (Date.now().toString(36).toUpperCase().slice(-4)) + crypto.randomBytes(3).toString('hex').toUpperCase();
const cleanEmail = e => String(e||'').trim().toLowerCase();
function publicUser(u){ return u?{ email:u.email, name:u.name, createdAt:u.createdAt }:null; }
function orderSummary(o){ return { id:o.id, status:o.status, total:o.total, items:o.items, createdAt:o.createdAt, updatedAt:o.updatedAt, hasProof:!!o.proof, unreadForSeller:o.unreadForSeller, unreadForBuyer:o.unreadForBuyer }; }

function canWriteKV(key, exists, admin){
  if(key==='krav:config') return admin;
  if(key.startsWith('krav:review:')) return true;
  if(key.startsWith('krav:ticket:')) return exists?admin:true;
  if(key.startsWith('krav:conv:')) return true;
  return admin;
}

async function buildStats(){
  const orders = await store.list('krav:order:');
  const reviews = await store.list('krav:review:');
  const done = orders.filter(o=>o && (o.status==='delivered'||o.status==='completed'));
  done.sort((a,b)=>(b.createdAt||0)-(a.createdAt||0));
  const recent = done.slice(0,8).map(o=>{ const ign=String(o.ign||''); const it=(o.items&&o.items[0])||{}; return { ign: ign.length>3?ign.slice(0,3)+'***':(ign+'***'), label:it.label||'', currency:it.currency||'' }; });
  const avg = reviews.length ? reviews.reduce((s,r)=>s+(r.rating||0),0)/reviews.length : null;
  return { delivered:done.length, avgRating: avg?Number(avg.toFixed(1)):null, recent };
}

// Auto-cancel orders left in 'awaiting_payment' (no proof) past the configured limit.
async function sweepExpired(){
  try{
    const cfg = await store.get('krav:config') || {};
    const mins = Number((cfg.store && cfg.store.autoCancelMins) || 0);
    if(!mins || mins<=0) return; // 0 / blank = feature off
    const cutoff = Date.now() - mins*60000;
    const orders = await store.list('krav:order:');
    for(const o of orders){
      if(o && o.status==='awaiting_payment' && Number(o.createdAt) < cutoff){
        const now=Date.now();
        o.status='cancelled'; o.updatedAt=now; o.cancelReason='auto';
        o.timeline = o.timeline||[]; o.timeline.push({status:'cancelled',at:now,auto:true});
        o.messages = o.messages||[];
        o.messages.push({from:'seller', text:'This order was automatically cancelled because payment was not completed in time. You can place a new order anytime.', at:now});
        o.unreadForBuyer=true;
        await store.set('krav:order:'+o.id, o);
      }
    }
  }catch(e){ console.error('sweep error', e.message); }
}

/* ================= server ================= */
const server = http.createServer(async (req,res)=>{
  const u = new URL(req.url, `http://${req.headers.host}`);
  const p = u.pathname;
  try{
    if(p.startsWith('/api/')){

      /* ---------- AUTH ---------- */
      if(p==='/api/auth/register' && req.method==='POST'){
        if(!rateOk(req,'auth',25,15*60000)) return send(res,429,{error:'Too many attempts. Please wait a few minutes.'});
        const b=await readBody(req); const email=cleanEmail(b.email).slice(0,120); const name=String(b.name||'').trim().slice(0,60); const pw=String(b.password||'');
        if(!email||!email.includes('@')||!name||pw.length<6) return send(res,400,{error:'Please enter a valid email, name, and a password of at least 6 characters.'});
        if(pw.length>200) return send(res,400,{error:'Password is too long.'});
        if(await store.has('krav:user:'+email)) return send(res,409,{error:'An account with this email already exists. Try logging in.'});
        const user={ email, name, pw:await hashPw(pw), createdAt:Date.now() };
        await store.set('krav:user:'+email, user);
        return send(res,200,{ token:signToken({role:'user',sub:email}), user:publicUser(user) });
      }
      if(p==='/api/auth/login' && req.method==='POST'){
        if(!rateOk(req,'auth',25,15*60000)) return send(res,429,{error:'Too many attempts. Please wait a few minutes.'});
        const b=await readBody(req); const email=cleanEmail(b.email); const pw=String(b.password||'');
        const user=await store.get('krav:user:'+email);
        if(!user||!(await verifyPw(pw,user.pw))) return send(res,401,{error:'Wrong email or password.'});
        return send(res,200,{ token:signToken({role:'user',sub:email}), user:publicUser(user) });
      }
      if(p==='/api/me' && req.method==='GET'){
        const email=userEmail(req); if(!email) return send(res,401,{error:'Not logged in'});
        await sweepExpired();
        const user=await store.get('krav:user:'+email);
        const orders=(await store.list('krav:order:')).filter(o=>o && o.userEmail===email).sort((a,b)=>b.createdAt-a.createdAt).map(orderSummary);
        return send(res,200,{ user:publicUser(user), orders });
      }

      /* ---------- ORDERS ---------- */
      // create order (must be logged in) — price computed server-side
      if(p==='/api/orders' && req.method==='POST'){
        const email=userEmail(req); if(!email) return send(res,401,{error:'Please log in to place an order.'});
        if(!rateOk(req,'order',40,60*60000)) return send(res,429,{error:'Too many orders in a short time. Please wait a bit.'});
        const b=await readBody(req);
        const cfg=await store.get('krav:config')||{}; const packages=cfg.packages||[]; const payments=cfg.payments||[];
        const reqItems=(Array.isArray(b.items)?b.items:[]).slice(0,50);
        const items=[]; let total=0;
        for(const ri of reqItems){
          const pkg=packages.find(x=>x.id===ri.id && x.active);
          if(!pkg || Number(pkg.price)<=0) continue;
          const qty=Math.max(1,Math.min(99,parseInt(ri.qty)||1));
          const cur = pkg.game==='toram'?'Spina':'Penya';
          items.push({ label:pkg.label, currency:cur, qty, price:Number(pkg.price) });
          total += Number(pkg.price)*qty;
        }
        if(!items.length) return send(res,400,{error:'Your cart is empty or items are unavailable.'});
        const pay=payments.find(x=>x.id===b.paymentId && x.active) || payments.find(x=>x.active) || null;
        const now=Date.now();
        const order={
          id:orderId(), userEmail:email, ign:String(b.ign||'').trim().slice(0,80), server:String(b.server||'').trim().slice(0,80),
          note:String(b.note||'').trim().slice(0,500), items, total,
          payment: pay?{type:pay.type,name:pay.name,number:pay.number}:null,
          status:'awaiting_payment', proof:null, reference:'',
          messages:[], timeline:[{status:'awaiting_payment',at:now}],
          unreadForSeller:false, unreadForBuyer:false, createdAt:now, updatedAt:now
        };
        if(!order.ign) return send(res,400,{error:'Please enter your in-game name (IGN).'});
        await store.set('krav:order:'+order.id, order);
        return send(res,200,{ order });
      }
      // order detail (owner or admin)
      const mOrder = p.match(/^\/api\/orders\/([A-Za-z0-9\-]+)$/);
      if(mOrder && req.method==='GET'){
        const o=await store.get('krav:order:'+mOrder[1]); if(!o) return send(res,404,{error:'Order not found'});
        const admin=isAdmin(req); const email=userEmail(req);
        if(!admin && o.userEmail!==email) return send(res,403,{error:'forbidden'});
        // inline auto-cancel if this order is unpaid and past the limit
        if(o.status==='awaiting_payment'){
          const cfg=await store.get('krav:config')||{}; const mins=Number((cfg.store&&cfg.store.autoCancelMins)||0);
          if(mins>0 && Number(o.createdAt) < Date.now()-mins*60000){
            const now=Date.now(); o.status='cancelled'; o.updatedAt=now; o.cancelReason='auto';
            o.timeline=o.timeline||[]; o.timeline.push({status:'cancelled',at:now,auto:true});
            o.messages=o.messages||[]; o.messages.push({from:'seller',text:'This order was automatically cancelled because payment was not completed in time. You can place a new order anytime.',at:now});
            o.unreadForBuyer=true; await store.set('krav:order:'+o.id,o);
          }
        }
        // mark read for the viewer
        if(admin && o.unreadForSeller){ o.unreadForSeller=false; await store.set('krav:order:'+o.id,o); }
        if(!admin && o.unreadForBuyer){ o.unreadForBuyer=false; await store.set('krav:order:'+o.id,o); }
        return send(res,200,{ order:o });
      }
      // delete order (admin only)
      if(mOrder && req.method==='DELETE'){
        if(!isAdmin(req)) return send(res,403,{error:'forbidden'});
        await store.del('krav:order:'+mOrder[1]);
        return send(res,200,{ ok:true });
      }
      // submit proof (owner only)
      const mProof = p.match(/^\/api\/orders\/([A-Za-z0-9\-]+)\/proof$/);
      if(mProof && req.method==='POST'){
        const email=userEmail(req); if(!email) return send(res,401,{error:'Please log in.'});
        const o=await store.get('krav:order:'+mProof[1]); if(!o) return send(res,404,{error:'Order not found'});
        if(o.userEmail!==email) return send(res,403,{error:'forbidden'});
        const b=await readBody(req);
        const img=String(b.image||'');
        if(!/^data:image\/(png|jpe?g|webp);base64,/i.test(img)) return send(res,400,{error:'Please attach a valid image screenshot (PNG/JPG).'});
        if(img.length > 2.6e6) return send(res,413,{error:'Image too large. Please use a smaller screenshot.'});
        o.proof=img; o.reference=String(b.reference||'').trim().slice(0,120);
        o.status='proof_submitted'; o.updatedAt=Date.now(); o.unreadForSeller=true;
        o.timeline.push({status:'proof_submitted',at:o.updatedAt});
        await store.set('krav:order:'+o.id,o);
        return send(res,200,{ ok:true, order:o });
      }
      // chat message (owner or admin)
      const mMsg = p.match(/^\/api\/orders\/([A-Za-z0-9\-]+)\/message$/);
      if(mMsg && req.method==='POST'){
        const admin=isAdmin(req); const email=userEmail(req);
        const o=await store.get('krav:order:'+mMsg[1]); if(!o) return send(res,404,{error:'Order not found'});
        if(!admin && o.userEmail!==email) return send(res,403,{error:'forbidden'});
        if(!admin && !rateOk(req,'msg',60,5*60000)) return send(res,429,{error:'Slow down a moment.'});
        o.messages=o.messages||[];
        if(o.messages.length>=1000) return send(res,429,{error:'This chat has reached its limit.'});
        const b=await readBody(req); const text=String(b.text||'').trim().slice(0,1000);
        if(!text) return send(res,400,{error:'Empty message'});
        o.messages.push({ from: admin?'seller':'buyer', text, at:Date.now() });
        if(admin) o.unreadForBuyer=true; else o.unreadForSeller=true;
        o.updatedAt=Date.now();
        await store.set('krav:order:'+o.id,o);
        return send(res,200,{ ok:true });
      }
      // buyer confirms received -> completed
      const mConfirm = p.match(/^\/api\/orders\/([A-Za-z0-9\-]+)\/confirm$/);
      if(mConfirm && req.method==='POST'){
        const email=userEmail(req); if(!email) return send(res,401,{error:'Please log in.'});
        const o=await store.get('krav:order:'+mConfirm[1]); if(!o) return send(res,404,{error:'Order not found'});
        if(o.userEmail!==email) return send(res,403,{error:'forbidden'});
        if(o.status!=='delivered') return send(res,400,{error:'You can confirm only after the order is delivered.'});
        o.status='completed'; o.updatedAt=Date.now(); o.timeline.push({status:'completed',at:o.updatedAt}); o.unreadForSeller=true;
        await store.set('krav:order:'+o.id,o);
        return send(res,200,{ ok:true, order:o });
      }
      // admin set status
      const mStatus = p.match(/^\/api\/orders\/([A-Za-z0-9\-]+)\/status$/);
      if(mStatus && req.method==='POST'){
        if(!isAdmin(req)) return send(res,403,{error:'forbidden'});
        const o=await store.get('krav:order:'+mStatus[1]); if(!o) return send(res,404,{error:'Order not found'});
        const b=await readBody(req); const st=String(b.status||'');
        if(!STATUSES.includes(st)) return send(res,400,{error:'bad status'});
        o.status=st; o.updatedAt=Date.now(); o.timeline.push({status:st,at:o.updatedAt}); o.unreadForBuyer=true;
        await store.set('krav:order:'+o.id,o);
        return send(res,200,{ ok:true, order:o });
      }
      // admin list all orders (summary)
      if(p==='/api/admin/orders' && req.method==='GET'){
        if(!isAdmin(req)) return send(res,403,{error:'forbidden'});
        await sweepExpired();
        const orders=(await store.list('krav:order:')).sort((a,b)=>b.createdAt-a.createdAt).map(o=>({ ...orderSummary(o), ign:o.ign, userEmail:o.userEmail, payment:o.payment }));
        return send(res,200,{ orders });
      }

      /* ---------- existing KV + stats + admin ---------- */
      if(p==='/api/admin/login' && req.method==='POST'){
        if(!rateOk(req,'adminlogin',12,15*60000)) return send(res,429,{error:'Too many attempts. Try again in a few minutes.'});
        const b=await readBody(req); const hash=await store.getPassword();
        if(!(await verifyPw(String(b.password||''), hash))) return send(res,401,{error:'invalid'});
        const totpSecret=await store.get('krav:_totp');
        if(totpSecret){
          if(!b.code) return send(res,401,{error:'2FA code required', need2fa:true});
          const mc=matchTotpCounter(totpSecret, b.code);
          if(mc<0) return send(res,401,{error:'Invalid 2FA code', need2fa:true});
          const last=Number(await store.get('krav:_totpLast'))||0;
          if(mc<=last) return send(res,401,{error:'That code was already used — wait for the next one.', need2fa:true});
          await store.set('krav:_totpLast', mc);
        }
        return send(res,200,{ token:signToken({role:'admin', ep:ADMIN_EPOCH}) });
      }
      if(p==='/api/admin/2fa/status' && req.method==='GET'){
        if(!isAdmin(req)) return send(res,403,{error:'forbidden'});
        return send(res,200,{ enabled: !!(await store.get('krav:_totp')) });
      }
      if(p==='/api/admin/2fa/setup' && req.method==='POST'){
        if(!isAdmin(req)) return send(res,403,{error:'forbidden'});
        const secret=base32Encode(crypto.randomBytes(20));
        await store.set('krav:_totp_pending', secret);
        const uri='otpauth://totp/KrAV%20Seller?secret='+secret+'&issuer=KrAV&digits=6&period=30';
        return send(res,200,{ secret, uri });
      }
      if(p==='/api/admin/2fa/enable' && req.method==='POST'){
        if(!isAdmin(req)) return send(res,403,{error:'forbidden'});
        const b=await readBody(req); const pending=await store.get('krav:_totp_pending');
        if(!pending) return send(res,400,{error:'Start setup first'});
        if(!verifyTotp(pending, b.code)) return send(res,401,{error:'That code is wrong. Check your authenticator app and try again.'});
        await store.set('krav:_totp', pending); await store.del('krav:_totp_pending');
        return send(res,200,{ ok:true });
      }
      if(p==='/api/admin/2fa/disable' && req.method==='POST'){
        if(!isAdmin(req)) return send(res,403,{error:'forbidden'});
        const b=await readBody(req); const secret=await store.get('krav:_totp');
        if(!secret) return send(res,200,{ ok:true });
        if(!verifyTotp(secret, b.code)) return send(res,401,{error:'Enter your current 2FA code to turn it off.'});
        await store.del('krav:_totp');
        return send(res,200,{ ok:true });
      }
      if(p==='/api/admin/logout-all' && req.method==='POST'){
        if(!isAdmin(req)) return send(res,403,{error:'forbidden'});
        await bumpAdminEpoch();
        // keep THIS device signed in with a fresh token on the new epoch
        return send(res,200,{ ok:true, token:signToken({role:'admin', ep:ADMIN_EPOCH}) });
      }
      if(p==='/api/admin/password' && req.method==='POST'){
        if(!isAdmin(req)) return send(res,403,{error:'forbidden'});
        const b=await readBody(req); const np=String(b.newPassword||'').trim();
        if(np.length<6) return send(res,400,{error:'New password must be at least 6 characters.'});
        if(np.length>200) return send(res,400,{error:'Password is too long.'});
        await store.setPassword(await hashPw(np));
        return send(res,200,{ok:true});
      }
      if(p==='/api/stats' && req.method==='GET'){ return send(res,200,await buildStats()); }
      if(p==='/api/kv/list' && req.method==='GET'){
        const prefix=u.searchParams.get('prefix')||'';
        if(!prefix.startsWith('krav:review:') && !isAdmin(req)) return send(res,403,{error:'forbidden'});
        return send(res,200,{ values:await store.list(prefix) });
      }
      if(p==='/api/kv' && req.method==='GET'){
        const key=u.searchParams.get('key')||'';
        // never expose internal secrets or per-user/order records through generic KV
        if(key.startsWith('krav:_') || key==='_meta' || key.startsWith('krav:user:') || key.startsWith('krav:order:')) return send(res,403,{error:'forbidden'});
        let val=await store.get(key);
        if(key==='krav:config' && val && val.store){ const c={...val,store:{...val.store}}; delete c.store.adminPass; val=c; }
        return send(res,200,{ value:val });
      }
      if(p==='/api/kv' && req.method==='POST'){
        const b=await readBody(req); const key=String(b.key||'');
        if(!key||key.length>200||key.startsWith('krav:_')||key==='_meta') return send(res,400,{error:'bad key'});
        if(key.startsWith('krav:user:')||key.startsWith('krav:order:')) return send(res,400,{error:'use the dedicated API'});
        const admin=isAdmin(req);
        const exists=await store.has(key);
        if(!canWriteKV(key,exists,admin)) return send(res,403,{error:'forbidden'});

        // Reviews: must be a logged-in buyer; shaped & sanitized on the server.
        if(key.startsWith('krav:review:') && !admin){
          const email=userEmail(req); if(!email) return send(res,401,{error:'Please log in to write a review.'});
          if(!rateOk(req,'review',10,60*60000)) return send(res,429,{error:'Too many reviews. Please wait a while.'});
          const v=isPlainObject(b.value)?b.value:{};
          const rating=Math.max(1,Math.min(5,parseInt(v.rating)||0));
          if(!rating) return send(res,400,{error:'Please choose a star rating.'});
          const clean={ rating, text:String(v.text||'').trim().slice(0,600), name:String(v.name||'').trim().slice(0,40), game:String(v.game||'').trim().slice(0,40), by:email, createdAt:Date.now() };
          await store.set(key, clean); return send(res,200,{ok:true});
        }

        // Other public writes (support conversations, tickets): rate + size + shape guards.
        if(!admin){
          if(!rateOk(req,'kv',80,60*60000)) return send(res,429,{error:'Too many requests. Please slow down.'});
          if(!isPlainObject(b.value)) return send(res,400,{error:'bad value'});
          if(JSON.stringify(b.value).length > PUBLIC_KV_LIMIT) return send(res,413,{error:'Too much data.'});
        }

        let value=b.value; if(key==='krav:config'&&value&&value.store&&'adminPass'in value.store){ value={...value,store:{...value.store}}; delete value.store.adminPass; }
        await store.set(key,value); return send(res,200,{ok:true});
      }
      if(p==='/api/kv' && req.method==='DELETE'){
        if(!isAdmin(req)) return send(res,403,{error:'forbidden'});
        const key=u.searchParams.get('key')||''; if(key.startsWith('krav:_')) return send(res,400,{error:'protected'});
        await store.del(key); return send(res,200,{ok:true});
      }
      return send(res,404,{error:'not found'});
    }

    /* static files */
    let file = p==='/'?'/index.html':decodeURIComponent(p);
    const full = path.join(PUBLIC_DIR, path.normalize(file).replace(/^(\.\.[/\\])+/,''));
    if(!full.startsWith(PUBLIC_DIR)) return send(res,403,'Forbidden','text/plain');
    fs.readFile(full,(err,data)=>{ if(err){ return fs.readFile(path.join(PUBLIC_DIR,'index.html'),(e2,d2)=>{ if(e2) return send(res,404,'Not found','text/plain'); send(res,200,d2,'text/html'); }); } send(res,200,data,MIME[path.extname(full)]||'application/octet-stream'); });
  }catch(e){ console.error(e); send(res,500,{error:'server error'}); }
});

(async()=>{
  try{ store = MONGODB_URI ? await mongoStore(MONGODB_URI) : fileStore(); }
  catch(e){ console.error('Mongo failed, using file store:', e.message); store = fileStore(); }
  await ensureSecret();
  await ensureAdminPassword();
  server.listen(PORT, ()=>console.log(`KrAV server running on port ${PORT} (storage: ${store.mode})`));
  setInterval(()=>sweepExpired(), 5*60000); // periodic auto-cancel sweep while awake
})();
