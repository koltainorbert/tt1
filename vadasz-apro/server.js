'use strict';
const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');

const app    = express();
const PORT   = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || 'vadasz-apro-2026-dev-change-me';
const PUBLIC  = path.join(__dirname, 'public');
const UPLOADS = path.join(PUBLIC, 'uploads');
const DB_FILE = path.join(__dirname, 'db.json');

if (!fs.existsSync(UPLOADS)) fs.mkdirSync(UPLOADS, { recursive: true });

// ── SIMPLE JSON DB ────────────────────────────────────────
function readDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf-8')); }
  catch { return { users: [], listings: [], messages: [] }; }
}
function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function nextId(coll) {
  const data = readDB();
  const items = data[coll] || [];
  return items.length ? Math.max(0, ...items.map(i => i.id)) + 1 : 1;
}
function nowStr() { return new Date().toISOString().replace('T',' ').slice(0,19); }
function validateEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }

// ── MIDDLEWARE ────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.static(PUBLIC));

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Nincs bejelentkezve' });
  try { req.user = jwt.verify(h.slice(7), SECRET); next(); }
  catch { res.status(401).json({ error: 'Ervénytelen token' }); }
}
function optAuth(req, res, next) {
  const h = req.headers.authorization;
  if (h && h.startsWith('Bearer ')) {
    try { req.user = jwt.verify(h.slice(7), SECRET); } catch {}
  }
  next();
}

// ── FILE UPLOAD ───────────────────────────────────────────
const storage = multer.diskStorage({
  destination: UPLOADS,
  filename(_, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g,'');
    cb(null, Date.now() + '-' + Math.random().toString(36).slice(2) + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 8*1024*1024, files: 6 },
  fileFilter(_, file, cb) {
    /^image\/(jpeg|jpg|png|webp|gif)$/i.test(file.mimetype) ? cb(null,true) : cb(new Error('Csak képek'));
  }
});

function fmtListing(l, user) {
  const db = readDB();
  const seller = db.users.find(u => u.id === l.user_id) || {};
  return { ...l, seller_name: seller.name||'', seller_phone: user ? (seller.phone||'') : null, isMine: user ? l.user_id === user.id : false };
}

// ── AUTH ──────────────────────────────────────────────────
app.post('/api/auth/register', (req, res) => {
  const { name, email, password, phone } = req.body || {};
  if (!name||!email||!password) return res.status(400).json({ error: 'Kötelező mezők hiányoznak' });
  if (typeof name!=='string'||name.trim().length<2) return res.status(400).json({ error: 'Érvénytelen név' });
  if (!validateEmail(email)) return res.status(400).json({ error: 'Érvénytelen email cím' });
  if (typeof password!=='string'||password.length<6) return res.status(400).json({ error: 'Jelszó min. 6 karakter' });
  const db = readDB();
  if (db.users.find(u => u.email === email.trim().toLowerCase()))
    return res.status(409).json({ error: 'Ez az email már regisztrált' });
  const hash = bcrypt.hashSync(password, 10);
  const id   = (db.users.length ? Math.max(0,...db.users.map(u=>u.id)) : 0) + 1;
  const user = { id, name:name.trim(), email:email.trim().toLowerCase(), password_hash:hash, phone:(phone||'').toString().trim().slice(0,30), created_at:nowStr() };
  db.users.push(user);
  writeDB(db);
  const token = jwt.sign({ id, name:user.name, email:user.email }, SECRET, { expiresIn:'30d' });
  res.status(201).json({ user:{ id, name:user.name, email:user.email }, token });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email||!password) return res.status(400).json({ error: 'Kötelező mezők hiányoznak' });
  const db   = readDB();
  const user = db.users.find(u => u.email === (email||'').trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Hibás email vagy jelszó' });
  const token = jwt.sign({ id:user.id, name:user.name, email:user.email }, SECRET, { expiresIn:'30d' });
  res.json({ user:{ id:user.id, name:user.name, email:user.email }, token });
});

app.get('/api/auth/me', auth, (req, res) => {
  const u = readDB().users.find(u => u.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'Felhasználó nem található' });
  res.json({ id:u.id, name:u.name, email:u.email, phone:u.phone, created_at:u.created_at });
});

app.put('/api/auth/me', auth, (req, res) => {
  const { name, phone } = req.body || {};
  if (!name||name.trim().length<2) return res.status(400).json({ error: 'Érvénytelen név' });
  const db = readDB();
  const u  = db.users.find(u => u.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'Felhasználó nem található' });
  u.name = name.trim(); u.phone = (phone||'').toString().trim().slice(0,30);
  writeDB(db);
  res.json({ ok:true, name:u.name });
});

// ── LISTINGS ──────────────────────────────────────────────
app.get('/api/listings', optAuth, (req, res) => {
  const { category, search, page='1', sort='new', mine } = req.query;
  const limit  = 24;
  const pg     = Math.max(1, parseInt(page));
  const offset = (pg-1)*limit;
  const q      = (search||'').toLowerCase();
  const db     = readDB();

  let items = db.listings.filter(l => {
    if (mine==='1' && req.user) return l.user_id === req.user.id;
    if (l.status !== 'active') return false;
    if (category && l.category !== category) return false;
    if (q && !l.title.toLowerCase().includes(q) && !l.description.toLowerCase().includes(q) && !(l.location||'').toLowerCase().includes(q)) return false;
    return true;
  });

  items.sort((a,b) => {
    if (sort==='new')        return new Date(b.created_at)-new Date(a.created_at);
    if (sort==='old')        return new Date(a.created_at)-new Date(b.created_at);
    if (sort==='price_asc')  return a.price-b.price;
    if (sort==='price_desc') return b.price-a.price;
    if (sort==='views')      return b.views-a.views;
    return 0;
  });

  const total = items.length;
  res.json({ listings:items.slice(offset,offset+limit).map(l=>fmtListing(l,req.user)), total, page:pg, pages:Math.max(1,Math.ceil(total/limit)) });
});

app.get('/api/listings/:id', optAuth, (req, res) => {
  const db = readDB();
  const l  = db.listings.find(l => l.id === parseInt(req.params.id));
  if (!l) return res.status(404).json({ error: 'Hirdetés nem található' });
  l.views = (l.views||0)+1;
  writeDB(db);
  res.json(fmtListing(l, req.user));
});

app.post('/api/listings', auth, upload.array('images',6), (req, res) => {
  const { title, description, price, category, location } = req.body||{};
  if (!title||!title.trim()) return res.status(400).json({ error: 'A cím kötelező' });
  if (!category||!category.trim()) return res.status(400).json({ error: 'A kategória kötelező' });
  const db     = readDB();
  const images = (req.files||[]).map(f => '/uploads/'+f.filename);
  const id     = (db.listings.length ? Math.max(0,...db.listings.map(l=>l.id)) : 0) + 1;
  const listing = { id, user_id:req.user.id, title:title.trim().slice(0,120), description:(description||'').trim().slice(0,5000), price:Math.max(0,parseInt(price)||0), category:category.trim(), location:(location||'').trim().slice(0,80), images, status:'active', views:0, created_at:nowStr() };
  db.listings.push(listing);
  writeDB(db);
  res.status(201).json(fmtListing(listing, req.user));
});

app.delete('/api/listings/:id', auth, (req, res) => {
  const db = readDB();
  const l  = db.listings.find(l => l.id===parseInt(req.params.id) && l.user_id===req.user.id);
  if (!l) return res.status(404).json({ error: 'Hirdetés nem található' });
  (l.images||[]).forEach(img => { try { fs.unlinkSync(path.join(PUBLIC,img)); } catch {} });
  db.listings = db.listings.filter(x => x.id !== l.id);
  db.messages = db.messages.filter(m => m.listing_id !== l.id);
  writeDB(db);
  res.json({ ok:true });
});

// ── MESSAGES ──────────────────────────────────────────────
app.post('/api/listings/:id/message', (req, res) => {
  const { sender_name, sender_email, message } = req.body||{};
  if (!sender_name||!sender_email||!message) return res.status(400).json({ error: 'Hiányzó adatok' });
  if (!validateEmail(sender_email)) return res.status(400).json({ error: 'Érvénytelen email' });
  if (!message.trim()||message.trim().length<5) return res.status(400).json({ error: 'Üzenet túl rövid' });
  const db = readDB();
  const l  = db.listings.find(l => l.id === parseInt(req.params.id));
  if (!l) return res.status(404).json({ error: 'Hirdetés nem található' });
  const id = (db.messages.length ? Math.max(0,...db.messages.map(m=>m.id)) : 0) + 1;
  db.messages.push({ id, listing_id:l.id, sender_name:sender_name.trim().slice(0,80), sender_email:sender_email.trim().slice(0,120), message:message.trim().slice(0,2000), read:0, created_at:nowStr() });
  writeDB(db);
  res.json({ ok:true });
});

app.get('/api/listings/:id/messages', auth, (req, res) => {
  const db = readDB();
  const l  = db.listings.find(l => l.id===parseInt(req.params.id) && l.user_id===req.user.id);
  if (!l) return res.status(404).json({ error: 'Hirdetés nem található' });
  const msgs = db.messages.filter(m => m.listing_id === l.id).sort((a,b) => b.created_at.localeCompare(a.created_at));
  res.json(msgs);
});

app.get('/api/stats', (_,res) => {
  const db = readDB();
  res.json({ users:db.users.length, listings:db.listings.filter(l=>l.status==='active').length, messages:db.messages.length });
});

app.get('*', (_,res) => res.sendFile(path.join(PUBLIC,'index.html')));

app.use((err,_req,res,_next) => {
  if (err.code==='LIMIT_FILE_SIZE') return res.status(400).json({error:'Fájl túl nagy (max 8 MB)'});
  if (err.code==='LIMIT_FILE_COUNT') return res.status(400).json({error:'Max 6 kép tölthető fel'});
  console.error(err.message);
  res.status(400).json({error:err.message||'Szerver hiba'});
});

app.listen(PORT, () => console.log('VadaszApro 2026 fut: http://localhost:' + PORT));