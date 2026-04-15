'use strict';
const express  = require('express');
const Database = require('better-sqlite3');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');

const app  = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || 'vadasz-apro-2026-dev-change-me';

// ¦¦ DIRS ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦
const UPLOADS = path.join(__dirname, 'public', 'uploads');
const PUBLIC  = path.join(__dirname, 'public');
if (!fs.existsSync(UPLOADS)) fs.mkdirSync(UPLOADS, { recursive: true });

// ¦¦ DATABASE ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦
const db = new Database(path.join(__dirname, 'vadasz.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    phone         TEXT DEFAULT '',
    created_at    TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS listings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    title       TEXT NOT NULL,
    description TEXT DEFAULT '',
    price       INTEGER DEFAULT 0,
    category    TEXT NOT NULL,
    location    TEXT DEFAULT '',
    images      TEXT DEFAULT '[]',
    status      TEXT DEFAULT 'active',
    views       INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id   INTEGER NOT NULL,
    sender_name  TEXT NOT NULL,
    sender_email TEXT NOT NULL,
    message      TEXT NOT NULL,
    read         INTEGER DEFAULT 0,
    created_at   TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (listing_id) REFERENCES listings(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_listings_cat    ON listings(category);
  CREATE INDEX IF NOT EXISTS idx_listings_status ON listings(status);
  CREATE INDEX IF NOT EXISTS idx_listings_user   ON listings(user_id);
`);

// ¦¦ MIDDLEWARE ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦
app.use(express.json({ limit: '1mb' }));
app.use(express.static(PUBLIC));

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer '))
    return res.status(401).json({ error: 'Nincs bejelentkezve' });
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

// ¦¦ FILE UPLOAD ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦
const storage = multer.diskStorage({
  destination: UPLOADS,
  filename(_, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g,'');
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 8*1024*1024, files: 6 },
  fileFilter(_, file, cb) {
    /^image\/(jpeg|jpg|png|webp|gif)$/i.test(file.mimetype) ? cb(null,true) : cb(new Error('Csak képek'));
  }
});

function fmtListing(row, user) {
  return {
    ...row,
    images:       JSON.parse(row.images || '[]'),
    isMine:       user ? row.user_id === user.id : false,
    seller_phone: user ? (row.seller_phone || '') : null,
  };
}
function validateEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }

// ¦¦ AUTH ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦
app.post('/api/auth/register', (req, res) => {
  const { name, email, password, phone } = req.body || {};
  if (!name||!email||!password) return res.status(400).json({error:'Kötelezõ mezõk hiányoznak'});
  if (typeof name!=='string'||name.trim().length<2) return res.status(400).json({error:'Érvénytelen név'});
  if (!validateEmail(email)) return res.status(400).json({error:'Érvénytelen email cím'});
  if (typeof password!=='string'||password.length<6) return res.status(400).json({error:'Jelszó min. 6 karakter'});
  try {
    const hash = bcrypt.hashSync(password, 10);
    const r = db.prepare('INSERT INTO users (name,email,password_hash,phone) VALUES (?,?,?,?)')
      .run(name.trim(), email.trim().toLowerCase(), hash, (phone||'').toString().trim().slice(0,30));
    const user  = { id: r.lastInsertRowid, name: name.trim(), email: email.trim().toLowerCase() };
    const token = jwt.sign(user, SECRET, { expiresIn:'30d' });
    res.status(201).json({ user, token });
  } catch(e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({error:'Ez az email már regisztrált'});
    console.error(e); res.status(500).json({error:'Szerver hiba'});
  }
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email||!password) return res.status(400).json({error:'Kötelezõ mezõk hiányoznak'});
  const user = db.prepare('SELECT * FROM users WHERE email=?').get((email||'').trim().toLowerCase());
  if (!user||!bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({error:'Hibás email vagy jelszó'});
  const payload = { id:user.id, name:user.name, email:user.email };
  const token   = jwt.sign(payload, SECRET, { expiresIn:'30d' });
  res.json({ user:payload, token });
});

app.get('/api/auth/me', auth, (req, res) => {
  const user = db.prepare('SELECT id,name,email,phone,created_at FROM users WHERE id=?').get(req.user.id);
  if (!user) return res.status(404).json({error:'Felhasználó nem található'});
  res.json(user);
});

app.put('/api/auth/me', auth, (req, res) => {
  const { name, phone } = req.body || {};
  if (!name||name.trim().length<2) return res.status(400).json({error:'Érvénytelen név'});
  db.prepare('UPDATE users SET name=?,phone=? WHERE id=?')
    .run(name.trim(), (phone||'').toString().trim().slice(0,30), req.user.id);
  res.json({ ok:true, name:name.trim(), phone:(phone||'').toString().trim() });
});

// ¦¦ LISTINGS ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦
app.get('/api/listings', optAuth, (req, res) => {
  const { category, search, page='1', sort='new', mine } = req.query;
  const limit  = 24;
  const offset = (Math.max(1,parseInt(page))-1)*limit;
  const conds  = ["l.status='active'"];
  const params = [];

  if (mine==='1'&&req.user) {
    conds.length=0; conds.push('l.user_id=?'); params.push(req.user.id);
  } else {
    if (category) { conds.push('l.category=?'); params.push(category); }
    if (search)   { conds.push('(l.title LIKE ? OR l.description LIKE ? OR l.location LIKE ?)'); params.push(`%${search}%`,`%${search}%`,`%${search}%`); }
  }

  const where  = conds.join(' AND ');
  const orders = { new:'l.created_at DESC', old:'l.created_at ASC', price_asc:'l.price ASC', price_desc:'l.price DESC', views:'l.views DESC' };
  const order  = orders[sort]||'l.created_at DESC';

  const total = db.prepare(`SELECT COUNT(*) n FROM listings l WHERE ${where}`).get(...params).n;
  const rows  = db.prepare(`SELECT l.*,u.name AS seller_name,u.phone AS seller_phone FROM listings l JOIN users u ON l.user_id=u.id WHERE ${where} ORDER BY ${order} LIMIT ? OFFSET ?`).all(...params,limit,offset);
  res.json({ listings:rows.map(r=>fmtListing(r,req.user)), total, page:parseInt(page), pages:Math.max(1,Math.ceil(total/limit)) });
});

app.get('/api/listings/:id', optAuth, (req, res) => {
  const row = db.prepare('SELECT l.*,u.name AS seller_name,u.phone AS seller_phone FROM listings l JOIN users u ON l.user_id=u.id WHERE l.id=?').get(req.params.id);
  if (!row) return res.status(404).json({error:'Hirdetés nem található'});
  db.prepare('UPDATE listings SET views=views+1 WHERE id=?').run(req.params.id);
  row.views+=1;
  res.json(fmtListing(row,req.user));
});

app.post('/api/listings', auth, upload.array('images',6), (req, res) => {
  const { title, description, price, category, location } = req.body||{};
  if (!title||!title.trim()) return res.status(400).json({error:'A cím kötelezõ'});
  if (!category||!category.trim()) return res.status(400).json({error:'A kategória kötelezõ'});
  const images = (req.files||[]).map(f=>'/uploads/'+f.filename);
  const result = db.prepare('INSERT INTO listings (user_id,title,description,price,category,location,images) VALUES (?,?,?,?,?,?,?)')
    .run(req.user.id, title.trim().slice(0,120), (description||'').trim().slice(0,5000), Math.max(0,parseInt(price)||0), category.trim(), (location||'').trim().slice(0,80), JSON.stringify(images));
  const listing = db.prepare('SELECT l.*,u.name AS seller_name,u.phone AS seller_phone FROM listings l JOIN users u ON l.user_id=u.id WHERE l.id=?').get(result.lastInsertRowid);
  res.status(201).json(fmtListing(listing,req.user));
});

app.delete('/api/listings/:id', auth, (req, res) => {
  const listing = db.prepare('SELECT * FROM listings WHERE id=? AND user_id=?').get(req.params.id,req.user.id);
  if (!listing) return res.status(404).json({error:'Hirdetés nem található'});
  JSON.parse(listing.images||'[]').forEach(img=>{ try{ fs.unlinkSync(path.join(PUBLIC,img)); }catch{} });
  db.prepare('DELETE FROM listings WHERE id=?').run(listing.id);
  res.json({ok:true});
});

// ¦¦ MESSAGES ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦
app.post('/api/listings/:id/message', (req, res) => {
  const { sender_name, sender_email, message } = req.body||{};
  if (!sender_name||!sender_email||!message) return res.status(400).json({error:'Hiányzó adatok'});
  if (!validateEmail(sender_email)) return res.status(400).json({error:'Érvénytelen email'});
  if (typeof message!=='string'||message.trim().length<5) return res.status(400).json({error:'Üzenet túl rövid'});
  const listing = db.prepare('SELECT id FROM listings WHERE id=?').get(req.params.id);
  if (!listing) return res.status(404).json({error:'Hirdetés nem található'});
  db.prepare('INSERT INTO messages (listing_id,sender_name,sender_email,message) VALUES (?,?,?,?)')
    .run(listing.id, sender_name.trim().slice(0,80), sender_email.trim().slice(0,120), message.trim().slice(0,2000));
  res.json({ok:true});
});

app.get('/api/listings/:id/messages', auth, (req, res) => {
  const listing = db.prepare('SELECT id FROM listings WHERE id=? AND user_id=?').get(req.params.id,req.user.id);
  if (!listing) return res.status(404).json({error:'Hirdetés nem található'});
  res.json(db.prepare('SELECT * FROM messages WHERE listing_id=? ORDER BY created_at DESC').all(listing.id));
});

app.get('/api/stats', (_,res) => res.json({
  users:    db.prepare('SELECT COUNT(*) n FROM users').get().n,
  listings: db.prepare("SELECT COUNT(*) n FROM listings WHERE status='active'").get().n,
  messages: db.prepare('SELECT COUNT(*) n FROM messages').get().n,
}));

// SPA fallback
app.get('*', (_,res) => res.sendFile(path.join(PUBLIC,'index.html')));

// Error handler
app.use((err,_req,res,_next) => {
  if (err.code==='LIMIT_FILE_SIZE') return res.status(400).json({error:'Fájl túl nagy (max 8 MB)'});
  if (err.code==='LIMIT_FILE_COUNT') return res.status(400).json({error:'Max 6 kép'});
  console.error(err);
  res.status(400).json({error:err.message||'Szerver hiba'});
});

app.listen(PORT, () => console.log(`\n??  VadászApró 2026  ›  http://localhost:${PORT}\n`));
