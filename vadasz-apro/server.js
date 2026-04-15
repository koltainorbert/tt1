'use strict';
const express  = require('express');
const Database = require('better-sqlite3');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');

const app    = express();
const PORT   = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || 'vadasz-apro-2026-changeme';

// ── UPLOADS DIR ───────────────────────────────────────────
const UPLOADS = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOADS)) fs.mkdirSync(UPLOADS, { recursive: true });

// ── DATABASE ──────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'vadasz.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    email         TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    phone         TEXT    DEFAULT '',
    created_at    TEXT    DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS listings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    title       TEXT    NOT NULL,
    description TEXT    DEFAULT '',
    price       INTEGER DEFAULT 0,
    category    TEXT    NOT NULL,
    location    TEXT    DEFAULT '',
    images      TEXT    DEFAULT '[]',
    status      TEXT    DEFAULT 'active',
    views       INTEGER DEFAULT 0,
    created_at  TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id    INTEGER NOT NULL,
    sender_name   TEXT    NOT NULL,
    sender_email  TEXT    NOT NULL,
    message       TEXT    NOT NULL,
    read          INTEGER DEFAULT 0,
    created_at    TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (listing_id) REFERENCES listings(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_listings_cat    ON listings(category);
  CREATE INDEX IF NOT EXISTS idx_listings_user   ON listings(user_id);
  CREATE INDEX IF NOT EXISTS idx_listings_status ON listings(status);
`);

// ── MIDDLEWARE ────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH MIDDLEWARE ───────────────────────────────────────
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Nincs bejelentkezve' });
  try { req.user = jwt.verify(h.slice(7), SECRET); next(); }
  catch { res.status(401).json({ error: 'Érvénytelen token' }); }
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
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, '');
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024, files: 6 },
  fileFilter: (_, file, cb) => {
    if (/^image\/(jpeg|jpg|png|webp|gif)$/i.test(file.mimetype)) cb(null, true);
    else cb(new Error('Csak képfájlok tölthetők fel'));
  }
});

// ── HELPERS ───────────────────────────────────────────────
const isEmail = s => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
const fmt = (row, user) => ({
  ...row,
  images:  JSON.parse(row.images  || '[]'),
  isMine:  user ? row.user_id === user.id : false
});

// ── AUTH ROUTES ───────────────────────────────────────────
app.post('/api/auth/register', (req, res) => {
  const { name, email, password, phone } = req.body || {};
  if (!name || !email || !password)        return res.status(400).json({ error: 'Hiányzó adatok' });
  if (!isEmail(email))                     return res.status(400).json({ error: 'Érvénytelen email cím' });
  if (password.length < 6)                 return res.status(400).json({ error: 'A jelszó minimum 6 karakter' });
  if (name.trim().length < 2)              return res.status(400).json({ error: 'A név legalább 2 karakter' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const r = db.prepare(
      'INSERT INTO users (name, email, password_hash, phone) VALUES (?, ?, ?, ?)'
    ).run(name.trim(), email.trim().toLowerCase(), hash, (phone || '').trim());
    const user  = { id: r.lastInsertRowid, name: name.trim(), email: email.trim().toLowerCase() };
    const token = jwt.sign(user, SECRET, { expiresIn: '30d' });
    res.status(201).json({ user, token });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'Ez az email már regisztrált' });
    console.error(e); res.status(500).json({ error: 'Szerver hiba' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Hiányzó adatok' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Hibás email vagy jelszó' });
  const payload = { id: user.id, name: user.name, email: user.email };
  const token   = jwt.sign(payload, SECRET, { expiresIn: '30d' });
  res.json({ user: payload, token });
});

app.get('/api/auth/me', auth, (req, res) => {
  const u = db.prepare('SELECT id, name, email, phone, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!u) return res.status(404).json({ error: 'Felhasználó nem található' });
  res.json(u);
});

app.put('/api/auth/me', auth, (req, res) => {
  const { name, phone } = req.body || {};
  if (name && name.trim().length < 2) return res.status(400).json({ error: 'Érvénytelen név' });
  db.prepare('UPDATE users SET name = COALESCE(?, name), phone = COALESCE(?, phone) WHERE id = ?')
    .run(name ? name.trim() : null, phone !== undefined ? phone.trim() : null, req.user.id);
  const u = db.prepare('SELECT id, name, email, phone, created_at FROM users WHERE id = ?').get(req.user.id);
  res.json(u);
});

// ── LISTING ROUTES ────────────────────────────────────────
app.get('/api/listings', optAuth, (req, res) => {
  const { category, search, page = 1, sort = 'new', mine } = req.query;
  const limit  = 24;
  const offset = (Math.max(parseInt(page) || 1, 1) - 1) * limit;

  const where  = [];
  const params = [];

  if (mine && req.user) {
    where.push('l.user_id = ?'); params.push(req.user.id);
  } else {
    where.push("l.status = 'active'");
    if (category) { where.push('l.category = ?'); params.push(category); }
    if (search) {
      where.push('(l.title LIKE ? OR l.description LIKE ? OR l.location LIKE ?)');
      const q = `%${search}%`;
      params.push(q, q, q);
    }
  }

  const W = where.join(' AND ');
  const ORDER = {
    new:        'l.created_at DESC',
    old:        'l.created_at ASC',
    price_asc:  'l.price ASC',
    price_desc: 'l.price DESC',
    views:      'l.views DESC'
  }[sort] || 'l.created_at DESC';

  const total = db.prepare(`SELECT COUNT(*) n FROM listings l WHERE ${W}`).get(...params).n;
  const rows  = db.prepare(
    `SELECT l.*, u.name seller_name FROM listings l
     JOIN users u ON l.user_id = u.id
     WHERE ${W} ORDER BY ${ORDER} LIMIT ? OFFSET ?`
  ).all(...params, limit, offset);

  res.json({
    listings: rows.map(r => fmt(r, req.user)),
    total, page: parseInt(page) || 1,
    pages: Math.ceil(total / limit)
  });
});

app.get('/api/listings/:id', optAuth, (req, res) => {
  const row = db.prepare(
    `SELECT l.*, u.name seller_name, u.phone seller_phone, u.email seller_email
     FROM listings l JOIN users u ON l.user_id = u.id WHERE l.id = ?`
  ).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Hirdetés nem található' });
  db.prepare('UPDATE listings SET views = views + 1 WHERE id = ?').run(req.params.id);
  row.views += 1;
  const result = fmt(row, req.user);
  // Only reveal contact info if authenticated
  if (!req.user) { delete result.seller_phone; delete result.seller_email; }
  res.json(result);
});

app.post('/api/listings', auth, upload.array('images', 6), (req, res) => {
  const { title, description, price, category, location } = req.body || {};
  if (!title || !title.trim())    return res.status(400).json({ error: 'A cím kötelező' });
  if (!category)                  return res.status(400).json({ error: 'A kategória kötelező' });
  if (title.trim().length > 120)  return res.status(400).json({ error: 'A cím max 120 karakter' });

  const images = (req.files || []).map(f => '/uploads/' + f.filename);
  const r = db.prepare(
    'INSERT INTO listings (user_id, title, description, price, category, location, images) VALUES (?,?,?,?,?,?,?)'
  ).run(
    req.user.id, title.trim(), (description || '').trim(),
    Math.max(parseInt(price) || 0, 0), category,
    (location || '').trim(), JSON.stringify(images)
  );
  const listing = db.prepare(
    'SELECT l.*, u.name seller_name FROM listings l JOIN users u ON l.user_id = u.id WHERE l.id = ?'
  ).get(r.lastInsertRowid);
  res.status(201).json(fmt(listing, req.user));
});

app.put('/api/listings/:id', auth, upload.array('images', 6), (req, res) => {
  const existing = db.prepare('SELECT * FROM listings WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!existing) return res.status(404).json({ error: 'Hirdetés nem található' });

  const { title, description, price, category, location, keep_images } = req.body || {};
  let images = JSON.parse(existing.images || '[]');

  // Keep only explicitly kept images
  if (keep_images !== undefined) {
    const keep = Array.isArray(keep_images) ? keep_images : [keep_images];
    const toDelete = images.filter(i => !keep.includes(i));
    toDelete.forEach(img => {
      const file = path.join(__dirname, 'public', img);
      if (fs.existsSync(file)) fs.unlinkSync(file);
    });
    images = keep;
  }
  const newImgs = (req.files || []).map(f => '/uploads/' + f.filename);
  images = [...images, ...newImgs].slice(0, 6);

  db.prepare(
    `UPDATE listings SET title=COALESCE(?,title), description=COALESCE(?,description),
     price=COALESCE(?,price), category=COALESCE(?,category),
     location=COALESCE(?,location), images=? WHERE id=?`
  ).run(
    title ? title.trim() : null,
    description !== undefined ? description.trim() : null,
    price !== undefined ? Math.max(parseInt(price) || 0, 0) : null,
    category || null, location ? location.trim() : null,
    JSON.stringify(images), req.params.id
  );

  const listing = db.prepare(
    'SELECT l.*, u.name seller_name FROM listings l JOIN users u ON l.user_id = u.id WHERE l.id = ?'
  ).get(req.params.id);
  res.json(fmt(listing, req.user));
});

app.delete('/api/listings/:id', auth, (req, res) => {
  const listing = db.prepare('SELECT * FROM listings WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!listing) return res.status(404).json({ error: 'Hirdetés nem található' });
  JSON.parse(listing.images || '[]').forEach(img => {
    const file = path.join(__dirname, 'public', img);
    if (fs.existsSync(file)) try { fs.unlinkSync(file); } catch {}
  });
  db.prepare('DELETE FROM listings WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ── MESSAGES ──────────────────────────────────────────────
app.post('/api/listings/:id/message', (req, res) => {
  const { sender_name, sender_email, message } = req.body || {};
  if (!sender_name || !sender_email || !message) return res.status(400).json({ error: 'Minden mező kitöltése kötelező' });
  if (!isEmail(sender_email)) return res.status(400).json({ error: 'Érvénytelen email cím' });
  if (message.trim().length < 5) return res.status(400).json({ error: 'Az üzenet legalább 5 karakter' });
  const listing = db.prepare('SELECT id FROM listings WHERE id = ?').get(req.params.id);
  if (!listing) return res.status(404).json({ error: 'Hirdetés nem található' });
  db.prepare(
    'INSERT INTO messages (listing_id, sender_name, sender_email, message) VALUES (?,?,?,?)'
  ).run(req.params.id, sender_name.trim(), sender_email.trim().toLowerCase(), message.trim());
  res.json({ ok: true });
});

app.get('/api/listings/:id/messages', auth, (req, res) => {
  const listing = db.prepare('SELECT id, user_id FROM listings WHERE id = ?').get(req.params.id);
  if (!listing) return res.status(404).json({ error: 'Hirdetés nem található' });
  if (listing.user_id !== req.user.id) return res.status(403).json({ error: 'Nincs jogosultság' });
  const msgs = db.prepare('SELECT * FROM messages WHERE listing_id = ? ORDER BY created_at DESC').all(req.params.id);
  db.prepare("UPDATE messages SET read=1 WHERE listing_id=?").run(req.params.id);
  res.json(msgs);
});

// ── STATS (for admin/testing) ──────────────────────────────
app.get('/api/stats', (req, res) => {
  res.json({
    users:    db.prepare('SELECT COUNT(*) n FROM users').get().n,
    listings: db.prepare("SELECT COUNT(*) n FROM listings WHERE status='active'").get().n,
    messages: db.prepare('SELECT COUNT(*) n FROM messages').get().n,
  });
});

// ── 404 fallback for SPA ──────────────────────────────────
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── START ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  🦌 Vadász Apró fut: http://localhost:${PORT}\n`);
});
