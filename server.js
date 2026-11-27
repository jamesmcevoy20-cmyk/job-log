const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const PDFDocument = require('pdfkit');
const archiver = require('archiver');

const PORT = process.env.PORT || 3000;
let DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
try { fs.mkdirSync(path.join(DATA_DIR, 'photos'), { recursive: true }); }
catch (e) {
  console.warn('WARNING: cannot write to', DATA_DIR, '- no disk attached? Using temporary storage; data will be lost on redeploy.');
  DATA_DIR = path.join(__dirname, 'data');
  fs.mkdirSync(path.join(DATA_DIR, 'photos'), { recursive: true });
}
const PHOTO_DIR = path.join(DATA_DIR, 'photos');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
fs.mkdirSync(BACKUP_DIR, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'jobs.json');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const PASSWORD = process.env.APP_PASSWORD || '';

// ---------- storage ----------
function readJson(file, fallback) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return fallback; } }
let jobs = readJson(DB_FILE, []);
let settings = Object.assign({ businessName: process.env.BUSINESS_NAME || 'Job Log', phone: '', email: '', address: '', footer: '' }, readJson(SETTINGS_FILE, {}));
// upgrade older jobs
jobs.forEach(j => {
  j.photoMeta = j.photoMeta || {};
  j.history = j.history && j.history.length ? j.history : [{ status: j.status || 'Quote', at: j.created || Date.now() }];
});

let writing = Promise.resolve();
function writeAtomic(file, text) {
  writing = writing.then(() => new Promise(res => {
    const tmp = file + '.tmp';
    fs.writeFile(tmp, text, err => {
      if (err) { console.error('save failed', err); return res(); }
      fs.rename(tmp, file, () => res());
    });
  }));
  return writing;
}
const save = () => writeAtomic(DB_FILE, JSON.stringify(jobs));
const saveSettings = () => writeAtomic(SETTINGS_FILE, JSON.stringify(settings));

const id = () => crypto.randomBytes(8).toString('hex');
const str = (v, n = 2000) => String(v == null ? '' : v).slice(0, n);
const STATUSES = ['Quote', 'Booked', 'In progress', 'Done', 'Invoiced'];
const LABELS = ['', 'Before', 'During', 'After'];

// ---------- automatic daily backup of the data file ----------
function snapshot() {
  try {
    const day = new Date().toISOString().slice(0, 10);
    const f = path.join(BACKUP_DIR, 'jobs-' + day + '.json');
    if (!fs.existsSync(f)) {
      fs.writeFileSync(f, JSON.stringify({ jobs, settings }));
      const all = fs.readdirSync(BACKUP_DIR).filter(n => /^jobs-\d{4}-\d{2}-\d{2}\.json$/.test(n)).sort();
      all.slice(0, Math.max(0, all.length - 14)).forEach(n => fs.unlink(path.join(BACKUP_DIR, n), () => {}));
    }
  } catch (e) { console.error('snapshot failed', e.message); }
}
setTimeout(snapshot, 5000);
setInterval(snapshot, 6 * 3600 * 1000).unref();

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.get('/health', (req, res) => res.send('ok'));

// ---------- login (cookie session) ----------
const SECRET = crypto.createHash('sha256').update('job-log|' + PASSWORD).digest();
const COOKIE = 'jl_session';
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
function makeToken() { const exp = String(Date.now() + 30 * 86400 * 1000); return exp + '.' + sign(exp); }
function validToken(t) {
  if (!t) return false;
  const [exp, sig] = t.split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const a = Buffer.from(sig), b = Buffer.from(sign(exp));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function getCookie(req, name) {
  const m = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : '';
}
const attempts = new Map(); // ip -> {n, t}
function loginPage(error) {
  const name = String(settings.businessName || 'Job Log').replace(/[<>&"]/g, '');
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#1d6fd6"><link rel="manifest" href="/manifest.webmanifest"><link rel="apple-touch-icon" href="/apple-touch-icon.png"><title>${name} – Sign in</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f6f8;font:16px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1c2430}
form{background:#fff;border:1px solid #e2e6ec;border-radius:16px;padding:28px 24px;width:min(360px,92vw);text-align:center;box-shadow:0 6px 24px rgba(20,40,80,.07)}
img{width:72px;height:72px;border-radius:16px}h1{font-size:21px;margin:12px 0 4px}p{color:#6b7685;margin:0 0 18px;font-size:14px}
input{width:100%;font:inherit;padding:12px;border:1px solid #e2e6ec;border-radius:10px;margin-bottom:12px}
button{width:100%;font:inherit;font-weight:600;padding:12px;border:0;border-radius:10px;background:#1d6fd6;color:#fff;cursor:pointer}
.e{color:#c93b3b;font-size:14px;margin-bottom:10px}</style></head><body>
<form method="post" action="/login"><img src="/icon-192.png" alt=""><h1>${name}</h1><p>Sign in to continue</p>
${error ? '<div class="e">' + error + '</div>' : ''}
<input type="password" name="password" placeholder="Password" autocomplete="current-password" autofocus required><button>Sign in</button></form></body></html>`;
}
const PUBLIC_FILES = new Set(['/manifest.webmanifest', '/sw.js', '/icon-192.png', '/icon-512.png', '/icon-maskable-512.png', '/apple-touch-icon.png', '/login']);
app.post('/login', express.urlencoded({ extended: false, limit: '4kb' }), (req, res) => {
  if (!PASSWORD) return res.redirect('/');
  const ip = req.ip, now = Date.now();
  const a = attempts.get(ip) || { n: 0, t: now };
  if (now - a.t > 15 * 60 * 1000) { a.n = 0; a.t = now; }
  if (a.n >= 10) return res.status(429).send(loginPage('Too many attempts. Try again in 15 minutes.'));
  const given = Buffer.from(String(req.body.password || '')), want = Buffer.from(PASSWORD);
  if (given.length === want.length && crypto.timingSafeEqual(given, want)) {
    attempts.delete(ip);
    res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(makeToken())}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${30 * 86400}${req.secure ? '; Secure' : ''}`);
    return res.redirect('/');
  }
  a.n++; attempts.set(ip, a);
  res.status(401).send(loginPage('Wrong password'));
});
app.get('/login', (req, res) => res.send(loginPage('')));
app.get('/logout', (req, res) => {
  res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
  res.redirect('/login');
});
// ---------- intake from other sites (e.g. DIY Guy bookings) ----------
// Needs INTAKE_KEY set here and the same key on the sending site. Without it the endpoint is off.
const INTAKE_KEY = process.env.INTAKE_KEY || '';
app.post('/api/intake', express.json({ limit: '100kb' }), (req, res) => {
  if (!INTAKE_KEY) return res.status(404).json({ error: 'Not found' });
  const given = Buffer.from(String(req.get('x-intake-key') || '')), want = Buffer.from(INTAKE_KEY);
  if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) return res.status(401).json({ error: 'Bad key' });
  const b = req.body || {};
  const customer = str(b.customer, 200).trim();
  if (!customer) return res.status(400).json({ error: 'Customer name required' });
  const ref = str(b.ref, 60).trim();
  if (ref) { const dup = jobs.find(j => j.sourceRef === ref); if (dup) return res.json({ ok: true, id: dup.id, duplicate: true }); }
  const status = STATUSES.includes(b.status) ? b.status : 'Booked';
  const j = {
    customer,
    phone: str(b.phone, 60).trim(),
    email: str(b.email, 200).trim(),
    address: str(b.address, 500).trim(),
    title: str(b.title, 200).trim(),
    notes: str(b.notes, 5000).trim(),
    status,
    date: /^\d{4}-\d{2}-\d{2}$/.test(b.date || '') ? b.date : new Date().toISOString().slice(0, 10),
    photos: [], photoMeta: {},
    history: [{ status, at: Date.now() }],
    created: Date.now(),
    source: str(b.source, 60).trim(),
    sourceRef: ref,
    id: id()
  };
  jobs.unshift(j);
  save().then(() => res.status(201).json({ ok: true, id: j.id }));
});

app.use((req, res, next) => {
  if (!PASSWORD || PUBLIC_FILES.has(req.path)) return next();
  if (validToken(getCookie(req, COOKIE))) return next();
  if (req.path.startsWith('/api/') || req.path.startsWith('/photos/')) return res.status(401).json({ error: 'Please sign in again' });
  res.redirect('/login');
});

app.use(express.json({ limit: '1mb' }));

const IMG_EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/heic': '.heic', 'image/heif': '.heif' };
const upload = multer({
  storage: multer.diskStorage({
    destination: PHOTO_DIR,
    filename: (req, file, cb) => cb(null, id() + (IMG_EXT[file.mimetype] || '.jpg'))
  }),
  limits: { fileSize: 25 * 1024 * 1024, files: 20 },
  fileFilter: (req, file, cb) => cb(null, /^image\//.test(file.mimetype))
});
const logoUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 3 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => cb(null, /^image\/(png|jpeg)$/.test(file.mimetype))
});

function clean(body, old) {
  const first = !old;
  old = old || {};
  const status = STATUSES.includes(body.status) ? body.status : (old.status || 'Quote');
  const history = (old.history || []).slice();
  if (first || old.status !== status) history.push({ status, at: Date.now() });
  return {
    customer: str(body.customer, 200).trim(),
    phone: str(body.phone, 60).trim(),
    email: str(body.email, 200).trim(),
    address: str(body.address, 500).trim(),
    title: str(body.title, 200).trim(),
    notes: str(body.notes, 5000).trim(),
    status,
    date: /^\d{4}-\d{2}-\d{2}$/.test(body.date || '') ? body.date : (old.date || new Date().toISOString().slice(0, 10)),
    photos: old.photos || [],
    photoMeta: old.photoMeta || {},
    history,
    created: old.created || Date.now()
  };
}

app.get('/api/jobs', (req, res) => res.json(jobs));

app.post('/api/jobs', (req, res) => {
  const j = clean(req.body || {});
  if (!j.customer) return res.status(400).json({ error: 'Customer name required' });
  j.id = id();
  jobs.unshift(j);
  save().then(() => res.json(j));
});

app.put('/api/jobs/:id', (req, res) => {
  const i = jobs.findIndex(j => j.id === req.params.id);
  if (i < 0) return res.status(404).json({ error: 'Not found' });
  const j = clean(req.body || {}, jobs[i]);
  if (!j.customer) return res.status(400).json({ error: 'Customer name required' });
  j.id = jobs[i].id;
  jobs[i] = j;
  save().then(() => res.json(j));
});

app.patch('/api/jobs/:id/status', (req, res) => {
  const j = jobs.find(x => x.id === req.params.id);
  if (!j) return res.status(404).json({ error: 'Not found' });
  const s = (req.body || {}).status;
  if (!STATUSES.includes(s)) return res.status(400).json({ error: 'Bad status' });
  if (j.status !== s) { j.status = s; j.history.push({ status: s, at: Date.now() }); }
  save().then(() => res.json(j));
});

function removeFile(name) {
  if (!/^[a-f0-9]+\.\w+$/.test(name)) return;
  fs.unlink(path.join(PHOTO_DIR, name), () => {});
}

app.delete('/api/jobs/:id', (req, res) => {
  const i = jobs.findIndex(j => j.id === req.params.id);
  if (i < 0) return res.status(404).json({ error: 'Not found' });
  jobs[i].photos.forEach(removeFile);
  jobs.splice(i, 1);
  save().then(() => res.json({ ok: true }));
});

const asArray = v => v == null ? [] : Array.isArray(v) ? v : [v];
app.post('/api/jobs/:id/photos', upload.array('photos', 20), (req, res) => {
  const j = jobs.find(x => x.id === req.params.id);
  if (!j) { (req.files || []).forEach(f => removeFile(f.filename)); return res.status(404).json({ error: 'Not found' }); }
  const labels = asArray(req.body && req.body.labels), times = asArray(req.body && req.body.times);
  (req.files || []).forEach((f, i) => {
    j.photos.push(f.filename);
    let t = Number(times[i]);
    if (!(t > Date.now() - 10 * 365 * 86400000 && t <= Date.now() + 86400000)) t = Date.now();
    j.photoMeta[f.filename] = { label: LABELS.includes(labels[i]) ? labels[i] : '', at: t };
  });
  save().then(() => res.json(j));
});

app.patch('/api/jobs/:id/photos/:file', (req, res) => {
  const j = jobs.find(x => x.id === req.params.id);
  if (!j || !j.photos.includes(req.params.file)) return res.status(404).json({ error: 'Not found' });
  const label = (req.body || {}).label;
  if (!LABELS.includes(label)) return res.status(400).json({ error: 'Bad label' });
  j.photoMeta[req.params.file] = Object.assign({ at: j.created }, j.photoMeta[req.params.file], { label });
  save().then(() => res.json(j));
});

app.delete('/api/jobs/:id/photos/:file', (req, res) => {
  const j = jobs.find(x => x.id === req.params.id);
  if (!j) return res.status(404).json({ error: 'Not found' });
  j.photos = j.photos.filter(p => p !== req.params.file);
  delete j.photoMeta[req.params.file];
  removeFile(req.params.file);
  save().then(() => res.json(j));
});

app.get('/photos/:file', (req, res) => {
  if (!/^[a-f0-9]+\.\w+$/.test(req.params.file)) return res.status(400).end();
  res.set('Cache-Control', 'private, max-age=86400');
  res.sendFile(path.join(PHOTO_DIR, req.params.file), err => { if (err && !res.headersSent) res.status(404).end(); });
});

// ---------- settings + logo ----------
const findLogo = () => ['logo.png', 'logo.jpg'].map(n => path.join(DATA_DIR, n)).find(f => fs.existsSync(f));
app.get('/api/settings', (req, res) => res.json(Object.assign({}, settings, { hasLogo: !!findLogo() })));
app.put('/api/settings', (req, res) => {
  const b = req.body || {};
  settings = {
    businessName: str(b.businessName, 100).trim() || 'Job Log',
    phone: str(b.phone, 60).trim(), email: str(b.email, 200).trim(),
    address: str(b.address, 300).trim(), footer: str(b.footer, 300).trim()
  };
  saveSettings().then(() => res.json(Object.assign({}, settings, { hasLogo: !!findLogo() })));
});
app.post('/api/settings/logo', logoUpload.single('logo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Choose a PNG or JPG image' });
  ['logo.png', 'logo.jpg'].forEach(n => fs.rmSync(path.join(DATA_DIR, n), { force: true }));
  fs.writeFileSync(path.join(DATA_DIR, req.file.mimetype === 'image/png' ? 'logo.png' : 'logo.jpg'), req.file.buffer);
  res.json({ ok: true });
});
app.delete('/api/settings/logo', (req, res) => {
  ['logo.png', 'logo.jpg'].forEach(n => fs.rmSync(path.join(DATA_DIR, n), { force: true }));
  res.json({ ok: true });
});
const DEFAULT_LOGO = path.join(__dirname, 'public', 'icon-512.png');
app.get('/logo', (req, res) => {
  const f = findLogo() || DEFAULT_LOGO;
  res.set('Cache-Control', 'no-cache');
  res.sendFile(f);
});

// ---------- backup / export ----------
app.get('/api/backup.zip', (req, res) => {
  const day = new Date().toISOString().slice(0, 10);
  res.set({ 'Content-Type': 'application/zip', 'Content-Disposition': `attachment; filename="job-log-backup-${day}.zip"` });
  const zip = archiver('zip', { zlib: { level: 1 } });
  zip.on('error', e => { console.error('zip error', e); res.destroy(); });
  zip.pipe(res);
  zip.append(JSON.stringify({ jobs, settings }, null, 2), { name: 'jobs.json' });
  zip.directory(PHOTO_DIR, 'photos');
  const logo = findLogo();
  if (logo) zip.file(logo, { name: path.basename(logo) });
  zip.finalize();
});

app.get('/api/export.csv', (req, res) => {
  const cell = v => {
    let s = String(v == null ? '' : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  };
  const head = ['Date', 'Customer', 'Phone', 'Email', 'Address', 'Job', 'Status', 'Notes', 'Photos'];
  const rows = jobs.map(j => [j.date, j.customer, j.phone, j.email, j.address, j.title, j.status, j.notes, j.photos.length].map(cell).join(','));
  res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="job-log-export.csv"' });
  res.send('﻿' + [head.map(cell).join(','), ...rows].join('\r\n'));
});

// ---------- PDF job report ----------
const fmtDate = d => { try { return new Date(d).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }); } catch (e) { return ''; } };
const fmtDateTime = t => { try { return new Date(t).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'Europe/London' }); } catch (e) { return ''; } };

app.get('/api/jobs/:id/report.pdf', (req, res) => {
  const j = jobs.find(x => x.id === req.params.id);
  if (!j) return res.status(404).json({ error: 'Not found' });
  const safe = (j.customer + ' ' + (j.title || '')).replace(/[^\w\- ]+/g, '').trim().replace(/\s+/g, '-').slice(0, 60) || 'job';
  res.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': `inline; filename="Job-Report-${safe}.pdf"` });
  const doc = new PDFDocument({ size: 'A4', margin: 40, bufferPages: true, info: { Title: 'Job report - ' + j.customer, Author: settings.businessName } });
  doc.on('error', e => { console.error('pdf error', e); res.destroy(); });
  doc.pipe(res);
  const W = doc.page.width - 80, INK = '#1c2430', MUTE = '#6b7685', ACC = '#1d6fd6';

  // letterhead
  let textX = 40;
  const logo = findLogo() || DEFAULT_LOGO;
  if (logo) { try { doc.image(logo, 40, 40, { fit: [56, 56] }); textX = 110; } catch (e) { /* ignore bad logo */ } }
  doc.font('Helvetica-Bold').fontSize(19).fillColor(INK).text(settings.businessName || 'Job Log', textX, 40, { width: 555 - textX });
  const contact = [settings.phone, settings.email, settings.address].filter(Boolean).join('  ·  ');
  if (contact) doc.font('Helvetica').fontSize(9).fillColor(MUTE).text(contact, textX, doc.y + 2, { width: 555 - textX });
  const lineY = Math.max(doc.y, logo ? 100 : 0) + 10;
  doc.moveTo(40, lineY).lineTo(555, lineY).lineWidth(2).strokeColor(ACC).stroke();
  doc.y = lineY + 16;

  doc.font('Helvetica-Bold').fontSize(10).fillColor(ACC).text('JOB REPORT', 40, doc.y);
  doc.font('Helvetica-Bold').fontSize(16).fillColor(INK).text(j.title || j.customer, 40, doc.y + 2, { width: W });
  doc.moveDown(0.6);

  const row = (k, v) => {
    if (!v) return;
    const y0 = doc.y;
    doc.font('Helvetica-Bold').fontSize(8.5).fillColor(MUTE).text(k.toUpperCase(), 40, y0 + 2, { width: 100 });
    doc.font('Helvetica').fontSize(11).fillColor(INK).text(String(v), 145, y0, { width: W - 105 });
    doc.y = Math.max(doc.y, y0 + 14) + 4;
  };
  row('Date', j.date ? fmtDate(j.date + 'T00:00:00') : '');
  row('Customer', j.customer);
  row('Address', j.address);
  row('Phone', j.phone);
  row('Email', j.email);
  row('Status', j.status);
  row('Notes', j.notes);

  if (j.history && j.history.length > 1) {
    doc.moveDown(0.5);
    doc.font('Helvetica-Bold').fontSize(10).fillColor(ACC).text('PROGRESS', 40);
    doc.moveDown(0.2);
    j.history.forEach(h => {
      doc.font('Helvetica').fontSize(10).fillColor(INK).text(`${h.status}  –  ${fmtDateTime(h.at)}`, 40, doc.y, { width: W });
    });
  }

  // photos grouped Before / During / After / Other
  const groups = [['Before', []], ['During', []], ['After', []], ['Photos', []]];
  j.photos.forEach(f => {
    const m = j.photoMeta[f] || {};
    const g = groups.find(x => x[0] === m.label) || groups[3];
    g[1].push({ f, at: m.at });
  });
  const cw = (W - 14) / 2, ch = 190, BOTTOM = doc.page.height - 70;
  groups.forEach(([name, list]) => {
    list = list.filter(p => /\.(jpe?g|png)$/i.test(p.f));
    if (!list.length) return;
    if (doc.y + 30 + ch > BOTTOM) doc.addPage();
    doc.moveDown(0.8);
    doc.font('Helvetica-Bold').fontSize(10).fillColor(ACC).text(name.toUpperCase(), 40, doc.y);
    let rowY = doc.y + 6, col = 0;
    list.forEach(p => {
      if (col === 0 && rowY + ch + 20 > BOTTOM) { doc.addPage(); rowY = 40; }
      const x = 40 + col * (cw + 14);
      try { doc.image(path.join(PHOTO_DIR, p.f), x, rowY, { fit: [cw, ch], align: 'center', valign: 'center' }); }
      catch (e) { return; }
      doc.font('Helvetica').fontSize(8).fillColor(MUTE).text((name === 'Photos' ? '' : name + ' · ') + (p.at ? fmtDateTime(p.at) : ''), x, rowY + ch + 4, { width: cw, lineBreak: false });
      col++;
      if (col === 2) { col = 0; rowY += ch + 22; }
    });
    if (col === 1) rowY += ch + 22;
    doc.y = rowY;
  });

  // footer on every page
  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i++) {
    doc.switchToPage(range.start + i);
    doc.page.margins.bottom = 0;
    doc.font('Helvetica').fontSize(8).fillColor(MUTE)
      .text([settings.footer, `Page ${i + 1} of ${range.count}`].filter(Boolean).join('   ·   '), 40, doc.page.height - 36, { width: W, align: 'center', lineBreak: false });
  }
  doc.end();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Server error' }); });
app.listen(PORT, () => console.log('Job Log on', PORT));
