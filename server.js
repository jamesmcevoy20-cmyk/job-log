const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
let DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
try { fs.mkdirSync(path.join(DATA_DIR, 'photos'), { recursive: true }); }
catch (e) {
  console.warn('WARNING: cannot write to', DATA_DIR, '- no disk attached? Using temporary storage; data will be lost on redeploy.');
  DATA_DIR = path.join(__dirname, 'data');
  fs.mkdirSync(path.join(DATA_DIR, 'photos'), { recursive: true });
}
const PHOTO_DIR = path.join(DATA_DIR, 'photos');
const DB_FILE = path.join(DATA_DIR, 'jobs.json');
const PASSWORD = process.env.APP_PASSWORD || '';

let jobs = [];
try { jobs = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { jobs = []; }
let writing = Promise.resolve();
function save() {
  const snapshot = JSON.stringify(jobs);
  writing = writing.then(() => new Promise(res => {
    const tmp = DB_FILE + '.tmp';
    fs.writeFile(tmp, snapshot, err => {
      if (err) { console.error('save failed', err); return res(); }
      fs.rename(tmp, DB_FILE, () => res());
    });
  }));
  return writing;
}
const id = () => crypto.randomBytes(8).toString('hex');
const str = (v, n = 2000) => String(v == null ? '' : v).slice(0, n);
const STATUSES = ['Quote', 'Booked', 'In progress', 'Done', 'Invoiced'];

const app = express();
app.disable('x-powered-by');
app.get('/health', (req, res) => res.send('ok'));

// Password protection (HTTP basic auth). Customer details are private.
// Only the home-screen install files are left open: they contain no customer data.
const PUBLIC_FILES = new Set(['/manifest.webmanifest', '/sw.js', '/icon-192.png', '/icon-512.png', '/icon-maskable-512.png', '/apple-touch-icon.png']);
app.use((req, res, next) => {
  if (!PASSWORD) return next();
  if (PUBLIC_FILES.has(req.path)) return next();
  const h = req.headers.authorization || '';
  if (h.startsWith('Basic ')) {
    const given = Buffer.from(h.slice(6), 'base64').toString();
    const pw = given.slice(given.indexOf(':') + 1);
    const a = Buffer.from(pw), b = Buffer.from(PASSWORD);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="Job Log"').status(401).send('Password required');
});

app.use(express.json({ limit: '1mb' }));

const upload = multer({
  storage: multer.diskStorage({
    destination: PHOTO_DIR,
    filename: (req, file, cb) => {
      const ext = ({ 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/heic': '.heic', 'image/heif': '.heif' })[file.mimetype] || '.jpg';
      cb(null, id() + ext);
    }
  }),
  limits: { fileSize: 25 * 1024 * 1024, files: 20 },
  fileFilter: (req, file, cb) => cb(null, /^image\//.test(file.mimetype))
});

function clean(body, old = {}) {
  return {
    customer: str(body.customer, 200).trim(),
    phone: str(body.phone, 60).trim(),
    email: str(body.email, 200).trim(),
    address: str(body.address, 500).trim(),
    title: str(body.title, 200).trim(),
    notes: str(body.notes, 5000).trim(),
    status: STATUSES.includes(body.status) ? body.status : 'Quote',
    date: /^\d{4}-\d{2}-\d{2}$/.test(body.date || '') ? body.date : new Date().toISOString().slice(0, 10),
    photos: old.photos || [],
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

app.post('/api/jobs/:id/photos', upload.array('photos', 20), (req, res) => {
  const j = jobs.find(x => x.id === req.params.id);
  if (!j) { (req.files || []).forEach(f => removeFile(f.filename)); return res.status(404).json({ error: 'Not found' }); }
  (req.files || []).forEach(f => j.photos.push(f.filename));
  save().then(() => res.json(j));
});

app.delete('/api/jobs/:id/photos/:file', (req, res) => {
  const j = jobs.find(x => x.id === req.params.id);
  if (!j) return res.status(404).json({ error: 'Not found' });
  j.photos = j.photos.filter(p => p !== req.params.file);
  removeFile(req.params.file);
  save().then(() => res.json(j));
});

app.get('/photos/:file', (req, res) => {
  if (!/^[a-f0-9]+\.\w+$/.test(req.params.file)) return res.status(400).end();
  res.set('Cache-Control', 'private, max-age=86400');
  res.sendFile(path.join(PHOTO_DIR, req.params.file), err => { if (err && !res.headersSent) res.status(404).end(); });
});

app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Server error' }); });
app.listen(PORT, () => console.log('Job Log on', PORT));
