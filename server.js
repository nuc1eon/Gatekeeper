const express = require('express');
const path = require('path');
const argon2 = require('argon2');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(cookieParser());

const HMAC_KEY = process.env.HMAC_KEY || 'dev-secret-change-me';
function sign(obj) {
  const payload = Buffer.from(JSON.stringify(obj)).toString('base64');
  const sig = crypto.createHmac('sha256', HMAC_KEY).update(payload).digest('base64');
  return `${payload}.${sig}`;
}
function verifyToken(token) {
  if (!token) return null;
  const [payloadB64, sig] = token.split('.');
  if (!payloadB64 || !sig) return null;
  const expected = crypto.createHmac('sha256', HMAC_KEY).update(payloadB64).digest('base64');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    return JSON.parse(Buffer.from(payloadB64, 'base64').toString());
  } catch { return null; }
}

// Load stored Argon2 hash (pin.hash) OR convert to it from pin.txt
const hashPath = path.join(__dirname, 'pin.hash');
const legacyPath = path.join(__dirname, 'pin.txt');

if (fs.existsSync(hashPath)) {
  const stored = fs.readFileSync(hashPath, 'utf8').trim();
  if (!stored) throw new Error('pin.hash exists but is empty');
  app.locals.storedHash = stored;
  console.log('Loaded PIN hash from pin.hash');
} else if (fs.existsSync(legacyPath)) {
  console.warn('pin.txt (plain text pin) detected. Converting to pin.hash...');
  const plain = fs.readFileSync(legacyPath, 'utf8').trim();
  (async () => {
    const hash = await argon2.hash(plain, { type: argon2.argon2id, timeCost: 2, memoryCost: 64 * 1024, parallelism: 1 });
    fs.writeFileSync(hashPath, hash + '\n', { mode: 0o600 });
    fs.chmodSync(hashPath, 0o600);
    try { fs.unlinkSync(legacyPath); console.log('Removed plain pin.txt'); } catch {}
    app.locals.storedHash = hash;
    console.log('Conversion complete: pin.hash written');
  })().catch((e) => { console.error('Conversion failed', e); process.exit(1); });
} else {
  console.error('No pin.hash found. Run `node set-pin.js` to create one.');
  process.exit(1);
}

app.post('/verify', async (req, res) => {
  const { pin } = req.body;
  if (!pin) return res.status(400).json({ ok: false, error: 'missing' });
  try {
    const ok = await argon2.verify(req.app.locals.storedHash, String(pin));
    if (!ok) return res.json({ ok: false });
    const tokenObj = { user: 'guest', iat: Date.now(), exp: Date.now() + 24 * 60 * 60 * 1000 };
    const token = sign(tokenObj);
    res.cookie('site_auth', token, { httpOnly: true, secure: false, sameSite: 'Lax', maxAge: 24 * 60 * 60 * 1000 });
    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false });
  }
});

function requireAuth(req, res, next) {
  const token = req.cookies.site_auth;
  const data = verifyToken(token);
  if (!data || data.exp < Date.now()) return res.redirect('/pin-challenge');
  req.user = data;
  next();
}

// Serve static assets (CSS, images) publicly
app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));

// Serve the pin challenge UI
app.get('/pin-challenge', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pin-challenge', 'index.html'));
});

// Protect root (the real site)
app.use('/', requireAuth, express.static(path.join(__dirname, 'protected')));

// Modify port number if desired
const PORT = process.env.PORT || 7125;
app.listen(PORT, () => console.log('Listening', PORT));
