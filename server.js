const express = require('express');
const path = require('path');
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

// scrypt parameters (tune if desired)
const SCRYPT_N = parseInt(process.env.SCRYPT_N, 10) || 16384; // cost parameter (2^14)
const SCRYPT_r = parseInt(process.env.SCRYPT_r, 10) || 8;
const SCRYPT_p = parseInt(process.env.SCRYPT_p, 10) || 1;
const KEY_LEN = parseInt(process.env.SCRYPT_KEY_LEN, 10) || 32;
const SALT_LEN = parseInt(process.env.SCRYPT_SALT_LEN, 10) || 16;

function scryptDerive(password, salt) {
  // crypto.scryptSync accepts an options object for cost on modern Node versions:
  // { N, r, p } are provided as {cost: N, blockSize: r, parallelization: p} in older docs,
  // but Node's current signature supports {N, r, p} via scrypt derived from libsodium-like API.
  // Use the options object with maxmem if needed. Here we pass the params via options where supported.
  // For compatibility, pass { N: SCRYPT_N, r: SCRYPT_r, p: SCRYPT_p }.
  return crypto.scryptSync(password, salt, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_r, p: SCRYPT_p });
}

// Load stored scrypt-derived hash (pin.hash) OR convert to it from pin.txt
const hashPath = path.join(__dirname, 'pin.hash');
const legacyPath = path.join(__dirname, 'pin.txt');

if (fs.existsSync(hashPath)) {
  const stored = fs.readFileSync(hashPath, 'utf8').trim();
  if (!stored) throw new Error('pin.hash exists but is empty');
  app.locals.storedHash = stored;
  console.log('Loaded PIN hash from pin.hash');
} else if (fs.existsSync(legacyPath)) {
  console.warn('pin.txt (plain text pin) detected. Converting to pin.hash (scrypt)...');
  const plain = fs.readFileSync(legacyPath, 'utf8').trim();
  (async () => {
    try {
      const salt = crypto.randomBytes(SALT_LEN);
      const derived = scryptDerive(plain, salt);
      const hash = `${salt.toString('base64')}.${derived.toString('base64')}`;
      fs.writeFileSync(hashPath, hash + '\n', { mode: 0o600 });
      fs.chmodSync(hashPath, 0o600);
      try { fs.unlinkSync(legacyPath); console.log('Removed plain pin.txt'); } catch {}
      app.locals.storedHash = out;
      console.log('Conversion complete: pin.hash written (scrypt)');
    } catch (e) {
      console.error('Conversion failed', e);
      process.exit(1);
    }
  })();
} else {
  console.error('No pin.hash found. Run `node set-pin.js` to create one.');
  process.exit(1);
}

app.post('/verify', (req, res) => {
  const { pin } = req.body;
  if (!pin) return res.status(400).json({ ok: false, error: 'missing' });
  try {
    const stored = req.app.locals.storedHash;
    if (!stored) return res.status(500).json({ ok: false });
    const [saltB64, derivedB64] = stored.split('.');
    if (!saltB64 || !derivedB64) return res.status(500).json({ ok: false });
    const salt = Buffer.from(saltB64, 'base64');
    const derivedStored = Buffer.from(derivedB64, 'base64');
    const derivedTry = scryptDerive(String(pin), salt);
    if (!crypto.timingSafeEqual(derivedStored, derivedTry)) return res.json({ ok: false });

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
