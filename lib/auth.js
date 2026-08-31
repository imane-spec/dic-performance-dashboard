/* =============================================================================
   lib/auth.js — shared login logic for the DIC Performance Dashboard
   ---------------------------------------------------------------------------
   Domain allow-list, password hashing/verification, password-reset-code
   generation/hashing, session token sign/verify, and cookie helpers.
   Everything here is plain Node.js (no framework dependency) so it works
   the same whether it's called from a Vercel-style /api function, a
   Netlify function, or a plain Express route.

   Accounts are email + password. Approved-domain users can create their own
   account through the public sign-up flow; the admin-create-user endpoint
   remains available for manual provisioning. The one-time-code MACHINERY
   below is used only for the "forgot password" flow, never for sign-in.
   ========================================================================= */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

/* ---- Configuration ------------------------------------------------------ */

// Only these three domains may hold an account. Match is exact
// (case-insensitive) on the part after "@" — "user@mcit.gov.qa" matches,
// "user@sub.mcit.gov.qa" or "user@fakemcit.gov.qa" do not. Add or remove
// domains here only. Enforced both when an account is created (see
// admin-create-user.js) and again at login/session time, so it stays a real
// restriction even if a store somehow ends up with an out-of-policy account.
const ALLOWED_DOMAINS = [
  'consultant.mcit.gov.qa',
  'mcit.gov.qa',
  'ibtechar.com',
];

const BCRYPT_ROUNDS = 12;
const MIN_PASSWORD_LENGTH = 8;

const RESET_CODE_LENGTH = 6;
const RESET_CODE_TTL_MS = 15 * 60 * 1000;     // a reset code is valid for 15 minutes
const RESET_CODE_MAX_ATTEMPTS = 5;            // wrong-code guesses allowed per code
const RESET_REQUEST_COOLDOWN_MS = 60 * 1000;  // min gap between two reset requests to the same email
const RESET_REQUEST_MAX_PER_HOUR = 5;         // max reset codes sent to the same email per hour

const LOGIN_MAX_ATTEMPTS = 8;                 // wrong-password guesses allowed per hour, per email
const LOGIN_ATTEMPT_WINDOW_MS = 60 * 60 * 1000;

const SESSION_TTL_SECONDS = 12 * 60 * 60; // 12 hours
const SESSION_COOKIE_NAME = 'dic_session';

function getSecret() {
  const secret = process.env.AUTH_SECRET || process.env.SESSION_SECRET;
  if (!secret || secret.length < 16) {
    throw new Error(
      'AUTH_SECRET or SESSION_SECRET is not set (or is too short). Set a long random string ' +
      'before deploying.'
    );
  }
  return secret;
}

function getAdminSecret() {
  const secret = process.env.ADMIN_SECRET;
  if (!secret || secret.length < 16) {
    throw new Error(
      'ADMIN_SECRET is not set (or is too short). Set a long random string as ' +
      'the ADMIN_SECRET environment variable before deploying — see .env.example. ' +
      'This is the shared secret you keep to yourself and use to create accounts ' +
      'via /api/admin-create-user; it is never shown to end users.'
    );
  }
  return secret;
}

/* Constant-time comparison of the caller-supplied admin secret against the
   real one, so the check can't be timing-attacked the way a plain === would
   allow — same reasoning as safeEqual() below, applied to a different value. */
function isValidAdminSecret(candidate) {
  try {
    const real = getAdminSecret();
    return safeEqual(String(candidate || ''), real);
  } catch (e) {
    return false;
  }
}

/* ---- Email / domain validation ------------------------------------------ */

function normalizeEmail(raw) {
  return String(raw || '').trim().toLowerCase();
}

function isAllowedEmail(rawEmail) {
  const email = normalizeEmail(rawEmail);
  const at = email.lastIndexOf('@');
  if (at < 1 || at === email.length - 1) return false;
  const domain = email.slice(at + 1);
  return ALLOWED_DOMAINS.indexOf(domain) >= 0;
}

function isValidPassword(pw) {
  return typeof pw === 'string' && pw.length >= MIN_PASSWORD_LENGTH && pw.length <= 200;
}

/* ---- Passwords -----------------------------------------------------------
   bcryptjs (pure JS, no native compile step) rather than the native
   `bcrypt` package — this matters for a serverless function bundle, where a
   native addon has to match the exact deployed OS/architecture and can
   silently fail to load. Only the hash is ever stored, never the password
   itself. ------------------------------------------------------------- */

async function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

async function verifyPassword(password, hash) {
  if (!hash) return false;
  return bcrypt.compare(password, hash);
}

/* ---- Password-reset codes -------------------------------------------------
   Same "never store the plaintext" pattern the old sign-in codes used: only
   a salted hash of the code is kept, so a leak of the store doesn't hand out
   a working reset code. -------------------------------------------------- */

function generateResetCode() {
  const n = crypto.randomInt(0, 10 ** RESET_CODE_LENGTH);
  return String(n).padStart(RESET_CODE_LENGTH, '0');
}

function hashResetCode(email, code) {
  return crypto
    .createHmac('sha256', getSecret())
    .update('reset:' + normalizeEmail(email) + ':' + code)
    .digest('hex');
}

function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/* ---- Session tokens (JWT in an httpOnly cookie) -------------------------- */

function signSession(email) {
  return jwt.sign({ email: normalizeEmail(email) }, getSecret(), {
    expiresIn: SESSION_TTL_SECONDS,
  });
}

function verifySession(token) {
  try {
    const payload = jwt.verify(token, getSecret());
    if (!isAllowedEmail(payload.email)) return null; // domain removed after issuance
    return payload;
  } catch (e) {
    return null;
  }
}

/* ---- Cookie helpers -------------------------------------------------------
   Framework-agnostic: build/parse the Cookie / Set-Cookie header text
   directly rather than depending on a request object shape, so the same
   helpers work under Vercel's (req, res), Netlify's (event, context), or a
   plain Node http.IncomingMessage/ServerResponse. ------------------------ */

function parseCookies(cookieHeader) {
  const out = {};
  String(cookieHeader || '').split(';').forEach(function (part) {
    const eq = part.indexOf('=');
    if (eq < 0) return;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

function serializeSessionCookie(token) {
  const isProd = process.env.NODE_ENV === 'production';
  const parts = [
    SESSION_COOKIE_NAME + '=' + encodeURIComponent(token),
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=' + SESSION_TTL_SECONDS,
  ];
  // Secure requires HTTPS, which is how Vercel/Netlify serve everything in
  // production; skip it for plain-http local dev so cookies still get set.
  if (isProd) parts.push('Secure');
  return parts.join('; ');
}

function serializeLogoutCookie() {
  const isProd = process.env.NODE_ENV === 'production';
  const parts = [
    SESSION_COOKIE_NAME + '=',
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
  ];
  if (isProd) parts.push('Secure');
  return parts.join('; ');
}

function getSessionFromRequest(req) {
  const cookies = parseCookies(req.headers && req.headers.cookie);
  const token = cookies[SESSION_COOKIE_NAME];
  if (!token) return null;
  return verifySession(token);
}

module.exports = {
  ALLOWED_DOMAINS,
  MIN_PASSWORD_LENGTH,
  RESET_CODE_TTL_MS,
  RESET_CODE_MAX_ATTEMPTS,
  RESET_REQUEST_COOLDOWN_MS,
  RESET_REQUEST_MAX_PER_HOUR,
  LOGIN_MAX_ATTEMPTS,
  LOGIN_ATTEMPT_WINDOW_MS,
  SESSION_TTL_SECONDS,
  SESSION_COOKIE_NAME,
  normalizeEmail,
  isAllowedEmail,
  isValidPassword,
  isValidAdminSecret,
  hashPassword,
  verifyPassword,
  generateResetCode,
  hashResetCode,
  safeEqual,
  signSession,
  verifySession,
  parseCookies,
  serializeSessionCookie,
  serializeLogoutCookie,
  getSessionFromRequest,
};
