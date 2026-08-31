/* POST /api/signup
   Creates a password account for an approved DIC organization email.
   Passwords are hashed before persistence; the plaintext password is never
   stored or returned. Sign-up intentionally does not create a session so the
   user completes the normal sign-in step afterward. */

const {
  isAllowedEmail,
  normalizeEmail,
  isValidPassword,
  hashPassword,
  MIN_PASSWORD_LENGTH,
} = require('../../lib/auth');
const { getUser, setUser } = require('../../lib/store');
const { jsonResponse } = require('../../lib/httpResponse');

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return jsonResponse(405, { ok: false, error: 'Method not allowed' });
  }

  let parsedBody = {};
  try {
    parsedBody = JSON.parse(event.body || '{}');
  } catch (e) {
    parsedBody = {};
  }

  const email = normalizeEmail(parsedBody.email);
  const password = String(parsedBody.password || '');
  const confirmPassword = String(parsedBody.confirmPassword || '');

  if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(email)) {
    return jsonResponse(400, { ok: false, error: 'Enter a valid email address.' });
  }
  if (!isAllowedEmail(email)) {
    return jsonResponse(403, {
      ok: false,
      error: 'Your email domain is not listed.',
    });
  }
  if (!isValidPassword(password)) {
    return jsonResponse(400, {
      ok: false,
      error: 'Password must be at least ' + MIN_PASSWORD_LENGTH + ' characters.',
    });
  }
  if (password !== confirmPassword) {
    return jsonResponse(400, { ok: false, error: 'Passwords do not match.' });
  }

  const existing = await getUser(email);
  if (existing) {
    return jsonResponse(409, {
      ok: false,
      error: 'An account with this email already exists. Sign in or reset your password.',
    });
  }

  const now = Date.now();
  await setUser(email, {
    passwordHash: await hashPassword(password),
    createdAt: now,
    updatedAt: now,
    loginAttempts: [],
  });

  return jsonResponse(201, { ok: true, email: email });
};