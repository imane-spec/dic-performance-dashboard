/* POST /api/reset-password (rewritten by netlify.toml to
   /.netlify/functions/reset-password)
   Checks the submitted reset code, and if it matches, sets a new password
   and signs the person straight in (same as the old verify-otp behavior) —
   one less step than making them reset, then log in again separately. */

const {
  isAllowedEmail,
  normalizeEmail,
  isValidPassword,
  hashResetCode,
  hashPassword,
  safeEqual,
  signSession,
  serializeSessionCookie,
  RESET_CODE_MAX_ATTEMPTS,
  MIN_PASSWORD_LENGTH,
} = require('../../lib/auth');
const { getUser, setUser, getResetRecord, setResetRecord, deleteResetRecord } = require('../../lib/store');
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
  const code = String(parsedBody.code || '').trim();
  const newPassword = String(parsedBody.newPassword || '');

  if (!isAllowedEmail(email)) {
    return jsonResponse(403, { ok: false, error: 'That email domain is not authorized.' });
  }
  if (!/^\d{6}$/.test(code)) {
    return jsonResponse(400, { ok: false, error: 'Enter the 6-digit code from your email.' });
  }
  if (!isValidPassword(newPassword)) {
    return jsonResponse(400, { ok: false, error: 'Choose a password at least ' + MIN_PASSWORD_LENGTH + ' characters long.' });
  }

  const record = await getResetRecord(email);
  if (!record) {
    return jsonResponse(400, { ok: false, error: 'No active reset code for this email. Request a new one.' });
  }
  if (Date.now() > record.expiresAt) {
    await deleteResetRecord(email);
    return jsonResponse(400, { ok: false, error: 'That code has expired. Request a new one.' });
  }
  if ((record.attempts || 0) >= RESET_CODE_MAX_ATTEMPTS) {
    await deleteResetRecord(email);
    return jsonResponse(429, { ok: false, error: 'Too many incorrect attempts. Request a new code.' });
  }

  const matches = safeEqual(hashResetCode(email, code), record.hash);
  if (!matches) {
    await setResetRecord(email, Object.assign({}, record, { attempts: (record.attempts || 0) + 1 }));
    return jsonResponse(401, { ok: false, error: 'Incorrect code. Please try again.' });
  }

  const user = await getUser(email);
  if (!user) {
    // The account existed when the code was requested (request-password-reset
    // only emails one for a real account) but is gone now — an edge case,
    // not something a normal user flow should hit.
    await deleteResetRecord(email);
    return jsonResponse(400, { ok: false, error: 'That account no longer exists. Contact the DIC team.' });
  }

  const passwordHash = await hashPassword(newPassword);
  await setUser(email, Object.assign({}, user, {
    passwordHash: passwordHash,
    updatedAt: Date.now(),
    loginAttempts: [],
  }));
  await deleteResetRecord(email);

  const token = signSession(email);
  return jsonResponse(200, { ok: true, email: email }, { 'Set-Cookie': serializeSessionCookie(token) });
};
