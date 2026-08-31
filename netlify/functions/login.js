/* POST /api/login (rewritten by netlify.toml to /.netlify/functions/login)
   Checks the submitted email + password against the stored account. On
   success, issues a signed session token in an httpOnly cookie and the
   dashboard unlocks — same session mechanism the old one-time-code flow
   used, just a different way of proving who's asking. */

const {
  isAllowedEmail,
  normalizeEmail,
  verifyPassword,
  signSession,
  serializeSessionCookie,
  LOGIN_MAX_ATTEMPTS,
  LOGIN_ATTEMPT_WINDOW_MS,
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

  if (!email || !password) {
    return jsonResponse(400, { ok: false, error: 'Enter your email and password.' });
  }

  if (!isAllowedEmail(email)) {
    return jsonResponse(403, {
      ok: false,
      error: 'Only @consultant.mcit.gov.qa, @mcit.gov.qa, and @ibtechar.com addresses can sign in.',
    });
  }

  const user = await getUser(email);

  // Deliberately the same generic message whether the account doesn't exist
  // or the password is wrong — telling a stranger "no such account" would
  // hand out which emails have one.
  const genericError = { ok: false, error: 'Incorrect email or password.' };

  if (!user) {
    return jsonResponse(401, genericError);
  }

  const now = Date.now();
  const recentAttempts = Array.isArray(user.loginAttempts)
    ? user.loginAttempts.filter(function (t) { return now - t < LOGIN_ATTEMPT_WINDOW_MS; })
    : [];

  if (recentAttempts.length >= LOGIN_MAX_ATTEMPTS) {
    return jsonResponse(429, { ok: false, error: 'Too many incorrect attempts. Please try again in an hour, or reset your password.' });
  }

  const matches = await verifyPassword(password, user.passwordHash);
  if (!matches) {
    await setUser(email, Object.assign({}, user, { loginAttempts: recentAttempts.concat([now]) }));
    return jsonResponse(401, genericError);
  }

  if (recentAttempts.length) {
    await setUser(email, Object.assign({}, user, { loginAttempts: [] }));
  }

  const token = signSession(email);
  return jsonResponse(200, { ok: true, email: email }, { 'Set-Cookie': serializeSessionCookie(token) });
};
