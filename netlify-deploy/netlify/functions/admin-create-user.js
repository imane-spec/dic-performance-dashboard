/* POST /api/admin-create-user (rewritten by netlify.toml to
   /.netlify/functions/admin-create-user)
   ---------------------------------------------------------------------------
   How an administrator manually creates (or resets) an account. Public
   approved-domain users can also create their own account through /api/signup.
   Call this endpoint with the shared ADMIN_SECRET in a header; it never asks
   the end user for anything, and end users never see it.

   Calling it again for an email that already has an account overwrites that
   account's password — handy for "I forgot my password and don't want to
   wait for the email flow," not just for first-time creation. The response
   says which one happened (`created: true/false`) so a provisioning script
   can tell the two apart. */

const {
  isAllowedEmail,
  normalizeEmail,
  isValidPassword,
  isValidAdminSecret,
  hashPassword,
  MIN_PASSWORD_LENGTH,
} = require('../../lib/auth');
const { getUser, setUser } = require('../../lib/store');
const { jsonResponse } = require('../../lib/httpResponse');

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return jsonResponse(405, { ok: false, error: 'Method not allowed' });
  }

  const headers = event.headers || {};
  const providedSecret = headers['x-admin-secret'] || headers['X-Admin-Secret'];
  if (!isValidAdminSecret(providedSecret)) {
    // Deliberately generic — doesn't distinguish "missing" from "wrong" so
    // there's nothing for a guesser to learn from the response.
    return jsonResponse(401, { ok: false, error: 'Unauthorized.' });
  }

  let parsedBody = {};
  try {
    parsedBody = JSON.parse(event.body || '{}');
  } catch (e) {
    parsedBody = {};
  }
  const email = normalizeEmail(parsedBody.email);
  const password = String(parsedBody.password || '');

  if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(email)) {
    return jsonResponse(400, { ok: false, error: 'Enter a valid email address.' });
  }
  if (!isAllowedEmail(email)) {
    return jsonResponse(400, {
      ok: false,
      error: 'Only @consultant.mcit.gov.qa, @mcit.gov.qa, and @ibtechar.com addresses can have accounts.',
    });
  }
  if (!isValidPassword(password)) {
    return jsonResponse(400, { ok: false, error: 'Password must be at least ' + MIN_PASSWORD_LENGTH + ' characters.' });
  }

  const existing = await getUser(email);
  const passwordHash = await hashPassword(password);
  const now = Date.now();
  await setUser(email, {
    passwordHash: passwordHash,
    createdAt: existing ? existing.createdAt : now,
    updatedAt: now,
    loginAttempts: [],
  });

  return jsonResponse(200, { ok: true, email: email, created: !existing });
};
