/* POST /api/request-password-reset (rewritten by netlify.toml to
   /.netlify/functions/request-password-reset)
   Emails a reset code IF an account exists for the given address — but
   always responds with the same generic success message either way, so a
   stranger can't use this endpoint to find out which emails have accounts.
   Rate-limited the same way the old sign-in codes were. */

const {
  isAllowedEmail,
  normalizeEmail,
  generateResetCode,
  hashResetCode,
  RESET_CODE_TTL_MS,
  RESET_REQUEST_COOLDOWN_MS,
  RESET_REQUEST_MAX_PER_HOUR,
} = require('../../lib/auth');
const { getUser, getResetRecord, setResetRecord } = require('../../lib/store');
const { sendPasswordResetEmail } = require('../../lib/mail');
const { jsonResponse } = require('../../lib/httpResponse');

const GENERIC_MESSAGE = 'If an account exists for that address, a password reset code has been sent to it.';

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

  if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(email)) {
    return jsonResponse(400, { ok: false, error: 'Enter a valid email address.' });
  }

  if (!isAllowedEmail(email)) {
    return jsonResponse(403, {
      ok: false,
      error: 'Only @consultant.mcit.gov.qa, @mcit.gov.qa, and @ibtechar.com addresses can have accounts.',
    });
  }

  const now = Date.now();
  const existing = await getResetRecord(email);
  const recentRequests = existing && Array.isArray(existing.requestTimestamps)
    ? existing.requestTimestamps.filter(function (t) { return now - t < 60 * 60 * 1000; })
    : [];

  if (recentRequests.length && now - recentRequests[recentRequests.length - 1] < RESET_REQUEST_COOLDOWN_MS) {
    return jsonResponse(429, { ok: false, error: 'Please wait a moment before requesting another reset code.' });
  }

  if (recentRequests.length >= RESET_REQUEST_MAX_PER_HOUR) {
    return jsonResponse(429, { ok: false, error: 'Too many reset codes requested. Please try again in an hour.' });
  }

  // Do the same amount of work whether or not the account exists, so the
  // response timing doesn't hint at the answer either.
  const user = await getUser(email);
  const code = generateResetCode();
  await setResetRecord(email, {
    hash: hashResetCode(email, code),
    expiresAt: now + RESET_CODE_TTL_MS,
    attempts: 0,
    requestTimestamps: recentRequests.concat([now]),
  });

  if (user) {
    try {
      await sendPasswordResetEmail(email, code);
    } catch (e) {
      console.error('[DIC dashboard] sendPasswordResetEmail failed for ' + email + ': ' + (e && e.message ? e.message : e));
      // Still return the generic success message — don't let a mail-provider
      // failure double as a "yes, that account exists" signal, and the
      // reset record is already stored in case Imane reads the code from
      // the function logs in the meantime.
    }
  }

  return jsonResponse(200, { ok: true, message: GENERIC_MESSAGE });
};
