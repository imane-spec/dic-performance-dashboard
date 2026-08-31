/* =============================================================================
   lib/store.js — persistent storage for user accounts + password-reset codes
   ---------------------------------------------------------------------------
   The six exported functions intentionally keep the same signatures the
   Replit Database version used. Netlify Blobs supplies the durable
   key-value storage here instead, so accounts survive restarts and
   redeploys without needing any separate database service.

   Netlify is supposed to auto-configure getStore() with no extra setup when
   called from a Function, but that automatic wiring can fail to attach to a
   given deploy (a known Netlify issue, not specific to this project). To
   sidestep it entirely, siteID and token are passed explicitly: SITE_ID is
   a read-only variable Netlify always injects into Functions automatically,
   and BLOBS_TOKEN is a personal access token you create once in Netlify and
   add as an environment variable (see README.md).
   ========================================================================== */

const { getStore } = require('@netlify/blobs');

const USER_KEY_PREFIX = 'user:';
const RESET_KEY_PREFIX = 'reset:';

function store() {
  return getStore({
    name: 'dic-accounts',
    siteID: process.env.SITE_ID,
    token: process.env.BLOBS_TOKEN,
  });
}

function userKey(email) {
  return USER_KEY_PREFIX + email;
}

function resetKey(email) {
  return RESET_KEY_PREFIX + email;
}

async function getUser(email) {
  const value = await store().get(userKey(email), { type: 'json' });
  return value === null || value === undefined ? null : value;
}

async function setUser(email, record) {
  await store().setJSON(userKey(email), record);
}

async function deleteUser(email) {
  await store().delete(userKey(email));
}

async function getResetRecord(email) {
  const value = await store().get(resetKey(email), { type: 'json' });
  return value === null || value === undefined ? null : value;
}

async function setResetRecord(email, record) {
  await store().setJSON(resetKey(email), record);
}

async function deleteResetRecord(email) {
  await store().delete(resetKey(email));
}

module.exports = {
  getUser,
  setUser,
  deleteUser,
  getResetRecord,
  setResetRecord,
  deleteResetRecord,
};
