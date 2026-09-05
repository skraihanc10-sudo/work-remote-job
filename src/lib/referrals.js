/* ---------------------------------------------------------------------------
   Referrals.

   The one decision that matters here: a referral reward is paid out of the
   platform's own commission, never out of what the worker earns or what the
   buyer paid.

   The tempting alternative is to shave a slice off the referred person's
   earnings. That is not a reward scheme, it is a transfer - it makes the site
   quietly worse for the person actually doing the work, and it gives everybody
   a reason to recruit rather than to work. Ours costs the platform, which is
   the only party that benefits from growth.

   That also keeps the books simple: every referral payment is a transfer from
   the platform account to the referrer, so the total money in the system does
   not change.
   --------------------------------------------------------------------------- */

const crypto = require('crypto');
const { db, numSetting, audit } = require('./db');
const money = require('./money');

// No 0/O/1/I/l - these get read aloud, written on paper and mistyped.
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

function newCode() {
  let out = '';
  for (let i = 0; i < 7; i++) out += ALPHABET[crypto.randomInt(ALPHABET.length)];
  return out;
}

/* Every account gets a code the first time one is asked for, rather than at
   creation - most people never share a link, and an unused code is a row of
   noise in an index that has to stay unique. */
function codeFor(userId) {
  const row = db.prepare('SELECT ref_code FROM users WHERE id = ?').get(userId);
  if (row && row.ref_code) return row.ref_code;

  for (let attempt = 0; attempt < 8; attempt++) {
    const code = newCode();
    try {
      db.prepare('UPDATE users SET ref_code = ? WHERE id = ?').run(code, userId);
      return code;
    } catch (err) {
      if (!String(err.message).includes('UNIQUE')) throw err;
      // Collision. Try again; with 31^7 codes this effectively never happens.
    }
  }
  throw new Error('Could not allocate a referral code');
}

function byCode(code) {
  if (!code) return null;
  return db.prepare('SELECT id, name, status FROM users WHERE ref_code = ?')
    .get(String(code).trim().toUpperCase()) || null;
}

/* Link a new account to whoever referred them. Only ever at creation: letting
   a referrer be attached later turns into people claiming each other's
   accounts after the fact. */
function attach(newUserId, code, ip) {
  const referrer = byCode(code);
  if (!referrer) return null;
  if (referrer.id === newUserId) return null;
  if (referrer.status === 'banned') return null;

  const already = db.prepare('SELECT referred_by FROM users WHERE id = ?').get(newUserId);
  if (already && already.referred_by) return null;

  db.prepare('UPDATE users SET referred_by = ? WHERE id = ?').run(referrer.id, newUserId);
  audit(newUserId, 'referred_by', `user:${referrer.id}`, { code }, ip);
  return referrer.id;
}

function referrerOf(userId) {
  const row = db.prepare('SELECT referred_by FROM users WHERE id = ?').get(userId);
  return row && row.referred_by ? row.referred_by : null;
}

/* Pay the referrer, once, for one event.

   Runs inside the caller's transaction so an approval and its referral payment
   either both happen or neither does. The unique index on (kind, source_id) is
   what makes a retry harmless - it throws, we ignore it, nobody is paid twice.
*/
function reward({ kind, sourceId, referredId, basis }) {
  const referrerId = referrerOf(referredId);
  if (!referrerId) return null;

  let amount;
  if (kind === 'task') {
    /* A flat amount, once, the first time somebody they invited has work
       approved.

       It used to be a share of our commission on every task they ever did,
       which sounds more generous and is impossible for anybody to check: the
       commission is invisible to them, so "you earn a percentage" is a promise
       with no number attached. The referral page says twenty taka, so twenty
       taka is what arrives, on a day they can point at.

       Paid once per referred person, not once per task - the unique index is
       on (kind, source_id), so the source here is the person, not the task. */
    const already = db.prepare(
      "SELECT 1 FROM referral_earnings WHERE kind = 'task' AND source_id = ?"
    ).get(referredId);
    if (already) return null;
    sourceId = referredId;
    amount = numSetting('referral_flat');
  } else {
    const bps = numSetting('referral_deposit_bps');
    if (!bps) return null;
    amount = Math.floor((basis * bps) / 10000);
  }

  if (!amount || amount <= 0) return null;

  const referrer = db.prepare('SELECT status FROM users WHERE id = ?').get(referrerId);
  if (!referrer || referrer.status === 'banned') return null;

  let platformId;
  try {
    platformId = money.platformUserId();
  } catch (err) {
    // No platform account yet. Skip the reward rather than minting money.
    return null;
  }
  if (platformId === referrerId) return null;

  try {
    db.prepare(`INSERT INTO referral_earnings (referrer_id, referred_id, kind, source_id, basis, amount)
                VALUES (?, ?, ?, ?, ?, ?)`)
      .run(referrerId, referredId, kind, sourceId, basis, amount);
  } catch (err) {
    if (String(err.message).includes('UNIQUE')) return null;   // already paid
    throw err;
  }

  const label = kind === 'task'
    ? 'somebody you invited starting work'
    : 'a deposit by your referral';
  money.entry(referrerId, 'referral', amount, { type: 'referral', id: sourceId },
    `Referral bonus from ${label}`);
  money.entry(platformId, 'referral_paid', -amount, { type: 'referral', id: sourceId },
    `Referral bonus paid to user ${referrerId}`);

  return { referrerId, amount };
}

function summary(userId) {
  const joined = db.prepare('SELECT COUNT(*) AS n FROM users WHERE referred_by = ?').get(userId).n;
  const earned = db.prepare(
    'SELECT COALESCE(SUM(amount), 0) AS n FROM referral_earnings WHERE referrer_id = ?'
  ).get(userId).n;
  const active = db.prepare(`
    SELECT COUNT(DISTINCT referred_id) AS n FROM referral_earnings WHERE referrer_id = ?
  `).get(userId).n;
  return { joined, earned, active };
}

function people(userId) {
  return db.prepare(`
    SELECT u.id, u.name, u.role, u.created_at,
      (SELECT COALESCE(SUM(amount), 0) FROM referral_earnings
        WHERE referrer_id = ? AND referred_id = u.id) AS earned,
      (SELECT COUNT(*) FROM submissions WHERE worker_id = u.id AND status = 'approved') AS tasks
    FROM users u WHERE u.referred_by = ? ORDER BY u.id DESC LIMIT 100
  `).all(userId, userId);
}

function recentEarnings(userId, limit = 20) {
  return db.prepare(`
    SELECT r.*, u.name AS from_name FROM referral_earnings r
    JOIN users u ON u.id = r.referred_id
    WHERE r.referrer_id = ? ORDER BY r.id DESC LIMIT ?
  `).all(userId, limit);
}

module.exports = { codeFor, byCode, attach, referrerOf, reward, summary, people, recentEarnings };
