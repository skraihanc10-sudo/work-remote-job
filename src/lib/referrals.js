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

/* A short number, not a string of letters.

   Codes used to be seven characters of a reduced alphabet. Four digits is
   what somebody can read off a screen, say down a phone, and type without
   asking whether that was an O or a zero - which is the whole job of a
   referral code.

   1000 to 9999, so it is always four digits: no leading zeros to lose, and
   nobody typing "42" for "0042".

   Nine thousand codes is plenty now and a wall later, so the width grows
   rather than the allocation failing. When four digits are crowded the next
   person gets five, then six. Nobody notices until it matters, and the site
   does not stop handing out codes on the day the nine-thousandth person asks
   for one.
*/
function newCode(digits) {
  const width = Math.max(4, Math.min(9, digits || 4));
  const low = Math.pow(10, width - 1);
  const high = Math.pow(10, width) - 1;
  return String(crypto.randomInt(low, high + 1));
}

// How wide a code to hand out next. Steps up while the current width is more
// than about two-thirds used, because random picking in a nearly full space
// spends most of its time colliding.
function nextWidth() {
  for (let width = 4; width < 9; width++) {
    const low = Math.pow(10, width - 1);
    const high = Math.pow(10, width) - 1;
    const room = high - low + 1;
    const used = db.prepare(
      'SELECT COUNT(*) AS n FROM users WHERE length(ref_code) = ?'
    ).get(width).n;
    if (used < room * 0.66) return width;
  }
  return 9;
}

/* Every account gets a code the first time one is asked for, rather than at
   creation - most people never share a link, and an unused code is a row of
   noise in an index that has to stay unique. */
function codeFor(userId) {
  const row = db.prepare('SELECT ref_code FROM users WHERE id = ?').get(userId);
  if (row && row.ref_code) return row.ref_code;

  const width = nextWidth();
  for (let attempt = 0; attempt < 40; attempt++) {
    const code = newCode(width);
    try {
      db.prepare('UPDATE users SET ref_code = ? WHERE id = ?').run(code, userId);
      return code;
    } catch (err) {
      if (!String(err.message).includes('UNIQUE')) throw err;
      // Taken. Try another; the width above keeps this rare.
    }
  }
  // Forty collisions at this width means it is fuller than the estimate
  // thought. Widen and take the first free one rather than giving up.
  for (let attempt = 0; attempt < 40; attempt++) {
    const code = newCode(width + 1);
    try {
      db.prepare('UPDATE users SET ref_code = ? WHERE id = ?').run(code, userId);
      return code;
    } catch (err) {
      if (!String(err.message).includes('UNIQUE')) throw err;
    }
  }
  throw new Error('Could not allocate a referral code');
}

/* Find whoever owns a code.

   Forgiving about how it arrives, because it gets typed by hand and pasted
   out of messages: spaces and dashes come off, and letters are uppercased for
   the older seven-character codes that are still in circulation. A digits-only
   code is unaffected by the uppercasing, so one lookup serves both.
*/
function byCode(code) {
  if (!code) return null;
  const clean = String(code).trim().replace(/[\s-]+/g, '').toUpperCase();
  if (!clean) return null;
  return db.prepare('SELECT id, name, status FROM users WHERE ref_code = ?')
    .get(clean) || null;
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
/* `basis` is the figure a percentage reward was worked out from, and it only
   applies to the deposit reward. The task reward is a flat amount, so callers
   pass nothing - which used to arrive as undefined and be handed straight to
   SQLite, where it threw. That threw inside the approval transaction, so
   approving work by anybody who had been referred failed outright, and the
   only accounts affected were the referred ones. Zero, not undefined. */
function reward({ kind, sourceId, referredId, basis = 0 }) {
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

/* Referrals that came from the referrer's own connection.

   The fraud the warning on the referral page describes, made checkable: an
   account signs up, makes a handful more from the same room, and points each
   one at itself. Matching on signup_ip is deliberate - last_ip moves around
   as people use the site, but where an account was *created* does not change,
   and creation is the moment being gamed.

   Reported rather than acted on. A family sharing one connection is the same
   shape as a fraud, and suspending somebody for their brother signing up
   would be worse than the fraud. This is a list for a person to look at.
*/
function sameConnection(referrerId) {
  return db.prepare(`
    SELECT u.id, u.name, u.email, u.status, u.created_at, u.signup_ip
    FROM users u
    JOIN users r ON r.id = u.referred_by
    WHERE u.referred_by = ?
      AND u.signup_ip IS NOT NULL
      AND u.signup_ip = r.signup_ip
    ORDER BY u.id DESC
  `).all(referrerId);
}

// Everybody with at least one referral from their own connection, worst first.
function suspicious(minShared = 1) {
  return db.prepare(`
    SELECT r.id, r.name, r.email, r.status, r.signup_ip,
           COUNT(u.id) AS shared,
           (SELECT COUNT(*) FROM users x WHERE x.referred_by = r.id) AS total
    FROM users r
    JOIN users u ON u.referred_by = r.id
    WHERE u.signup_ip IS NOT NULL AND u.signup_ip = r.signup_ip
    GROUP BY r.id
    HAVING shared >= ?
    ORDER BY shared DESC, total DESC
  `).all(minShared);
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

module.exports = {
  codeFor, byCode, attach, referrerOf, reward, summary, people, recentEarnings,
  sameConnection, suspicious,
};
