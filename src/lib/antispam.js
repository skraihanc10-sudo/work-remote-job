/* ---------------------------------------------------------------------------
   The rules that keep the marketplace honest.

   All of it is enforced here, on the server, before a slot is taken. None of
   it lives in the browser, because anything checked only in the browser is not
   checked at all.

   The rules, in the order a worker meets them:

     1. One worker may take a given job once. Ever. Not once a day - once.
        Enforced by a unique index as well as this check, so even a race
        between two tabs cannot produce two rows.
     2. A worker may take at most N of the same merchant's jobs per day, so
        nobody can farm a single buyer.
     3. A worker has a daily cap across the whole site.
     4. A task submitted faster than the job's minimum time is flagged for the
        merchant rather than silently accepted.
     5. Rejections inside a short window suspend the account automatically.
     6. Upheld reports add a strike; enough strikes suspend the account.
   --------------------------------------------------------------------------- */

const { db, numSetting, audit } = require('./db');

// SQLite stores our timestamps as 'YYYY-MM-DD HH:MM:SS' in UTC. A "day" here
// is a UTC day, which is what the queries below compare against.
function todayStart() {
  return new Date().toISOString().slice(0, 10) + ' 00:00:00';
}

function daysAgo(n) {
  return new Date(Date.now() - n * 86400000).toISOString().slice(0, 19).replace('T', ' ');
}

/* Everything a worker needs to know before pressing Start.
   Returns { allowed, reason, code } - the reason is shown to the worker, so it
   says what to do next rather than just refusing. */
function canStart(worker, job) {
  if (worker.status !== 'active') {
    return { allowed: false, code: 'suspended', reason: 'Your account is suspended.' };
  }
  if (worker.id === job.merchant_id) {
    return { allowed: false, code: 'own_job', reason: 'This is your own job.' };
  }
  /* An unconfirmed address cannot take work.

     This is the whole reason password sign-up is safe to offer. A name and an
     address cost nothing to invent, but a working inbox per account is real
     effort, which is the same thing that made Google-only sign-in worth
     having. Google accounts arrive already confirmed, so this never touches
     them. */
  if (!worker.email_verified) {
    return {
      allowed: false, code: 'unverified',
      reason: 'Confirm your email address first. Check your inbox for the link, or ask for a new one on your account page.',
    };
  }
  if (job.status !== 'active') {
    return { allowed: false, code: 'closed', reason: 'This job is no longer taking work.' };
  }
  if (job.slots_filled >= job.slots) {
    return { allowed: false, code: 'full', reason: 'Every slot on this job is taken.' };
  }
  if (job.country && worker.country && job.country !== worker.country) {
    return { allowed: false, code: 'country', reason: `This job is only for workers in ${job.country}.` };
  }

  // Level gate. Required late to avoid a circular require between the two
  // modules that both reason about a worker's history.
  if (job.min_level > 0) {
    const quality = require('./quality');
    const standing = quality.workerStanding(worker.id);
    if (standing.level < job.min_level) {
      return {
        allowed: false, code: 'level',
        reason: `This job needs ${quality.levelName(job.min_level)} level or above. You are ${standing.name}`
          + (standing.next ? ` - ${standing.next.tasks} approved tasks at ${standing.next.minRate}% or better reaches ${standing.next.name}.` : '.'),
      };
    }
  }

  // 1. Once per job, forever.
  const already = db.prepare(
    'SELECT id, status FROM submissions WHERE job_id = ? AND worker_id = ?'
  ).get(job.id, worker.id);
  if (already) {
    return {
      allowed: false,
      code: 'already_done',
      reason: already.status === 'started'
        ? 'You already have this task open.'
        : 'You have already done this job. Each job can be done once per worker.',
    };
  }

  // 2. Per-merchant daily cap.
  const perMerchant = numSetting('max_tasks_per_merchant_per_day');
  const fromMerchant = db.prepare(
    `SELECT COUNT(*) AS n FROM submissions
     WHERE worker_id = ? AND merchant_id = ? AND started_at >= ?
       AND status IN ('started','submitted','approved')`
  ).get(worker.id, job.merchant_id, todayStart()).n;
  if (fromMerchant >= perMerchant) {
    return {
      allowed: false,
      code: 'merchant_cap',
      reason: `You have taken ${perMerchant} tasks from this buyer today. Try another buyer, or come back tomorrow.`,
    };
  }

  // 3. Daily cap overall.
  const perDay = numSetting('max_tasks_per_day');
  const today = db.prepare(
    `SELECT COUNT(*) AS n FROM submissions
     WHERE worker_id = ? AND started_at >= ? AND status IN ('started','submitted','approved')`
  ).get(worker.id, todayStart()).n;
  if (today >= perDay) {
    return {
      allowed: false,
      code: 'daily_cap',
      reason: `You have reached today's limit of ${perDay} tasks. The limit resets at midnight UTC.`,
    };
  }

  // Do not let one worker sit on many open slots at once - it starves the job
  // and is the cheapest way to grief a merchant.
  const open = db.prepare(
    "SELECT COUNT(*) AS n FROM submissions WHERE worker_id = ? AND status = 'started'"
  ).get(worker.id).n;
  if (open >= 3) {
    return {
      allowed: false,
      code: 'too_many_open',
      reason: 'Finish or drop one of your open tasks first. You can hold three at a time.',
    };
  }

  return { allowed: true, remainingToday: perDay - today, fromThisMerchant: fromMerchant };
}

/* Checked when the proof arrives. Does not block - a merchant should decide -
   but marks anything implausible so it is not waved through. */
function inspectSubmission(sub, job) {
  const seconds = sub.seconds_spent == null ? 0 : sub.seconds_spent;
  const floor = Math.max(numSetting('min_seconds_floor'), job.min_seconds || 0);
  const reasons = [];

  if (seconds < floor) {
    reasons.push(`Submitted in ${seconds}s, under the ${floor}s this job expects`);
  }

  const text = String(sub.proof_text || '').trim();
  if (text.length < 8 && !sub.proof_file) {
    reasons.push('Proof is almost empty');
  }

  // The same proof text pasted across jobs is the clearest spam signal there
  // is, and it costs one indexed lookup to catch.
  if (text.length >= 8) {
    const dupe = db.prepare(
      `SELECT COUNT(*) AS n FROM submissions
       WHERE worker_id = ? AND id != ? AND proof_text = ?`
    ).get(sub.worker_id, sub.id, text).n;
    if (dupe > 0) reasons.push(`Identical proof used on ${dupe} other task${dupe > 1 ? 's' : ''}`);
  }

  if (!reasons.length) return { flagged: 0, reason: null };
  return { flagged: 1, reason: reasons.join('; ') };
}

/* After a rejection: too many in a short window and the account pauses. This
   is deliberately about *recent* rejections - an old mistake should not follow
   somebody forever. */
function afterRejection(workerId) {
  const limit = numSetting('auto_suspend_rejects');
  const windowDays = numSetting('auto_suspend_window_days');
  const since = daysAgo(windowDays);

  const recent = db.prepare(
    `SELECT COUNT(*) AS n FROM submissions
     WHERE worker_id = ? AND status = 'rejected' AND reviewed_at >= ?`
  ).get(workerId, since).n;

  if (recent >= limit) {
    suspend(workerId,
      `${recent} rejected tasks in ${windowDays} days`,
      numSetting('suspend_days'));
    return true;
  }
  return false;
}

function suspend(userId, reason, days) {
  const until = new Date(Date.now() + (days || 7) * 86400000)
    .toISOString().slice(0, 19).replace('T', ' ');
  db.prepare(
    "UPDATE users SET status = 'suspended', suspended_until = ?, suspend_reason = ? WHERE id = ?"
  ).run(until, reason, userId);
  audit(null, 'auto_suspend', `user:${userId}`, { reason, until });
}

function addStrike(userId, reason) {
  db.prepare('UPDATE users SET strikes = strikes + 1 WHERE id = ?').run(userId);
  const user = db.prepare('SELECT strikes FROM users WHERE id = ?').get(userId);
  const limit = numSetting('strikes_before_suspend');
  if (user.strikes >= limit) {
    suspend(userId, `${user.strikes} upheld reports - ${reason}`, numSetting('suspend_days'));
    return true;
  }
  return false;
}

/* A suspension that has run its course should lift itself. Called on every
   authenticated request, which is cheap and means nobody has to remember. */
function liftIfExpired(user) {
  if (user.status !== 'suspended' || !user.suspended_until) return user;
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  if (user.suspended_until > now) return user;

  db.prepare(
    "UPDATE users SET status = 'active', suspended_until = NULL, suspend_reason = NULL WHERE id = ?"
  ).run(user.id);
  audit(null, 'suspension_expired', `user:${user.id}`);
  return { ...user, status: 'active', suspended_until: null, suspend_reason: null };
}

/* Slots held past the job's window go back in the pool, so an abandoned task
   does not block the job forever. */
function releaseExpiredHolds() {
  const stale = db.prepare(`
    SELECT s.id, s.job_id FROM submissions s
    JOIN jobs j ON j.id = s.job_id
    WHERE s.status = 'started'
      AND datetime(s.started_at, '+' || j.hold_minutes || ' minutes') < datetime('now')
  `).all();

  for (const row of stale) {
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare("UPDATE submissions SET status = 'expired' WHERE id = ? AND status = 'started'")
        .run(row.id);
      db.prepare('UPDATE jobs SET slots_filled = MAX(0, slots_filled - 1) WHERE id = ?')
        .run(row.job_id);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
    }
  }
  return stale.length;
}

module.exports = {
  canStart, inspectSubmission, afterRejection,
  suspend, addStrike, liftIfExpired, releaseExpiredHolds,
  todayStart, daysAgo,
};
