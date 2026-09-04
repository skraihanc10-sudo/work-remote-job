/* ---------------------------------------------------------------------------
   Worker levels, buyer reputation, and the review deadline.

   The review deadline is the important one. Before it existed a buyer could
   simply never look at a submission: the worker was never paid, never
   rejected, and their money sat in escrow indefinitely. Nothing in the system
   was broken - it just quietly stopped, which is the worst failure mode
   because nobody can point at it.

   Now every submission carries a deadline. Miss it and the work is approved
   and paid for. That is deliberately harsher on the buyer than on the worker:
   the buyer chose the window, funded the job and holds all the information,
   while the worker has already done the work and can only wait.
   --------------------------------------------------------------------------- */

const { db, numSetting, audit } = require('./db');
const money = require('./money');

// ------------------------------------------------------------------- levels
const LEVELS = [
  { level: 0, name: 'New',    note: 'Just started' },
  { level: 1, name: 'Bronze', note: 'Getting going' },
  { level: 2, name: 'Silver', note: 'Reliable' },
  { level: 3, name: 'Gold',   note: 'Trusted' },
];

/* A worker's standing, computed rather than stored, so it can never disagree
   with their actual history. Satisfaction is approved over decided - work
   still waiting is not held against anybody. */
function workerStanding(userId) {
  const r = db.prepare(`
    SELECT
      SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved,
      SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected
    FROM submissions WHERE worker_id = ?
  `).get(userId);

  const approved = r.approved || 0;
  const rejected = r.rejected || 0;
  const decided = approved + rejected;
  const rate = decided ? Math.round((approved / decided) * 100) : null;
  const minRate = numSetting('level_min_rate');

  let level = 0;
  // A high count does not carry a poor satisfaction rate: somebody who has
  // done four hundred tasks and had a quarter rejected is not "trusted".
  if (rate === null || rate >= minRate) {
    if (approved >= numSetting('level4_tasks')) level = 3;
    else if (approved >= numSetting('level3_tasks')) level = 2;
    else if (approved >= numSetting('level2_tasks')) level = 1;
  }

  return {
    approved, rejected, decided, rate, level,
    name: LEVELS[level].name,
    note: LEVELS[level].note,
    // What it takes to reach the next one, so the number means something.
    next: level < 3 ? {
      name: LEVELS[level + 1].name,
      tasks: numSetting(['level2_tasks', 'level3_tasks', 'level4_tasks'][level]),
      minRate,
    } : null,
  };
}

function levelName(level) {
  return (LEVELS[level] || LEVELS[0]).name;
}

// --------------------------------------------------------- buyer reputation
function buyerStanding(merchantId) {
  const r = db.prepare(`
    SELECT COUNT(*) AS n, AVG(stars) AS avg FROM buyer_ratings WHERE merchant_id = ?
  `).get(merchantId);

  const decided = db.prepare(`
    SELECT
      SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved,
      SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected,
      SUM(CASE WHEN auto_approved = 1 THEN 1 ELSE 0 END) AS lapsed
    FROM submissions WHERE merchant_id = ?
  `).get(merchantId);

  const a = decided.approved || 0;
  const rj = decided.rejected || 0;

  return {
    ratings: r.n || 0,
    stars: r.avg ? Math.round(r.avg * 10) / 10 : null,
    approved: a,
    rejected: rj,
    // How often this buyer approves what is sent. A very low number beside a
    // lot of submissions is the shape of a buyer taking free work.
    approvalRate: a + rj ? Math.round((a / (a + rj)) * 100) : null,
    // How often they let the deadline run out instead of deciding.
    lapsed: decided.lapsed || 0,
  };
}

function canWorkerRate(submissionId, workerId) {
  const sub = db.prepare(
    "SELECT id, worker_id, status FROM submissions WHERE id = ? AND worker_id = ?"
  ).get(submissionId, workerId);
  if (!sub) return false;
  if (sub.status !== 'approved' && sub.status !== 'rejected') return false;
  const already = db.prepare('SELECT id FROM buyer_ratings WHERE submission_id = ?').get(submissionId);
  return !already;
}

function rateBuyer({ submissionId, workerId, stars, comment }) {
  const n = Math.max(1, Math.min(5, Math.round(Number(stars) || 0)));
  if (!canWorkerRate(submissionId, workerId)) {
    throw new Error('That task cannot be rated - it is either not yours, not decided yet, or already rated.');
  }
  const sub = db.prepare('SELECT merchant_id FROM submissions WHERE id = ?').get(submissionId);
  db.prepare(`INSERT INTO buyer_ratings (merchant_id, worker_id, submission_id, stars, comment)
              VALUES (?, ?, ?, ?, ?)`)
    .run(sub.merchant_id, workerId, submissionId, n, String(comment || '').trim().slice(0, 300) || null);
  return n;
}

// ------------------------------------------------------------- the deadline
function deadlineOf(sub, job) {
  if (!sub.submitted_at) return null;
  const from = new Date(sub.submitted_at.replace(' ', 'T') + 'Z').getTime();
  return from + (job.ttr_days || numSetting('default_ttr_days')) * 86400000;
}

function hoursLeft(sub, job) {
  const at = deadlineOf(sub, job);
  if (!at) return null;
  return Math.max(0, Math.round((at - Date.now()) / 3600000));
}

/* Approve everything whose deadline has passed.

   Runs on a timer and also on boot, because a server that was down over a
   weekend must not swallow the deadline it was supposed to be enforcing.

   Each one is its own transaction: a job that has somehow run out of escrow
   should not stop the rest from being paid.
*/
function releaseOverdue() {
  const due = db.prepare(`
    SELECT s.id FROM submissions s JOIN jobs j ON j.id = s.job_id
    WHERE s.status = 'submitted'
      AND s.submitted_at IS NOT NULL
      AND datetime(s.submitted_at, '+' || COALESCE(j.ttr_days, 7) || ' days') <= datetime('now')
  `).all();

  let paid = 0;
  for (const row of due) {
    db.exec('BEGIN IMMEDIATE');
    try {
      const sub = db.prepare("SELECT * FROM submissions WHERE id = ? AND status = 'submitted'").get(row.id);
      if (!sub) { db.exec('COMMIT'); continue; }
      const job = db.prepare('SELECT * FROM jobs WHERE id = ?').get(sub.job_id);
      if (!job) { db.exec('COMMIT'); continue; }

      const result = money.payForSubmission(sub, job);
      db.prepare(`UPDATE submissions SET status = 'approved', auto_approved = 1,
                  reviewed_at = datetime('now'),
                  review_note = 'Approved automatically - the buyer did not review it in time'
                  WHERE id = ?`).run(sub.id);

      db.prepare(`INSERT INTO notices (user_id, kind, title, body) VALUES (?, 'auto_approved', ?, ?)`)
        .run(sub.worker_id, 'Your task was approved automatically',
          'The buyer had ' + (job.ttr_days || 7) + ' days to review it and did not, so it was approved and '
          + money.fmt(result.net) + ' has been added to your balance. This is how the deadline works - you are never left waiting indefinitely.');

      db.prepare(`INSERT INTO notices (user_id, kind, title, body) VALUES (?, 'auto_approved', ?, ?)`)
        .run(sub.merchant_id, 'A submission was approved without you',
          'The review deadline on "' + job.title + '" ran out, so the submission was approved and paid. '
          + 'Reviewing inside the window you set is what keeps this from happening.');

      db.exec('COMMIT');
      audit(null, 'auto_approved', `submission:${sub.id}`,
        { job: job.id, ttr: job.ttr_days, net: result.net });
      paid++;
    } catch (err) {
      db.exec('ROLLBACK');
      console.error('auto-approve failed for submission', row.id, '-', err.message);
    }
  }
  return paid;
}

module.exports = {
  LEVELS, levelName, workerStanding, buyerStanding,
  canWorkerRate, rateBuyer,
  deadlineOf, hoursLeft, releaseOverdue,
};
