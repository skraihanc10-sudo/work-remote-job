/* ---------------------------------------------------------------------------
   Numbers for the admin dashboard.

   Every figure here is derived, never stored. A stored counter and the rows it
   counts drift apart the first time something is deleted or a transaction
   rolls back, and then the dashboard quietly lies - which is worse than having
   no dashboard, because somebody acts on it.

   The queries are deliberately plain. This runs on SQLite on a small box, and
   the whole point is that an admin can open the page at any moment without
   wondering whether it will cost anything.
   --------------------------------------------------------------------------- */

const { db, numSetting } = require('./db');

function daysAgo(n) {
  return new Date(Date.now() - n * 86400000).toISOString().slice(0, 19).replace('T', ' ');
}

const one = (sql, ...args) => db.prepare(sql).get(...args) || {};
const num = (sql, ...args) => Number(one(sql, ...args).n || 0);

// ------------------------------------------------------------------- people
function people() {
  const byRole = db.prepare(
    "SELECT role, COUNT(*) AS n FROM users GROUP BY role"
  ).all().reduce((a, r) => (a[r.role] = r.n, a), {});

  return {
    total: (byRole.worker || 0) + (byRole.merchant || 0) + (byRole.admin || 0),
    workers: byRole.worker || 0,
    merchants: byRole.merchant || 0,
    admins: byRole.admin || 0,
    suspended: num("SELECT COUNT(*) AS n FROM users WHERE status = 'suspended'"),
    unverified: num("SELECT COUNT(*) AS n FROM users WHERE email_verified = 0 AND role != 'admin'"),
    newToday: num("SELECT COUNT(*) AS n FROM users WHERE created_at >= ?", daysAgo(1)),
    new7: num("SELECT COUNT(*) AS n FROM users WHERE created_at >= ?", daysAgo(7)),
    new30: num("SELECT COUNT(*) AS n FROM users WHERE created_at >= ?", daysAgo(30)),
    // Somebody who has done something, as opposed to somebody who signed up.
    active7: num(`SELECT COUNT(DISTINCT worker_id) AS n FROM submissions WHERE started_at >= ?`, daysAgo(7)),
    buying7: num(`SELECT COUNT(DISTINCT merchant_id) AS n FROM jobs WHERE created_at >= ?`, daysAgo(7)),
  };
}

// -------------------------------------------------------------------- money
/* Where every unit on the site currently is.

   The identity that must always hold:
     deposits + admin credits - admin debits = balances + escrow remaining
   If these two disagree, something has created or destroyed money and that is
   the first thing an admin should be told - so it is on the dashboard rather
   than buried in a script nobody runs.
*/
function money() {
  const kinds = db.prepare(
    'SELECT kind, COALESCE(SUM(amount), 0) AS n FROM ledger GROUP BY kind'
  ).all().reduce((a, r) => (a[r.kind] = r.n, a), {});

  const inflow = (kinds.deposit || 0) + (kinds.admin_credit || 0) + (kinds.admin_debit || 0);
  const balances = db.prepare('SELECT COALESCE(SUM(amount), 0) AS n FROM ledger').get().n;
  const escrow = num('SELECT COALESCE(SUM(held - released - refunded), 0) AS n FROM escrow');

  return {
    deposited: kinds.deposit || 0,
    adminAdded: kinds.admin_credit || 0,
    adminTaken: -(kinds.admin_debit || 0),
    earned: kinds.task_earning || 0,
    fees: kinds.platform_fee || 0,
    referralPaid: kinds.referral || 0,
    withdrawn: -(kinds.withdrawal || 0),
    escrow,
    balances,
    inflow,
    // The whole point of the section.
    balanced: inflow === balances + escrow,
    drift: inflow - (balances + escrow),

    pendingDeposits: num("SELECT COUNT(*) AS n FROM deposits WHERE status = 'pending'"),
    pendingWithdrawals: num("SELECT COUNT(*) AS n FROM withdrawals WHERE status = 'pending'"),
    pendingWithdrawalValue: num("SELECT COALESCE(SUM(amount), 0) AS n FROM withdrawals WHERE status = 'pending'"),
  };
}

// -------------------------------------------------------------------- work
function work() {
  const byStatus = db.prepare(
    'SELECT status, COUNT(*) AS n FROM submissions GROUP BY status'
  ).all().reduce((a, r) => (a[r.status] = r.n, a), {});

  const jobs = db.prepare(
    'SELECT status, COUNT(*) AS n FROM jobs GROUP BY status'
  ).all().reduce((a, r) => (a[r.status] = r.n, a), {});

  const decided = (byStatus.approved || 0) + (byStatus.rejected || 0);

  return {
    open: byStatus.started || 0,
    waiting: byStatus.submitted || 0,
    approved: byStatus.approved || 0,
    rejected: byStatus.rejected || 0,
    expired: byStatus.expired || 0,
    autoApproved: num('SELECT COUNT(*) AS n FROM submissions WHERE auto_approved = 1'),
    approvalRate: decided ? Math.round(((byStatus.approved || 0) / decided) * 100) : null,
    flagged: num("SELECT COUNT(*) AS n FROM submissions WHERE flagged = 1 AND status = 'submitted'"),
    done7: num("SELECT COUNT(*) AS n FROM submissions WHERE reviewed_at >= ? AND status = 'approved'", daysAgo(7)),

    jobsActive: jobs.active || 0,
    jobsCompleted: jobs.completed || 0,
    jobsCancelled: jobs.cancelled || 0,
    slotsOpen: num("SELECT COALESCE(SUM(slots - slots_filled), 0) AS n FROM jobs WHERE status = 'active'"),

    // Work that is past its review deadline right now. The sweep clears these
    // every minute, so a number above zero means the sweep is not running.
    overdue: num(`
      SELECT COUNT(*) AS n FROM submissions s JOIN jobs j ON j.id = s.job_id
      WHERE s.status = 'submitted' AND s.submitted_at IS NOT NULL
        AND datetime(s.submitted_at, '+' || COALESCE(j.ttr_days, 7) || ' days') <= datetime('now')`),
  };
}

function queue() {
  return {
    reports: num("SELECT COUNT(*) AS n FROM reports WHERE status = 'open'"),
    roleRequests: num("SELECT COUNT(*) AS n FROM role_requests WHERE status = 'pending'"),
    tickets: num("SELECT COUNT(*) AS n FROM tickets WHERE status = 'open'"),
    mailFailed: num("SELECT COUNT(*) AS n FROM mail_outbox WHERE status = 'failed'"),
    mailQueued: num("SELECT COUNT(*) AS n FROM mail_outbox WHERE status IN ('queued','held')"),
  };
}

// ------------------------------------------------------------- time series
/* A row per day for the last N days, with zeroes filled in.

   The gaps matter: a chart that silently skips quiet days makes a dead week
   look like a busy one, which is precisely the thing you want the chart to
   show you.
*/
function series(days = 14) {
  const out = [];
  const signups = db.prepare(`
    SELECT date(created_at) AS d, COUNT(*) AS n FROM users
    WHERE created_at >= ? GROUP BY d
  `).all(daysAgo(days)).reduce((a, r) => (a[r.d] = r.n, a), {});

  const tasks = db.prepare(`
    SELECT date(reviewed_at) AS d, COUNT(*) AS n FROM submissions
    WHERE status = 'approved' AND reviewed_at >= ? GROUP BY d
  `).all(daysAgo(days)).reduce((a, r) => (a[r.d] = r.n, a), {});

  const paid = db.prepare(`
    SELECT date(created_at) AS d, COALESCE(SUM(amount), 0) AS n FROM ledger
    WHERE kind = 'task_earning' AND created_at >= ? GROUP BY d
  `).all(daysAgo(days)).reduce((a, r) => (a[r.d] = r.n, a), {});

  const deposits = db.prepare(`
    SELECT date(created_at) AS d, COALESCE(SUM(amount), 0) AS n FROM ledger
    WHERE kind = 'deposit' AND created_at >= ? GROUP BY d
  `).all(daysAgo(days)).reduce((a, r) => (a[r.d] = r.n, a), {});

  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    out.push({
      day: d,
      label: d.slice(5),
      signups: signups[d] || 0,
      tasks: tasks[d] || 0,
      paid: paid[d] || 0,
      deposits: deposits[d] || 0,
    });
  }
  return out;
}

// --------------------------------------------------------- buyer behaviour
/* How a buyer treats the people working for them.

   This is the section that exists to answer one question: is this buyer taking
   free work? The shape of that is a high rejection rate, or a habit of letting
   the review deadline lapse, or reports from workers - usually all three. None
   of these is proof on its own, which is why they are shown together and
   nothing is decided automatically.
*/
function buyerBehaviour(merchantId) {
  const s = one(`
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved,
      SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected,
      SUM(CASE WHEN status = 'submitted' THEN 1 ELSE 0 END) AS waiting,
      SUM(CASE WHEN auto_approved = 1 THEN 1 ELSE 0 END) AS lapsed
    FROM submissions WHERE merchant_id = ?`, merchantId);

  const approved = s.approved || 0;
  const rejected = s.rejected || 0;
  const decided = approved + rejected;

  const jobs = one(`
    SELECT COUNT(*) AS total,
      SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active
    FROM jobs WHERE merchant_id = ?`, merchantId);

  const paidOut = num(`
    SELECT COALESCE(SUM(l.amount), 0) AS n FROM ledger l
    JOIN submissions s ON s.id = l.ref_id
    WHERE l.kind = 'task_earning' AND l.ref_type = 'submission' AND s.merchant_id = ?`, merchantId);

  const held = num(`
    SELECT COALESCE(SUM(e.held - e.released - e.refunded), 0) AS n
    FROM escrow e JOIN jobs j ON j.id = e.job_id WHERE j.merchant_id = ?`, merchantId);

  const reports = num(
    "SELECT COUNT(*) AS n FROM reports WHERE against_id = ?", merchantId);
  const upheld = num(
    "SELECT COUNT(*) AS n FROM reports WHERE against_id = ? AND status = 'upheld'", merchantId);

  const rating = one(
    'SELECT COUNT(*) AS n, AVG(stars) AS avg FROM buyer_ratings WHERE merchant_id = ?', merchantId);

  /* Work that is sitting. Not a raw count - a count only says the buyer is
     busy, and a big buyer with fifty submissions in flight is fine. What
     matters is how long each one has been waiting against the window the buyer
     themselves chose, so this counts the ones already past halfway. */
  const stale = num(`
    SELECT COUNT(*) AS n FROM submissions s JOIN jobs j ON j.id = s.job_id
    WHERE s.merchant_id = ? AND s.status = 'submitted' AND s.submitted_at IS NOT NULL
      AND julianday('now') - julianday(s.submitted_at) > (COALESCE(j.ttr_days, 7) / 2.0)`, merchantId);

  // How long they actually take, not how long they promised.
  const speed = one(`
    SELECT AVG(julianday(reviewed_at) - julianday(submitted_at)) AS days
    FROM submissions
    WHERE merchant_id = ? AND reviewed_at IS NOT NULL AND submitted_at IS NOT NULL
      AND auto_approved = 0`, merchantId);

  const rejectRate = decided ? Math.round((rejected / decided) * 100) : null;
  /* Of the submissions that actually reached a conclusion, how many got there
     only because the deadline forced it.

     Measured against decided work rather than every submission on purpose:
     including work that is still legitimately inside its review window drags
     the figure down and lets a buyer who ignores everything look average
     simply by having a lot in flight. */
  const lapseRate = decided ? Math.round(((s.lapsed || 0) / decided) * 100) : null;

  /* Concerns, in plain words, only when the numbers are past the point where
     they are worth a person's attention. Thresholds are deliberately generous:
     a new buyer with three submissions and one rejection is not a scammer, and
     an admin who gets used to ignoring false alarms stops reading them. */
  const concerns = [];
  if (decided >= 10 && rejectRate >= 40) {
    concerns.push(`Rejects ${rejectRate}% of the work sent to them, over ${decided} decisions.`);
  }
  // 25%, not 40%: a buyer who ignores one submission in four is already not
  // running their jobs, and the worker is only paid because the site steps in.
  if (decided >= 8 && lapseRate >= 25) {
    concerns.push(`Lets the review deadline run out on ${lapseRate}% of submissions - the site pays those workers on their behalf.`);
  }
  if (upheld > 0) {
    concerns.push(`${upheld} report${upheld === 1 ? '' : 's'} against them ${upheld === 1 ? 'was' : 'were'} upheld.`);
  }
  if (stale >= 5) {
    concerns.push(`${stale} submissions are more than halfway through their review window with no decision.`);
  }
  if (rating.n >= 3 && rating.avg && rating.avg <= 2.5) {
    concerns.push(`Workers rate them ${Math.round(rating.avg * 10) / 10} out of 5 over ${rating.n} ratings.`);
  }

  return {
    jobs: jobs.total || 0,
    jobsActive: jobs.active || 0,
    submissions: s.total || 0,
    approved, rejected,
    waiting: s.waiting || 0,
    lapsed: s.lapsed || 0,
    approvalRate: decided ? Math.round((approved / decided) * 100) : null,
    rejectRate, lapseRate,
    paidOut, held,
    reports, upheld,
    ratings: rating.n || 0,
    stars: rating.avg ? Math.round(rating.avg * 10) / 10 : null,
    reviewDays: speed.days != null ? Math.round(speed.days * 10) / 10 : null,
    stale,
    concerns,
  };
}

/* Every buyer, ranked so the ones worth looking at come first. */
function buyers(limit = 100) {
  const rows = db.prepare(`
    SELECT u.id, u.name, u.email, u.status, u.created_at, u.email_verified,
      (SELECT COALESCE(SUM(amount), 0) FROM ledger WHERE user_id = u.id) AS balance
    FROM users u WHERE u.role = 'merchant'
    ORDER BY u.id DESC LIMIT ?
  `).all(limit);

  return rows.map(b => ({ ...b, behaviour: buyerBehaviour(b.id) }))
    .sort((a, z) => z.behaviour.concerns.length - a.behaviour.concerns.length);
}

// ------------------------------------------------------------- leaderboards
function topWorkers(limit = 8) {
  return db.prepare(`
    SELECT u.id, u.name,
      COUNT(*) AS approved,
      COALESCE(SUM(l.amount), 0) AS earned
    FROM submissions s
    JOIN users u ON u.id = s.worker_id
    LEFT JOIN ledger l ON l.kind = 'task_earning' AND l.ref_type = 'submission' AND l.ref_id = s.id
    WHERE s.status = 'approved'
    GROUP BY u.id ORDER BY approved DESC LIMIT ?
  `).all(limit);
}

function topBuyers(limit = 8) {
  return db.prepare(`
    SELECT u.id, u.name,
      COUNT(DISTINCT j.id) AS jobs,
      COALESCE(SUM(e.held), 0) AS funded
    FROM users u
    JOIN jobs j ON j.merchant_id = u.id
    LEFT JOIN escrow e ON e.job_id = j.id
    GROUP BY u.id ORDER BY funded DESC LIMIT ?
  `).all(limit);
}

module.exports = {
  people, money, work, queue, series,
  buyerBehaviour, buyers, topWorkers, topBuyers,
  daysAgo,
};
