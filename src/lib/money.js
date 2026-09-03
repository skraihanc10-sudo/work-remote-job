/* ---------------------------------------------------------------------------
   Money.

   Balances are never stored. A user's balance is SUM(ledger.amount) for that
   user, so the number on screen and the history behind it can never disagree.

   Posting a job moves money out of the merchant's balance and into escrow.
   Approving a task moves it from escrow to the worker. Cancelling returns what
   is left. At no point does money exist in two places, and at no point can a
   merchant spend what is already promised to workers.
   --------------------------------------------------------------------------- */

const { db, numSetting, getSetting } = require('./db');

// --------------------------------------------------------------- formatting
function parseAmount(input) {
  // Accepts "12", "12.50", "১২" is not attempted - keep input plain.
  const clean = String(input == null ? '' : input).trim().replace(/,/g, '');
  if (!/^\d+(\.\d{1,2})?$/.test(clean)) return null;
  return Math.round(Number(clean) * 100);
}

function fmt(units) {
  const sym = getSetting('currency_symbol');
  const n = (units || 0) / 100;
  return sym + n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

// ------------------------------------------------------------------ balance
function balance(userId) {
  const row = db.prepare('SELECT COALESCE(SUM(amount), 0) AS bal FROM ledger WHERE user_id = ?').get(userId);
  return Number(row.bal) || 0;
}

function entry(userId, kind, amount, ref, note) {
  db.prepare(
    'INSERT INTO ledger (user_id, kind, amount, ref_type, ref_id, note) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(userId, kind, amount, (ref && ref.type) || null, (ref && ref.id) || null, note || null);
}

function history(userId, limit = 60) {
  return db.prepare(
    'SELECT * FROM ledger WHERE user_id = ? ORDER BY id DESC LIMIT ?'
  ).all(userId, limit);
}

// ----------------------------------------------------------- admin adjust
/* An admin moving money into or out of somebody's balance by hand.

   This is the one place in the system where money appears without a payment
   behind it, so everything about it is built to be answerable later:

   - it is a normal ledger row, so it shows in the person's own wallet history
     exactly like anything else - nothing is hidden from the account holder
   - the reason is required and stored, and it is shown to them
   - who did it is recorded in the row and in the audit log
   - a deduction can never push somebody below zero, because a negative balance
     is not a state the rest of the system knows how to reason about

   It exists because real support work needs it: a payment that arrived outside
   the gateway, a mistaken rejection to put right, a bonus. What it must never
   become is a quiet way to change the books.
*/
function adjustBalance({ userId, amount, reason, adminId, note }) {
  if (!Number.isInteger(amount) || amount === 0) {
    throw new Error('Enter an amount to add or take away');
  }
  if (!reason || String(reason).trim().length < 5) {
    throw new Error('Give a reason - the account holder sees it in their wallet');
  }

  db.exec('BEGIN IMMEDIATE');
  try {
    const user = db.prepare('SELECT id, name FROM users WHERE id = ?').get(userId);
    if (!user) throw new Error('No such account');

    const before = balance(userId);
    if (amount < 0 && before + amount < 0) {
      throw new Error(
        `That would take ${user.name} to ${fmt(before + amount)}. Their balance is ${fmt(before)}.`
      );
    }

    entry(userId, amount > 0 ? 'admin_credit' : 'admin_debit', amount,
          { type: 'admin', id: adminId || null },
          (amount > 0 ? 'Added by support: ' : 'Deducted by support: ') + String(reason).trim());

    db.exec('COMMIT');
    return { before, after: before + amount, amount };
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

// ------------------------------------------------------------------ deposit
/* Credit a gateway deposit exactly once.

   Everything about this function exists to survive the two things that always
   happen in production: the same webhook arriving three times, and a webhook
   arriving at the same moment somebody presses the "check payment" button.

   The guard is the status transition itself, inside an immediate transaction:
   only a row still marked pending can move to approved, and only the winner of
   that race writes a ledger entry. A replay finds nothing pending and does
   nothing at all.

   The amount credited is the one recorded on our own deposit row, decided when
   the payment was created - never a number taken from the callback, because a
   callback is only as trustworthy as its signature and this is the one place
   where being wrong costs money.
*/
function creditGatewayDeposit(depositId, providerStatus, chargedAmount, chargedCurrency) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const dep = db.prepare("SELECT * FROM deposits WHERE id = ? AND status = 'pending'").get(depositId);
    if (!dep) {
      db.exec('COMMIT');
      return { credited: false, reason: 'not pending' };
    }

    db.prepare(`UPDATE deposits SET status = 'approved', provider_status = ?,
                charged_amount = ?, charged_currency = ?,
                reviewed_at = datetime('now'), credited_at = datetime('now')
                WHERE id = ?`)
      .run(providerStatus || null, chargedAmount || null, chargedCurrency || null, depositId);

    entry(dep.user_id, 'deposit', dep.amount, { type: 'deposit', id: depositId },
          `Deposit via ${dep.provider === 'manual' ? dep.method : dep.provider}`);

    const referrals = require('./referrals');
    referrals.reward({
      kind: 'deposit', sourceId: depositId, referredId: dep.user_id, basis: dep.amount,
    });

    db.exec('COMMIT');
    return { credited: true, userId: dep.user_id, amount: dep.amount };
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function failDeposit(depositId, providerStatus) {
  db.prepare(`UPDATE deposits SET status = 'rejected', provider_status = ?,
              reviewed_at = datetime('now') WHERE id = ? AND status = 'pending'`)
    .run(providerStatus || null, depositId);
}

function creditDeposit(depositId, adminId) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const dep = db.prepare("SELECT * FROM deposits WHERE id = ? AND status = 'pending'").get(depositId);
    if (!dep) throw new Error('That deposit is not pending');

    db.prepare("UPDATE deposits SET status = 'approved', reviewed_at = datetime('now') WHERE id = ?")
      .run(depositId);
    entry(dep.user_id, 'deposit', dep.amount, { type: 'deposit', id: depositId },
          `Deposit via ${dep.method}`);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

// ------------------------------------------------------- job funding/escrow
// Called inside the job-creation transaction.
function fundJob(jobId, merchantId, total) {
  if (balance(merchantId) < total) {
    throw new Error('Not enough balance. Add funds first.');
  }
  entry(merchantId, 'job_hold', -total, { type: 'job', id: jobId }, `Funded job #${jobId}`);
  db.prepare('INSERT INTO escrow (job_id, held) VALUES (?, ?)').run(jobId, total);
}

function escrowOf(jobId) {
  return db.prepare('SELECT * FROM escrow WHERE job_id = ?').get(jobId)
    || { job_id: jobId, held: 0, released: 0, refunded: 0 };
}

function escrowRemaining(jobId) {
  const e = escrowOf(jobId);
  return e.held - e.released - e.refunded;
}

/* The platform's own account. Fees are credited to it like any other money,
   so every unit that leaves escrow lands somewhere and the books balance. */
function platformUserId() {
  const row = db.prepare("SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1").get();
  if (!row) throw new Error('No platform account exists yet. Run the seed script first.');
  return row.id;
}

/* Approve one submission: escrow -> worker, minus commission.
   Runs inside the caller's transaction. */
function payForSubmission(sub, job) {
  const remaining = escrowRemaining(job.id);
  if (remaining < job.rate) {
    throw new Error('This job has no funds left to pay for that. Contact support.');
  }

  const bps = numSetting('commission_bps');
  const commission = Math.round((job.rate * bps) / 10000);
  const net = job.rate - commission;

  db.prepare('UPDATE escrow SET released = released + ? WHERE job_id = ?').run(job.rate, job.id);

  // One line in the worker's history, saying what they earned and why it is
  // less than the listed rate. A separate zero-value row for the fee would
  // read like a transaction that never happened.
  entry(sub.worker_id, 'task_earning', net, { type: 'submission', id: sub.id },
        commission > 0
          ? `Task approved - ${job.title} (${fmt(job.rate)} less ${fmt(commission)} fee)`
          : `Task approved - ${job.title}`);

  if (commission > 0) {
    entry(platformUserId(), 'platform_fee', commission, { type: 'submission', id: sub.id },
          `Fee from task #${sub.id}`);

    // Whoever brought this worker in gets a share of our fee - not a slice of
    // what the worker earned. Required late to avoid a circular require.
    const referrals = require('./referrals');
    referrals.reward({
      kind: 'task', sourceId: sub.id, referredId: sub.worker_id, basis: commission,
    });
  }
  return { gross: job.rate, commission, net };
}

/* Return whatever a job still holds to the merchant. Used when a job is
   cancelled or finishes with unfilled slots. */
function refundRemaining(jobId, reason) {
  const job = db.prepare('SELECT * FROM jobs WHERE id = ?').get(jobId);
  if (!job) return 0;
  const remaining = escrowRemaining(jobId);
  if (remaining <= 0) return 0;

  db.prepare('UPDATE escrow SET refunded = refunded + ? WHERE job_id = ?').run(remaining, jobId);
  entry(job.merchant_id, 'job_refund', remaining, { type: 'job', id: jobId },
        reason || `Unused funds returned from job #${jobId}`);
  return remaining;
}

// ---------------------------------------------------------------- withdraw
function requestWithdrawal(userId, amount, method, detail) {
  const min = numSetting('min_withdrawal');
  if (amount < min) throw new Error(`The smallest withdrawal is ${fmt(min)}`);
  if (balance(userId) < amount) throw new Error('That is more than your balance');

  db.exec('BEGIN IMMEDIATE');
  try {
    // Debit immediately so the same balance cannot be withdrawn twice while
    // the first request is still sitting in the admin queue.
    const info = db.prepare(
      'INSERT INTO withdrawals (user_id, amount, method, detail) VALUES (?, ?, ?, ?)'
    ).run(userId, amount, method, detail || null);
    const id = Number(info.lastInsertRowid);
    entry(userId, 'withdrawal_hold', -amount, { type: 'withdrawal', id }, `Withdrawal requested`);
    db.exec('COMMIT');
    return id;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function settleWithdrawal(id, approve, note) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const w = db.prepare("SELECT * FROM withdrawals WHERE id = ? AND status = 'pending'").get(id);
    if (!w) throw new Error('That withdrawal is not pending');

    if (approve) {
      db.prepare("UPDATE withdrawals SET status = 'paid', note = ?, reviewed_at = datetime('now') WHERE id = ?")
        .run(note || null, id);
    } else {
      db.prepare("UPDATE withdrawals SET status = 'rejected', note = ?, reviewed_at = datetime('now') WHERE id = ?")
        .run(note || null, id);
      entry(w.user_id, 'withdrawal_return', w.amount, { type: 'withdrawal', id },
            note ? `Withdrawal declined: ${note}` : 'Withdrawal declined');
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

module.exports = {
  parseAmount, fmt, balance, entry, history,
  adjustBalance, creditDeposit, creditGatewayDeposit, failDeposit, fundJob, escrowOf, escrowRemaining, payForSubmission, refundRemaining, platformUserId,
  requestWithdrawal, settleWithdrawal,
};
