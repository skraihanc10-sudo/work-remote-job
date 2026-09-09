/* ---------------------------------------------------------------------------
   Top boost.

   A buyer pays to have one job sit at the top of the list for one day. Five
   slots a day, first come first served, and when a day is full the only
   answer is another day - which is the whole point. A queue that always has
   room is not worth paying for.

   Two things this file is careful about:

   The slot count and the charge happen in one transaction. Checking "are
   there slots left" and then taking the money as a second step means two
   buyers who press at the same moment both see four taken and both get in,
   and the day ends with six boosts on a five-slot page. The count is taken
   inside BEGIN IMMEDIATE, so the second one waits and then loses honestly.

   The day is a plain UTC date string. "Today" has to mean the same thing to
   the buyer paying, the worker browsing and the admin looking at the books,
   and the only way that holds is if nobody's clock decides it.
   --------------------------------------------------------------------------- */

const { db, numSetting, getSetting } = require('./db');
const money = require('./money');

// UTC, and only ever UTC. See the note above.
function today() {
  return new Date().toISOString().slice(0, 10);
}

function addDays(day, n) {
  const d = new Date(day + 'T00:00:00Z');
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}

function slotsPerDay() {
  return Math.max(0, numSetting('boost_slots_per_day'));
}

/* What a boost costs, in local currency.

   Priced in dollars because that is the figure buyers are quoted everywhere
   else on the site, but charged in taka against a balance held in taka. The
   conversion happens here so one rounding rule applies rather than three. */
function fee() {
  const usdCents = numSetting('boost_fee_usd');
  const rate = numSetting('usd_rate');            // local units per dollar
  return Math.round((usdCents * rate) / 100);
}

function feeUsdLabel() {
  return '$' + (numSetting('boost_fee_usd') / 100).toFixed(2);
}

function takenOn(day) {
  return db.prepare('SELECT COUNT(*) AS n FROM boosts WHERE day = ?').get(day).n;
}

function freeOn(day) {
  return Math.max(0, slotsPerDay() - takenOn(day));
}

/* The next few days and how full each one is, for the buyer choosing when.

   Today is included even when it is full: "today is gone, tomorrow has five"
   is the answer somebody needs, and hiding today makes the page look like it
   simply starts tomorrow for no reason.
*/
function calendar(days = 7) {
  const start = today();
  const out = [];
  for (let i = 0; i < days; i++) {
    const day = addDays(start, i);
    const taken = takenOn(day);
    out.push({
      day,
      taken,
      free: Math.max(0, slotsPerDay() - taken),
      isToday: i === 0,
    });
  }
  return out;
}

// The boosted jobs for a day, oldest booking first - whoever paid first is
// top, which is the only ordering nobody can argue with.
function liveFor(day) {
  return db.prepare(`
    SELECT b.*, j.title, j.rate, j.slots, j.slots_filled, j.status, j.category_id,
           u.name AS merchant_name
    FROM boosts b
    JOIN jobs j ON j.id = b.job_id
    JOIN users u ON u.id = j.merchant_id
    WHERE b.day = ? AND j.status = 'active' AND j.slots_filled < j.slots
    ORDER BY b.id
  `).all(day);
}

function live() {
  return liveFor(today());
}

// Which of a buyer's jobs are already booked, and for when.
function forJob(jobId) {
  return db.prepare('SELECT * FROM boosts WHERE job_id = ? AND day >= ? ORDER BY day')
    .all(jobId, today());
}

function isBoostedToday(jobId) {
  return !!db.prepare('SELECT 1 FROM boosts WHERE job_id = ? AND day = ?').get(jobId, today());
}

/* Buy a slot.

   Throws with something the buyer can act on, because every one of these is a
   thing they can fix: add funds, pick another day, wait for the job to be
   approved.
*/
function book(jobId, merchantId, day) {
  const when = String(day || today());
  if (!/^\d{4}-\d{2}-\d{2}$/.test(when)) throw new Error('Pick a day.');
  if (when < today()) throw new Error('That day has already passed.');

  const cost = fee();

  db.exec('BEGIN IMMEDIATE');
  try {
    const job = db.prepare('SELECT * FROM jobs WHERE id = ? AND merchant_id = ?')
      .get(jobId, merchantId);
    if (!job) throw new Error('That job is not yours.');

    // Boosting a job nobody can take would be selling a place in a queue that
    // goes nowhere.
    if (job.status !== 'active') {
      throw new Error(job.approved_at
        ? 'That job is not live, so there is nothing to boost.'
        : 'That job is still waiting for approval. Boost it once it is live.');
    }
    if (job.slots_filled >= job.slots) throw new Error('That job is already full.');

    if (db.prepare('SELECT 1 FROM boosts WHERE day = ? AND job_id = ?').get(when, jobId)) {
      throw new Error('That job is already boosted for that day.');
    }

    const taken = db.prepare('SELECT COUNT(*) AS n FROM boosts WHERE day = ?').get(when).n;
    if (taken >= slotsPerDay()) {
      throw new Error(`All ${slotsPerDay()} boost slots for ${when} are taken. Pick another day.`);
    }

    if (money.balance(merchantId) < cost) {
      throw new Error(`A boost costs ${money.fmt(cost)} and your balance is `
        + `${money.fmt(money.balance(merchantId))}. Add funds first.`);
    }

    const info = db.prepare(
      'INSERT INTO boosts (job_id, merchant_id, day, amount) VALUES (?, ?, ?, ?)'
    ).run(jobId, merchantId, when, cost);
    const id = Number(info.lastInsertRowid);

    // The fee leaves the buyer and lands in the platform account, like any
    // other money - so the books still balance afterwards.
    money.entry(merchantId, 'boost_fee', -cost, { type: 'boost', id },
      `Top boost for "${job.title}" on ${when}`);
    money.entry(money.platformUserId(), 'boost_income', cost, { type: 'boost', id },
      `Boost fee from job #${jobId} for ${when}`);

    db.exec('COMMIT');
    return { id, day: when, amount: cost };
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

/* Cancel a booking that has not started yet, and give the money back.

   Only a future day: once a day has begun the position has been occupying the
   top of the page, and refunding something already delivered is not a refund.
*/
function cancel(id, merchantId) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const b = db.prepare('SELECT * FROM boosts WHERE id = ? AND merchant_id = ?').get(id, merchantId);
    if (!b) throw new Error('That boost is not yours.');
    if (b.day <= today()) {
      throw new Error('That boost has already started, so it cannot be cancelled.');
    }

    db.prepare('DELETE FROM boosts WHERE id = ?').run(id);
    money.entry(merchantId, 'boost_refund', b.amount, { type: 'boost', id },
      `Boost cancelled for ${b.day}`);
    money.entry(money.platformUserId(), 'boost_refunded', -b.amount, { type: 'boost', id },
      `Boost refund for job #${b.job_id}`);

    db.exec('COMMIT');
    return b.amount;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

module.exports = {
  today, addDays, slotsPerDay, fee, feeUsdLabel,
  takenOn, freeOn, calendar, live, liveFor, forJob, isBoostedToday,
  book, cancel,
};
