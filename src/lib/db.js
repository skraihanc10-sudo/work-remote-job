/* ---------------------------------------------------------------------------
   Schema and migrations.

   Two rules run through all of this:

   1. Money is stored in the smallest unit as INTEGER. Never a float. A float
      balance drifts by fractions of a cent and eventually somebody's payout is
      wrong by an amount nobody can explain.

   2. Balances are never edited directly. Every movement is a row in `ledger`,
      and a user's balance is the sum of their rows. That way a disputed payout
      can always be reconstructed from the record.
   --------------------------------------------------------------------------- */

const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');

// Settings come from a .env file when there is one, so nobody has to fight
// with shell syntax - `X=1 npm start` works in bash and silently does nothing
// in PowerShell, which is a confusing first hour. Loaded here because every
// entry point reaches this file first. Real environment variables still win,
// which is what a hosting platform sets.
try {
  const envFile = path.join(__dirname, '..', '..', '.env');
  if (fs.existsSync(envFile)) process.loadEnvFile(envFile);
} catch (err) {
  console.warn('Could not read .env:', err.message);
}

const ROOT = path.join(__dirname, '..', '..');
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(ROOT, 'data');

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(path.join(DATA_DIR, 'proofs'), { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, 'wrj.db'));
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');
db.exec('PRAGMA busy_timeout = 5000');

const MIGRATIONS = [
  {
    id: 1,
    name: 'core',
    sql: `
      CREATE TABLE users (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        role           TEXT NOT NULL CHECK (role IN ('worker','merchant','admin')),
        name           TEXT NOT NULL,
        email          TEXT NOT NULL,
        password_hash  TEXT NOT NULL,
        country        TEXT,
        status         TEXT NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active','suspended','banned')),
        suspended_until TEXT,
        suspend_reason TEXT,
        strikes        INTEGER NOT NULL DEFAULT 0,
        payout_method  TEXT,
        payout_detail  TEXT,
        created_at     TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE UNIQUE INDEX idx_users_email ON users(lower(email));

      CREATE TABLE sessions (
        token      TEXT PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE categories (
        id    INTEGER PRIMARY KEY AUTOINCREMENT,
        name  TEXT NOT NULL UNIQUE,
        slug  TEXT NOT NULL UNIQUE
      );

      -- A job is a batch: one set of instructions, N identical slots.
      CREATE TABLE jobs (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        merchant_id     INTEGER NOT NULL REFERENCES users(id),
        category_id     INTEGER REFERENCES categories(id),
        title           TEXT NOT NULL,
        instructions    TEXT NOT NULL,
        proof_required  TEXT NOT NULL,
        rate            INTEGER NOT NULL,          -- per approved task
        slots           INTEGER NOT NULL,
        slots_filled    INTEGER NOT NULL DEFAULT 0,
        -- Guard against a task that can be clicked through in three seconds.
        min_seconds     INTEGER NOT NULL DEFAULT 60,
        -- How long a worker holds a slot before it returns to the pool.
        hold_minutes    INTEGER NOT NULL DEFAULT 60,
        country         TEXT,
        status          TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','paused','completed','cancelled')),
        created_at      TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_jobs_status ON jobs(status, id DESC);
      CREATE INDEX idx_jobs_merchant ON jobs(merchant_id);

      -- One row the moment a worker starts. started_at is what makes the
      -- "too fast to be real" check possible, so it is written up front and
      -- never by the client.
      CREATE TABLE submissions (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id        INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        worker_id     INTEGER NOT NULL REFERENCES users(id),
        merchant_id   INTEGER NOT NULL REFERENCES users(id),
        status        TEXT NOT NULL DEFAULT 'started'
                      CHECK (status IN ('started','submitted','approved','rejected','expired')),
        proof_text    TEXT,
        proof_file    TEXT,
        seconds_spent INTEGER,
        started_at    TEXT NOT NULL DEFAULT (datetime('now')),
        submitted_at  TEXT,
        reviewed_at   TEXT,
        review_note   TEXT,
        flagged       INTEGER NOT NULL DEFAULT 0,
        flag_reason   TEXT
      );
      -- The rule that matters most: one worker, one job, once. Ever.
      CREATE UNIQUE INDEX idx_sub_once ON submissions(job_id, worker_id);
      CREATE INDEX idx_sub_worker_day ON submissions(worker_id, started_at);
      CREATE INDEX idx_sub_review ON submissions(merchant_id, status);

      -- Every movement of money. Balance = SUM(amount) for a user.
      CREATE TABLE ledger (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL REFERENCES users(id),
        kind       TEXT NOT NULL,
        amount     INTEGER NOT NULL,       -- signed, smallest currency unit
        ref_type   TEXT,
        ref_id     INTEGER,
        note       TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_ledger_user ON ledger(user_id, id DESC);

      -- Money committed to a job and not yet paid out or returned.
      CREATE TABLE escrow (
        job_id     INTEGER PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
        held       INTEGER NOT NULL DEFAULT 0,
        released   INTEGER NOT NULL DEFAULT 0,
        refunded   INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE deposits (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL REFERENCES users(id),
        amount      INTEGER NOT NULL,
        method      TEXT NOT NULL,
        reference   TEXT,
        status      TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','approved','rejected')),
        note        TEXT,
        created_at  TEXT NOT NULL DEFAULT (datetime('now')),
        reviewed_at TEXT
      );

      CREATE TABLE withdrawals (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL REFERENCES users(id),
        amount      INTEGER NOT NULL,
        method      TEXT NOT NULL,
        detail      TEXT,
        status      TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','paid','rejected')),
        note        TEXT,
        created_at  TEXT NOT NULL DEFAULT (datetime('now')),
        reviewed_at TEXT
      );

      CREATE TABLE reports (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        reporter_id   INTEGER NOT NULL REFERENCES users(id),
        against_id    INTEGER NOT NULL REFERENCES users(id),
        submission_id INTEGER REFERENCES submissions(id) ON DELETE SET NULL,
        job_id        INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
        reason        TEXT NOT NULL,
        detail        TEXT,
        status        TEXT NOT NULL DEFAULT 'open'
                      CHECK (status IN ('open','upheld','dismissed')),
        outcome       TEXT,
        created_at    TEXT NOT NULL DEFAULT (datetime('now')),
        reviewed_at   TEXT
      );
      CREATE INDEX idx_reports_status ON reports(status, id DESC);

      -- Anything an admin would want to reconstruct later.
      CREATE TABLE audit (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_id   INTEGER,
        action     TEXT NOT NULL,
        subject    TEXT,
        detail     TEXT,
        ip         TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_audit_created ON audit(id DESC);

      CREATE TABLE settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `,
  },
  {
    id: 2,
    name: 'google sign-in, device history, support',
    sql: `
      -- Sign-in is Google-only now. password_hash stays for the column's sake
      -- but is never written; identity is the Google account id.
      ALTER TABLE users ADD COLUMN google_sub TEXT;
      ALTER TABLE users ADD COLUMN avatar TEXT;
      ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;
      ALTER TABLE users ADD COLUMN signup_ip TEXT;
      ALTER TABLE users ADD COLUMN last_ip TEXT;
      ALTER TABLE users ADD COLUMN last_seen_at TEXT;
      ALTER TABLE users ADD COLUMN ip_notice_at TEXT;
      CREATE UNIQUE INDEX idx_users_google ON users(google_sub) WHERE google_sub IS NOT NULL;

      -- Every sign-in, so an admin can see the pattern rather than a single
      -- snapshot. Shared IPs are normal here; this is evidence, not a verdict.
      CREATE TABLE logins (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        ip         TEXT,
        user_agent TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_logins_ip ON logins(ip, created_at);
      CREATE INDEX idx_logins_user ON logins(user_id, id DESC);

      -- Support conversations. Polled rather than websockets: a support queue
      -- of this size does not need a socket per visitor.
      CREATE TABLE tickets (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        subject    TEXT NOT NULL,
        topic      TEXT,
        status     TEXT NOT NULL DEFAULT 'open'
                   CHECK (status IN ('open','answered','closed')),
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_tickets_user ON tickets(user_id, id DESC);
      CREATE INDEX idx_tickets_status ON tickets(status, updated_at DESC);

      CREATE TABLE ticket_messages (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id  INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
        sender_id  INTEGER REFERENCES users(id),
        from_staff INTEGER NOT NULL DEFAULT 0,
        body       TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_tmsg_ticket ON ticket_messages(ticket_id, id);

      CREATE TABLE notices (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        kind       TEXT NOT NULL,
        title      TEXT NOT NULL,
        body       TEXT NOT NULL,
        seen_at    TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_notices_user ON notices(user_id, seen_at, id DESC);
    `,
  },
  {
    id: 3,
    name: 'gateway deposits',
    sql: `
      -- Which gateway a deposit came through, and the identifiers needed to ask
      -- that gateway what really happened.
      ALTER TABLE deposits ADD COLUMN provider TEXT NOT NULL DEFAULT 'manual';
      ALTER TABLE deposits ADD COLUMN provider_ref TEXT;
      ALTER TABLE deposits ADD COLUMN provider_status TEXT;
      ALTER TABLE deposits ADD COLUMN pay_url TEXT;
      ALTER TABLE deposits ADD COLUMN charged_amount TEXT;
      ALTER TABLE deposits ADD COLUMN charged_currency TEXT;
      ALTER TABLE deposits ADD COLUMN credited_at TEXT;
      -- One gateway reference can only ever belong to one deposit. This index
      -- is what makes a replayed webhook harmless.
      CREATE UNIQUE INDEX idx_dep_ref ON deposits(provider, provider_ref)
        WHERE provider_ref IS NOT NULL;
      CREATE INDEX idx_dep_status ON deposits(status, id DESC);

      -- Every callback, verified or not, kept as received. When a payment is
      -- disputed this is the only record of what the gateway actually said.
      CREATE TABLE gateway_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        provider    TEXT NOT NULL,
        deposit_id  INTEGER REFERENCES deposits(id) ON DELETE SET NULL,
        ref         TEXT,
        verified    INTEGER NOT NULL DEFAULT 0,
        status      TEXT,
        payload     TEXT NOT NULL,
        ip          TEXT,
        created_at  TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_gwe_deposit ON gateway_events(deposit_id, id DESC);
      CREATE INDEX idx_gwe_created ON gateway_events(id DESC);
    `,
  },
  {
    id: 4,
    name: 'role requests and testimonials',
    sql: `
      -- Switching side is no longer instant. A request is reviewed by an
      -- admin, so somebody cannot quietly become a buyer to work around a
      -- history, and so a real buyer can be looked at before they are trusted
      -- with a funded job.
      CREATE TABLE role_requests (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        from_role   TEXT NOT NULL,
        to_role     TEXT NOT NULL,
        reason      TEXT,
        status      TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','approved','rejected','withdrawn')),
        admin_note  TEXT,
        reviewed_by INTEGER REFERENCES users(id),
        created_at  TEXT NOT NULL DEFAULT (datetime('now')),
        reviewed_at TEXT
      );
      -- One open request at a time, so the queue cannot be flooded.
      CREATE UNIQUE INDEX idx_rolereq_open ON role_requests(user_id)
        WHERE status = 'pending';
      CREATE INDEX idx_rolereq_status ON role_requests(status, id DESC);

      -- What the home page shows. Editable by an admin rather than hard-coded,
      -- so the demo entries can be swapped for real ones without a deploy.
      CREATE TABLE testimonials (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT NOT NULL,
        role       TEXT,
        body       TEXT NOT NULL,
        earned     TEXT,
        is_demo    INTEGER NOT NULL DEFAULT 1,
        visible    INTEGER NOT NULL DEFAULT 1,
        sort       INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_testi_visible ON testimonials(visible, sort);
    `,
  },
  {
    id: 5,
    name: 'referrals',
    sql: `
      ALTER TABLE users ADD COLUMN ref_code TEXT;
      ALTER TABLE users ADD COLUMN referred_by INTEGER REFERENCES users(id);
      CREATE UNIQUE INDEX idx_users_refcode ON users(ref_code) WHERE ref_code IS NOT NULL;
      CREATE INDEX idx_users_referred ON users(referred_by);

      -- Every referral payment, with what caused it. Kept separate from the
      -- ledger so "what has this person earned from referrals" is one indexed
      -- query rather than a scan of every money row they have.
      CREATE TABLE referral_earnings (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        referrer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        referred_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        kind        TEXT NOT NULL CHECK (kind IN ('task','deposit')),
        source_id   INTEGER,
        basis       INTEGER NOT NULL,
        amount      INTEGER NOT NULL,
        created_at  TEXT NOT NULL DEFAULT (datetime('now'))
      );
      -- One payment per source event, so a retried approval cannot pay twice.
      CREATE UNIQUE INDEX idx_ref_once ON referral_earnings(kind, source_id);
      CREATE INDEX idx_ref_referrer ON referral_earnings(referrer_id, id DESC);
    `,
  },
  {
    id: 6,
    name: 'review deadline, worker levels, buyer ratings',
    sql: `
      -- How long a buyer has to review a submission before it approves itself.
      -- Without this a buyer can simply never look, and the worker waits
      -- forever with their money sitting in escrow. It is the single biggest
      -- unfairness these marketplaces have, and a deadline is the fix.
      ALTER TABLE jobs ADD COLUMN ttr_days INTEGER NOT NULL DEFAULT 7;
      -- Minimum worker level a job will accept.
      ALTER TABLE jobs ADD COLUMN min_level INTEGER NOT NULL DEFAULT 0;

      ALTER TABLE submissions ADD COLUMN auto_approved INTEGER NOT NULL DEFAULT 0;
      CREATE INDEX idx_sub_pending ON submissions(status, submitted_at);

      -- Workers rate the buyer after a decision. A marketplace where only one
      -- side is rated gives the other side no reason to behave.
      CREATE TABLE buyer_ratings (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        merchant_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        worker_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        submission_id INTEGER NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
        stars         INTEGER NOT NULL CHECK (stars BETWEEN 1 AND 5),
        comment       TEXT,
        created_at    TEXT NOT NULL DEFAULT (datetime('now'))
      );
      -- One rating per submission, so nobody can pile on.
      CREATE UNIQUE INDEX idx_brate_once ON buyer_ratings(submission_id);
      CREATE INDEX idx_brate_merchant ON buyer_ratings(merchant_id, id DESC);

      -- Ready-made instructions for common job types. Vague instructions cause
      -- most rejections, so the fastest way to reduce them is to stop asking
      -- buyers to write from a blank box.
      CREATE TABLE job_templates (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        category_id  INTEGER REFERENCES categories(id),
        name         TEXT NOT NULL,
        title        TEXT NOT NULL,
        instructions TEXT NOT NULL,
        proof        TEXT NOT NULL,
        min_seconds  INTEGER NOT NULL DEFAULT 60,
        sort         INTEGER NOT NULL DEFAULT 0
      );
    `,
  },
  {
    id: 7,
    name: 'password sign-in, email verification, mail outbox',
    sql: `
      -- Sign-in by username as well as email. Kept separate from the display
      -- name: a name can be anything and change freely, a username is the
      -- handle you log in with and must be unique.
      ALTER TABLE users ADD COLUMN username TEXT;
      CREATE UNIQUE INDEX idx_user_username ON users(lower(username))
        WHERE username IS NOT NULL;

      -- Whether we may send this person anything beyond the essentials.
      -- Receipts and security mail ignore it; announcements do not.
      ALTER TABLE users ADD COLUMN email_opt_out INTEGER NOT NULL DEFAULT 0;

      /* One-time links: confirm an address, or reset a password.

         Stored as a hash, never the token itself. If this table leaks, the
         rows in it cannot be used to take an account over - which is the
         whole point, because a reset token is a password while it lives.
      */
      CREATE TABLE email_tokens (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        kind       TEXT NOT NULL,          -- 'verify' | 'reset'
        token_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at    TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE UNIQUE INDEX idx_token_hash ON email_tokens(token_hash);
      CREATE INDEX idx_token_user ON email_tokens(user_id, kind);

      /* Every message we send, queued before it is sent.

         Mail goes in here inside the same transaction as the thing it is
         about, and a separate sweep delivers it. That ordering matters: a
         mail server being slow or down must never roll back a payment, and a
         payment that committed must never lose its receipt.
      */
      CREATE TABLE mail_outbox (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
        to_email     TEXT NOT NULL,
        subject      TEXT NOT NULL,
        body         TEXT NOT NULL,
        kind         TEXT NOT NULL,
        status       TEXT NOT NULL DEFAULT 'queued',   -- queued|sent|failed
        attempts     INTEGER NOT NULL DEFAULT 0,
        last_error   TEXT,
        created_at   TEXT NOT NULL DEFAULT (datetime('now')),
        sent_at      TEXT
      );
      CREATE INDEX idx_mail_queued ON mail_outbox(status, id);
      CREATE INDEX idx_mail_user ON mail_outbox(user_id, id DESC);

      /* Failed sign-ins, so a password can be rate limited.

         Google sign-in needed nothing like this because there was no secret
         here to guess. A password changes that: without a limit, an account
         with a weak password is taken in an afternoon.
      */
      CREATE TABLE login_attempts (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        identifier TEXT NOT NULL,
        ip         TEXT,
        ok         INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_attempt_id ON login_attempts(identifier, created_at);
      CREATE INDEX idx_attempt_ip ON login_attempts(ip, created_at);
    `,
  },
  {
    id: 8,
    name: 'payout details, cancelling a withdrawal, payment proof, monthly prize',
    sql: `
      /* Where a withdrawal is actually going.

         One free-text "where to send it" box was not enough. A bKash number
         with no account name against it cannot be checked before sending, and
         a bank transfer needs four separate things that do not fit in one
         line. Each is its own column so an admin can read them without
         guessing which half of a sentence is the account number. */
      ALTER TABLE withdrawals ADD COLUMN account_name TEXT;
      ALTER TABLE withdrawals ADD COLUMN account_number TEXT;
      ALTER TABLE withdrawals ADD COLUMN bank_name TEXT;
      ALTER TABLE withdrawals ADD COLUMN branch TEXT;

      -- The screenshot an admin uploads after actually sending the money.
      ALTER TABLE withdrawals ADD COLUMN proof_file TEXT;

      -- Withdrawn by the person themselves, while it was still waiting.
      ALTER TABLE withdrawals ADD COLUMN cancelled_at TEXT;

      CREATE INDEX idx_wd_pending ON withdrawals(status, id DESC);

      /* Payout details worth remembering, so nobody retypes their account
         number every time. Filled from the last withdrawal they made. */
      ALTER TABLE users ADD COLUMN payout_name TEXT;
      ALTER TABLE users ADD COLUMN payout_bank TEXT;
      ALTER TABLE users ADD COLUMN payout_branch TEXT;

      /* The monthly prize.

         One row per month per winner, written when an admin awards it, so the
         same month cannot be paid twice and last month's winners stay on
         record after the leaderboard has moved on. */
      CREATE TABLE prizes (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        month       TEXT NOT NULL,              -- 'YYYY-MM'
        place       INTEGER NOT NULL,           -- 1, 2 or 3
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount      INTEGER NOT NULL,
        earned      INTEGER NOT NULL,           -- what they earned that month
        awarded_by  INTEGER REFERENCES users(id),
        created_at  TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE UNIQUE INDEX idx_prize_once ON prizes(month, place);
      CREATE INDEX idx_prize_user ON prizes(user_id, id DESC);
    `,
  },
  {
    id: 9,
    name: 'allow a cancelled withdrawal',
    sql: `
      /* Rebuild withdrawals so 'cancelled' is an allowed status.

         SQLite cannot alter a CHECK constraint, so the table is remade and the
         rows copied across. Done as its own migration rather than by widening
         migration 8, because 8 has already run on the live database and an
         applied migration must never change under a deployment's feet.
      */
      CREATE TABLE withdrawals_new (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id        INTEGER NOT NULL REFERENCES users(id),
        amount         INTEGER NOT NULL,
        method         TEXT NOT NULL,
        detail         TEXT,
        status         TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','paid','rejected','cancelled')),
        note           TEXT,
        account_name   TEXT,
        account_number TEXT,
        bank_name      TEXT,
        branch         TEXT,
        proof_file     TEXT,
        cancelled_at   TEXT,
        created_at     TEXT NOT NULL DEFAULT (datetime('now')),
        reviewed_at    TEXT
      );

      INSERT INTO withdrawals_new
        (id, user_id, amount, method, detail, status, note,
         account_name, account_number, bank_name, branch, proof_file, cancelled_at,
         created_at, reviewed_at)
      SELECT id, user_id, amount, method, detail, status, note,
             account_name, account_number, bank_name, branch, proof_file, cancelled_at,
             created_at, reviewed_at
      FROM withdrawals;

      DROP TABLE withdrawals;
      ALTER TABLE withdrawals_new RENAME TO withdrawals;
      CREATE INDEX idx_wd_pending ON withdrawals(status, id DESC);
      CREATE INDEX idx_wd_user ON withdrawals(user_id, id DESC);
    `,
  },
];

db.exec(`CREATE TABLE IF NOT EXISTS migrations (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL,
  applied_at TEXT NOT NULL DEFAULT (datetime('now')))`);

const applied = new Set(db.prepare('SELECT id FROM migrations').all().map(r => r.id));
for (const m of MIGRATIONS) {
  if (applied.has(m.id)) continue;
  db.exec('BEGIN');
  try {
    db.exec(m.sql);
    db.prepare('INSERT INTO migrations (id, name) VALUES (?, ?)').run(m.id, m.name);
    db.exec('COMMIT');
    console.log(`  migration ${m.id} applied: ${m.name}`);
  } catch (err) {
    db.exec('ROLLBACK');
    throw new Error(`Migration ${m.id} failed: ${err.message}`);
  }
}

// ------------------------------------------------------------------ settings
const DEFAULTS = {
  currency: 'BDT',
  currency_symbol: '৳',
  // Commission the platform keeps from each approved task, in basis points.
  commission_bps: '1000',
  min_withdrawal: '10000',
  // Anti-spam limits. Every one of these is enforced server-side.
  max_tasks_per_day: '25',
  max_tasks_per_merchant_per_day: '3',
  min_seconds_floor: '20',
  auto_suspend_rejects: '5',
  auto_suspend_window_days: '3',
  strikes_before_suspend: '3',
  suspend_days: '7',
  // Accounts seen from one IP before the people on it are told about it.
  // A warning, never a block: shared connections are normal.
  ip_accounts_warn: '3',
  telegram_channel: '',
  telegram_support: '',
  // Crypto is priced in USD; this converts to the site's own currency.
  // It is a manual rate on purpose - a wrong automatic one silently mispays
  // everybody, and this changes slowly enough to set by hand.
  usd_rate: '12000',
  min_deposit: '10000',
  /* The smallest deposit, in US cents.

     Deposits are chosen in dollars whichever way somebody pays, because the
     crypto side is priced in dollars and quoting two different minimums for
     the same page only confuses people. 100 = $1.00. */
  min_deposit_usd: '100',
  // Referral rewards. Both are paid out of the platform's own commission, never
  // out of what the worker or the buyer receives - a scheme funded by shaving
  // somebody else's earnings is not a reward, it is a transfer.
  // Share of our fee on a referred worker's approved task:
  referral_task_bps: '1500',
  /* Paid once, to the referrer, the first time somebody they invited has work
     approved. A flat amount is what was promised on the referral page, and a
     promise of "twenty taka" that pays a percentage of something invisible is
     not a promise anybody can check. Still funded out of our commission. */
  referral_flat: '2000',         // 20
  // Share of a referred buyer's deposit:
  referral_deposit_bps: '100',
  // Review deadline, in days. A buyer who does not decide inside this window
  // has the submission approved for them and the worker paid.
  default_ttr_days: '7',
  max_ttr_days: '14',
  // Worker levels: tasks approved needed for each, and the satisfaction rate
  // that must be held to stay there.
  /* Worker levels, by what they have actually earned from approved work.

     Earnings rather than a count of tasks: a hundred tasks worth five taka
     each is not the same standing as twenty worth two hundred, and the number
     people care about is the one in their wallet. Stored in paisa. */
  level_silver: '100000',        // 1,000
  level_gold: '500000',          // 5,000
  level_maxgold: '2000000',      // 20,000
  // A level still has to be held with decent work, so a poor satisfaction
  // rate keeps somebody at New however much they have earned.
  level_min_rate: '80',

  /* The monthly prize for the busiest workers, and what it takes to enter. */
  prize_first: '300000',         // 3,000
  prize_second: '200000',        // 2,000
  prize_third: '100000',         // 1,000
  prize_min_earned: '100000',    // 1,000 earned that month to qualify

  // Where support actually happens. Every one of these is optional and is
  // hidden everywhere on the site until it is filled in, so a half-configured
  // install never shows a dead link.
  /* Meta tags that prove we own the domain, one `name=value` per line.

     Cryptomus, Google Search Console, Facebook and Bing all work this way. Put
     here rather than in the code so adding one is a save, not a deploy. */
  verify_meta: '',

  whatsapp_number: '',
  whatsapp_text: 'Hello, I need help with my Remote Work BD account.',
  facebook_page: '',
  facebook_group: '',
  telegram_group: '',
  live_chat_url: '',
  support_hours: '10:00 - 22:00, seven days a week (Dhaka time)',

  /* Outgoing mail.

     On by default, because "on" here only means "send once there is somewhere
     to send through": nothing goes out until smtp_host and mail_from are also
     filled in. Two switches to flip meant people configured SMTP correctly,
     saw nothing arrive, and had no idea a separate toggle was still off.
     Set it to 0 to deliberately hold all mail while leaving SMTP configured. */
  mail_enabled: '1',
  mail_from_name: 'Remote Work BD',
  mail_from: '',
  smtp_host: '',
  smtp_port: '587',
  smtp_user: '',
  smtp_pass: '',
  // Which non-essential mail goes out. Receipts and security mail always do.
  mail_on_signup: '1',
  mail_on_task_submitted: '1',
  mail_on_task_decided: '1',
  mail_on_deposit: '1',
  mail_on_withdrawal: '1',
};

function getSetting(key, fallback = null) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  if (row) return row.value;
  if (key in DEFAULTS) return DEFAULTS[key];
  return fallback;
}

function setSetting(key, value) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run(key, String(value));
}

function numSetting(key) {
  return Number(getSetting(key));
}

function audit(actorId, action, subject, detail, ip) {
  db.prepare('INSERT INTO audit (actor_id, action, subject, detail, ip) VALUES (?, ?, ?, ?, ?)')
    .run(actorId || null, action, subject || null,
         detail ? (typeof detail === 'string' ? detail : JSON.stringify(detail)) : null, ip || null);
}

// Seed categories once so a fresh install is not an empty dropdown.
if (!db.prepare('SELECT COUNT(*) AS n FROM categories').get().n) {
  const insert = db.prepare('INSERT INTO categories (name, slug) VALUES (?, ?)');
  [
    ['Sign up', 'sign-up'],
    ['App install', 'app-install'],
    ['Social media', 'social-media'],
    ['YouTube', 'youtube'],
    ['Search & click', 'search-click'],
    ['Review & rating', 'review-rating'],
    ['Survey', 'survey'],
    ['Data entry', 'data-entry'],
    ['Other', 'other'],
  ].forEach(c => insert.run(c[0], c[1]));
}

module.exports = { db, DATA_DIR, getSetting, setSetting, numSetting, audit, DEFAULTS };
