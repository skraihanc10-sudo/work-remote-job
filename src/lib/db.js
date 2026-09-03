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
