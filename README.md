# Work Remote Job

A microjob marketplace. Buyers post batches of small tasks and fund them up
front; workers do a task, send proof, and are paid when it is approved. The
money sits in escrow in between, so a worker is never asked to trust that a
buyer will pay and a buyer never pays for work they have not seen.

```
npm install
ADMIN_PASSWORD=choose-something npm run seed -- --demo
npm start                # http://localhost:4700
```

The demo flag also creates a funded buyer and two workers to click around with:

| | |
| --- | --- |
| `buyer@example.com` | `demo12345` — merchant, funded |
| `rakib@example.com` | `demo12345` — worker |
| `nusrat@example.com` | `demo12345` — worker |

Drop `-- --demo` for a clean install with only the admin account.

---

## The two rules everything else follows from

**Money is an integer.** Amounts are stored in the smallest unit — paisa, not
taka. A float balance drifts by fractions and eventually somebody's payout is
wrong by an amount nobody can explain.

**Balances are never stored.** A balance is `SUM(ledger.amount)` for that user.
Every movement is a row, so the number on screen and the history behind it can
never disagree, and a disputed payout can always be reconstructed.

You can check the books at any time — deposits should equal all balances plus
everything still in escrow:

```
node -e "const m=require('./src/lib/money'),{db}=require('./src/lib/db');
const led=db.prepare('SELECT COALESCE(SUM(amount),0) n FROM ledger').get().n;
const esc=db.prepare('SELECT COALESCE(SUM(held-released-refunded),0) n FROM escrow').get().n;
const dep=db.prepare(\"SELECT COALESCE(SUM(amount),0) n FROM ledger WHERE kind='deposit'\").get().n;
console.log(led+esc===dep ? 'balanced' : 'MISMATCH ' + m.fmt(dep-led-esc));"
```

---

## Anti-spam

All of it is in `src/lib/antispam.js`, enforced server-side before a slot is
taken. None of it lives in the browser, because anything checked only in the
browser is not checked at all.

| Rule | Default | Where |
| --- | --- | --- |
| One worker may do a job **once, ever** | — | unique index + check |
| Tasks from the same buyer per day | 3 | `max_tasks_per_merchant_per_day` |
| Tasks per day in total | 25 | `max_tasks_per_day` |
| Tasks held open at once | 3 | fixed |
| Faster than the job's minimum time | flagged | `min_seconds_floor` |
| Same proof text reused | flagged | duplicate check |
| Rejections that trigger suspension | 5 in 3 days | `auto_suspend_rejects` |
| Upheld reports before suspension | 3 | `strikes_before_suspend` |

Two deliberate choices worth knowing:

**Flagged is not rejected.** A fast submission or duplicated proof is surfaced
to the buyer with the reason, sorted to the top of their queue. The system does
not decide — it makes the decision easy to make well.

**Time comes from the server.** `started_at` is written when the slot opens and
the elapsed time is computed on submit. The browser is never asked how long
something took.

Settings live in the `settings` table; the defaults are in `src/lib/db.js`.

---

## Roles

**Worker** — browse jobs, take a task, send proof, get paid, withdraw.

**Merchant** — add funds, post jobs (funded at the moment they go live),
review submissions, pause or cancel. Cancelling returns everything not already
paid out, but submissions already sent still need a decision.

**Admin** — confirm deposits, pay out withdrawals, handle reports, suspend and
restore accounts. The first admin account is also the platform's own account:
commission from each approved task is credited to it, so every unit that leaves
escrow lands somewhere.

---

## Where things live

```
src/server.js          every route
src/seed.js            admin account, and optional demo data
src/lib/db.js          schema, migrations, settings
src/lib/auth.js        scrypt passwords, database-backed sessions
src/lib/money.js       ledger, escrow, deposits, withdrawals
src/lib/antispam.js    every rule above
src/lib/views.js       HTML layout and shared pieces
src/web/               stylesheet and two small scripts
data/                  the database and uploaded proofs  (gitignored)
```

Pages are server-rendered. There is no build step and no client framework, and
every screen works with JavaScript switched off — which for a site where people
are counting their earnings is worth more than any animation.

---

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `4700` | |
| `HOST` | `0.0.0.0` | |
| `DATA_DIR` | `./data` | database and proof uploads |
| `CSRF_SECRET` | random per start | **set it in production**, or every restart invalidates open forms |
| `ADMIN_PASSWORD` | — | used by the seed script only |

---

## Before this handles real money

The parts below are deliberately not built, because getting them wrong is worse
than not having them.

- **Payments are manual.** A merchant records a deposit with a transaction
  reference and an admin confirms it. There is no gateway integration, and no
  automatic verification that the money actually arrived.
- **No KYC and no identity checks.** Holding customer funds and paying people
  out is a regulated activity in most places. Find out what applies to you
  before taking real deposits.
- **No email.** Nothing is sent — no verification, no password reset, no
  notification when work is approved.
- **Rate limiting is per-rule, not per-IP.** Add a proxy-level limit on
  `/login` and `/register` before this is public.
- **One server, one SQLite file.** Fine for a long time; back up `data/` by
  copying it, and know that this does not run on two machines at once.
