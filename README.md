# Work Remote Job

A microjob marketplace. Buyers post batches of small tasks and fund them up
front; workers do a task, send proof, and are paid when it is approved. The
money sits in escrow in between, so a worker is never asked to trust that a
buyer will pay and a buyer never pays for work they have not seen.

```
npm install
npm run seed -- --demo
ADMIN_EMAILS=you@gmail.com npm start        # http://localhost:4700
```

The demo flag creates a funded buyer, two workers and three live jobs so the
screens are not empty. Those accounts have no Google identity and cannot be
signed into.

---

## Sign-in

**Google only. There are no passwords anywhere in this application** — none are
stored, checked or resettable, so none can leak.

That is a deliberate anti-fraud choice. Anyone can invent a name and a phone
number; a Google account is more work to mass-produce, so running a crowd of
fake accounts here costs real effort.

It is worth being clear about the limit: **this raises the cost of multi-
accounting, it does not end it.** Gmail addresses are free and a determined
person can hold several. It is one layer, alongside the once-per-job rule, the
daily caps, the timing check and the connection history.

### Setting it up

1. Google Cloud Console → **APIs & Services → Credentials → Create OAuth client
   ID → Web application**.
2. Authorised redirect URI — exactly, including the path:
   `https://your-domain/auth/google/callback`
   (locally, `http://localhost:4700/auth/google/callback`)
3. On the OAuth consent screen, the only scopes needed are `email` and
   `profile`.
4. Then:

```
GOOGLE_CLIENT_ID=...apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=https://your-domain/auth/google/callback
ADMIN_EMAILS=you@gmail.com
```

**Admins are made by configuration.** Any email in `ADMIN_EMAILS` becomes an
admin the moment it signs in — checked on every sign-in, so adding one later
promotes an existing account. Nothing a visitor can do makes them an admin.

### Working without Google credentials

`ALLOW_DEV_LOGIN=1` enables `/dev-login?email=...`, which signs in as an
existing account with no Google round trip. It is fenced three ways and all
must hold: the flag is set, `NODE_ENV` is not `production`, and the request
comes from the machine itself. It cannot be reached on a deployed site.

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
| Accounts on one connection before a notice | 3 | `ip_accounts_warn` |

Two deliberate choices worth knowing:

**Flagged is not rejected.** A fast submission or duplicated proof is surfaced
to the buyer with the reason, sorted to the top of their queue. The system does
not decide — it makes the decision easy to make well.

**A shared connection is a notice, never a block.** Every sign-in records the
address. When several accounts appear on one, everybody on it is told once, in
plain language, and invited to explain — and an admin can see the pattern under
**Connections**. Nothing is restricted automatically.

That restraint is the point. On mobile networks here thousands of people share
one address, and a family shares one wifi. Treating that as fraud would punish
the honest majority to catch a few, so it is evidence for a human to weigh, not
a verdict.

**Time comes from the server.** `started_at` is written when the slot opens and
the elapsed time is computed on submit. The browser is never asked how long
something took.

Settings live in the `settings` table; the defaults are in `src/lib/db.js`.

---

## Payments

Two gateways, plus a manual fallback.

| | |
| --- | --- |
| **EPS** | bKash, Nagad, Rocket, cards, internet banking |
| **Cryptomus** | USDT, BTC and other crypto, priced in USD |
| Manual | A merchant records a transfer; an admin confirms it by hand |

### The rule that matters

**Money is credited only by a server-to-server answer from the gateway.**

A payer's browser returning to a success URL proves nothing — it is a page
anyone can open. So the EPS return page does not credit anything; it calls
`CheckMerchantTransactionStatus` and reports what EPS says. Cryptomus credits
from its signed webhook, and the return page asks `payment/info` for the same
answer.

The amount credited is the one recorded on our own deposit row when the payment
was created, never a number lifted from the callback.

### Crediting exactly once

Webhooks arrive twice. Sometimes ten times, sometimes while somebody is
refreshing the page. `creditGatewayDeposit` opens an immediate transaction and
only a row still marked `pending` may move to `approved`, so only one caller
ever writes the ledger entry. Everything else finds nothing pending and does
nothing.

Tested by firing ten identical signed webhooks in parallel: balance moved once,
one ledger row.

### Signatures

Cryptomus signs with `md5(base64(json) + payment_key)`. The catch worth knowing:
it is computed the way PHP's `json_encode` writes JSON, and PHP escapes forward
slashes. A URL in the payload is enough to make a naive Node signature differ.
We send the slash-escaped form and accept either when verifying.

EPS signs each request with `base64(HMAC-SHA512(value, hash_key))` in `x-hash` —
the username for the token call, the merchant transaction id for the others.

Every callback is written to `gateway_events` as received, verified or not.
Unverified ones are recorded and ignored — never answered with an error, which
would let a stranger probe which deposit ids exist. **Admin → Gateway** shows
them; a handful is normal noise, a lot with real references means a wrong key.

### Configuration

```
PUBLIC_URL=https://your-domain          # used to build callback URLs

EPS_USERNAME=...
EPS_PASSWORD=...
EPS_HASH_KEY=...
EPS_MERCHANT_ID=...
EPS_STORE_ID=...
EPS_SANDBOX=1                           # 0 for live

CRYPTOMUS_MERCHANT_ID=...
CRYPTOMUS_PAYMENT_KEY=...
```

Cryptomus needs the callback URL reachable from the internet:
`https://your-domain/hooks/cryptomus`. Nothing arrives on localhost.

**The crypto rate is manual.** `usd_rate` in settings is local units per USD
(default 12000 = 120.00). It is deliberately not automatic: a wrong live rate
silently mispays everybody, and this moves slowly enough to set by hand. Check
it before you rely on it.

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
src/seed.js            categories and optional demo data
src/lib/db.js          schema, migrations, settings
src/lib/auth.js        sessions, admin roles, connection history, notices
src/lib/money.js       ledger, escrow, deposits, withdrawals
src/lib/antispam.js    every rule above
src/lib/google.js      Google sign-in, by hand, no library
src/lib/payments/      EPS and Cryptomus
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
| `GOOGLE_CLIENT_ID` | — | required for anyone to sign in |
| `GOOGLE_CLIENT_SECRET` | — | required |
| `GOOGLE_REDIRECT_URI` | localhost | must match Google exactly |
| `ADMIN_EMAILS` | — | comma-separated; these accounts become admins |
| `ALLOW_DEV_LOGIN` | off | local development only, see above |
| `PUBLIC_URL` | from the request | the address gateways call back to |

---

## Before this handles real money

The parts below are deliberately not built, because getting them wrong is worse
than not having them.

- **The gateways are wired but untested against real money.** The code is
  written to both providers' documented APIs and every guard is tested (see
  below), but neither has been run against a live merchant account. Do a small
  real deposit through each before opening it to anyone else.
- **No KYC and no identity checks.** Holding customer funds and paying people
  out is a regulated activity in most places. Find out what applies to you
  before taking real deposits.
- **No outbound email.** Nothing is sent. Address verification is not needed
  (Google has already done it) but there are no notifications either — a worker
  finds out their task was approved by opening the site.
- **Support is in-app plus Telegram.** Conversations live under `/support` and
  poll every six seconds. Set `telegram_channel` and `telegram_support` in the
  settings table to show the Telegram links.
- **Behind a proxy, set `trust proxy` correctly.** It is on, so the recorded
  address is `X-Forwarded-For`. If the app is ever reachable without the proxy
  in front, that header can be spoofed and the connection history becomes
  worthless.
- **Rate limiting is per-rule, not per-IP.** Add a proxy-level limit on
  `/login` and `/register` before this is public.
- **One server, one SQLite file.** Fine for a long time; back up `data/` by
  copying it, and know that this does not run on two machines at once.
