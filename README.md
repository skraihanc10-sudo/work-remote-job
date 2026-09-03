# Remote Work BD

A microjob marketplace. Buyers post batches of small tasks and fund them up
front; workers do a task, send proof, and are paid when it is approved. The
money sits in escrow in between, so a worker is never asked to trust that a
buyer will pay and a buyer never pays for work they have not seen.

## Running it locally

```
npm install
copy .env.example .env      # cp on Mac/Linux, then edit it
npm run demo                # creates the admin, demo buyer, workers and jobs
npm start                   # http://localhost:4700
```

Settings come from `.env`, so nothing has to be set in the shell. That matters
on Windows: `X=1 npm start` works in bash and silently does nothing in
PowerShell, which is a confusing first hour.

The two lines to fill in before the first run:

```
ADMIN_EMAILS=your.google.address@gmail.com
ALLOW_DEV_LOGIN=1
```

With `ALLOW_DEV_LOGIN=1` you can walk the whole site before Google is set up:

| | |
| --- | --- |
| `/dev-login?email=your.google.address@gmail.com` | admin |
| `/dev-login?email=buyer@example.com` | merchant, funded, with three live jobs |
| `/dev-login?email=rakib@example.com` | worker |

It only answers from the machine it is running on, and only when `NODE_ENV` is
not `production`, so it cannot be reached on a server. Turn it off anyway once
Google works.

The boot banner tells you what is on:

```
  data      D:each\work-remote-job\data
  sign-in   NOT CONFIGURED - nobody can sign in
  admins    you@gmail.com
  payments  EPS off, Cryptomus off
  dev login ENABLED
```

---

## Deploying

Anywhere that runs Node 22.5 or newer and gives you a **persistent disk**. The
disk is not optional: the database, the uploaded proof screenshots and the
money are all in `DATA_DIR`, and a platform that throws the filesystem away on
each deploy throws all of that away with it.

### Railway

1. Push to GitHub, then **New Project → Deploy from GitHub repo**.
2. **Add a Volume**, mount path `/data`.
3. Variables:

```
DATA_DIR=/data
PUBLIC_URL=https://your-domain
CSRF_SECRET=(a long random string)
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=https://your-domain/auth/google/callback
ADMIN_EMAILS=you@gmail.com
NODE_ENV=production
```

Do **not** set `ALLOW_DEV_LOGIN`.

### One hostname

`PUBLIC_URL` is the site's only address. Everything reaching it on any other
host is redirected there permanently.

That matters more than it sounds. With a custom domain the site also answers on
the platform's own address, and then: the Google redirect URI matches exactly
one host, session cookies are per host, and somebody who signs in on one and
returns on the other is simply signed out with no explanation. Search engines
would index both.

Two things are exempt. `/health`, because the platform's health check arrives on
an internal hostname and redirecting it fails the deploy. And `/hooks/*`,
because a gateway calling a webhook is a server rather than a browser - some
follow redirects and some quietly do not, and a lost webhook is a lost deposit.

So set `PUBLIC_URL` to the address you want people to actually use, and set it
before pointing a domain at the site.

4. Deploy, then run `npm run seed` once from the Railway shell to create the
   admin row.

`railway.toml` sets the health check to `/health`, which reads the database
rather than just answering — a process that is listening but cannot read its own
data is not healthy.

### "Deployment crashed" that is not a crash

Every deploy stops the previous container with SIGTERM. The app catches it,
lets open requests finish and exits 0, so a normal replacement is reported as
what it was. Without that the process is killed, npm reports the signal as a
failure, and the platform writes "Deployment crashed" after every single
deploy — which is alarming, and worse, makes a real crash one day
indistinguishable from the noise.

### A VPS

```
git clone <repo> && cd work-remote-job
npm ci --omit=dev
cp .env.example .env      # fill it in, set DATA_DIR to somewhere outside the repo
npm run seed
```

Then put it behind nginx or Caddy with TLS and run it under systemd or pm2.
Two things that bite:

- **`trust proxy` is on**, so the recorded address is `X-Forwarded-For`. That is
  correct behind a reverse proxy and wrong without one — if the app is also
  reachable directly on its port, anyone can forge that header and the
  connection history becomes worthless. Bind it to `127.0.0.1` and let only the
  proxy reach it.
- **Back up `DATA_DIR`.** Copying the folder is the whole backup procedure.
  There is no other copy of anyone's balance.

---

## What the demo data gives you

A funded buyer, two workers and three live jobs, so the job list and the
dashboards are not empty. Those accounts have no Google identity and cannot be
signed into from the internet.

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

You can check the books at any time — everything that came in (deposits plus any
admin adjustment) should equal all balances plus everything still in escrow:

```
node -e "const m=require('./src/lib/money'),{db}=require('./src/lib/db');
const led=db.prepare('SELECT COALESCE(SUM(amount),0) n FROM ledger').get().n;
const esc=db.prepare('SELECT COALESCE(SUM(held-released-refunded),0) n FROM escrow').get().n;
const dep=db.prepare(\"SELECT COALESCE(SUM(amount),0) n FROM ledger WHERE kind='deposit'\").get().n;
const adj=db.prepare(\"SELECT COALESCE(SUM(amount),0) n FROM ledger WHERE kind IN ('admin_credit','admin_debit')\").get().n;
console.log(led+esc===dep+adj ? 'balanced' : 'MISMATCH ' + m.fmt(dep+adj-led-esc));"
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

A person picks a side when they first sign in. Changing it later is a
**request an admin approves**, not a switch — a buyer can fund jobs and set the
terms workers are judged on, so somebody moving across should be looked at
first. The request carries their reason, and the admin sees their approval
rate, rejections, strikes and balance beside it.

Requests are also blocked while work is in flight. A merchant with submissions
waiting owes those workers a decision, and a worker holding open tasks owes
that buyer proof or the slot back, so the switch is blocked until those are
cleared and the message says what to finish.

Switching cannot be used to approve your own work: a worker may never take a
job whose merchant is their own account, and that check reads the job rather
than the current role.

**Worker** — browse jobs, take a task, send proof, get paid, withdraw.

**Merchant** — add funds, post jobs (funded at the moment they go live),
review submissions, pause or cancel. Cancelling returns everything not already
paid out, but submissions already sent still need a decision.

**Admin** — confirm deposits, pay out withdrawals, handle reports, decide role
requests, suspend and restore accounts. **Admin → Users → a name** opens one
person's whole record on a page: earnings, deposits, withdrawals, every task
with the time spent, jobs posted, reports against them, sign-in addresses and
who else shares their connection. Built because judging a report by flicking
between four screens is how bad suspensions happen. The first admin account is also the platform's own account:
commission from each approved task is credited to it, so every unit that leaves
escrow lands somewhere.

---

## Moving money by hand

**Admin → Users → a name → Adjust balance** adds or removes money in the site
currency or in USD, converted at the rate in settings.

This is the only place money appears without a payment behind it, so it is
built to be answerable afterwards:

- it is an ordinary ledger row, so it shows in that person's own wallet history
  like anything else — nothing is hidden from the account holder
- the reason is required, stored, and shown to them in a notice
- who did it, and the balance before and after, go to the audit log
- a deduction can never take anyone below zero

It exists because real support work needs it: a payment that arrived outside the
gateway, a mistaken rejection to put right, a bonus. What it must never become is
a quiet way to change the books — which is why every one of those properties is
there.

**Admin → Settings** changes the rate, the fee, every anti-spam threshold and the
contact details without a deploy.

---

## Referrals

Each account gets a short code (`/r/CODE`). It rides through the Google sign-in
in a cookie and attaches only when the account is created — a referrer that can
be added afterwards becomes people claiming each other's accounts.

**Rewards come out of the platform's commission, never out of what the worker
earns or what the buyer paid.** Two settings control it:

| Setting | Default | |
| --- | --- | --- |
| `referral_task_bps` | 1500 | 15% *of our fee* on a referred worker's approved task |
| `referral_deposit_bps` | 100 | 1% of a referred buyer's deposit |

Worked example on a ৳5.00 task with a 10% fee: the worker receives ৳4.50, the
platform's fee is ৳0.50, the referrer gets ৳0.075 of that, and the platform
keeps the rest. The worker's ৳4.50 is untouched.

The alternative — taking a slice of the referred person's earnings — is not a
reward scheme, it is a transfer. It makes the site quietly worse for the person
doing the work and gives everybody a reason to recruit rather than to work.

Paid once per source event, enforced by a unique index on `(kind, source_id)`
rather than a check, so a retried approval cannot pay twice.

`/r/CODE` redirects the same way whether the code is real or invented. Anything
else lets a stranger probe which codes exist.

---

## Live activity and payment proof

`/activity` and `/payments` are real rows from the database. Nothing is
generated, padded or back-dated, and where there is nothing yet the page says so
instead of filling the space. A site that invents its own activity feed is
lying on the page that asks people to trust it.

Names are shortened to a first name and an initial. Somebody doing tasks for
money has not agreed to a public payout history under their full name.

---

## The home page numbers

Every figure is counted from the database. None is typed into a settings box,
because the moment one number is invented nobody can tell which of the others
are real — and this site asks people to trust it with their time and money.

A figure that is genuinely zero is left out rather than printed as "0". Not to
flatter the site, but because "0 tasks approved" tells a visitor nothing except
that it is new, which the rest of the page already makes obvious. With nothing
to show at all, the panel says so plainly.

The reviews come from the `testimonials` table. The seeded ones are marked
`is_demo`, and while any are still marked that way the page prints "Example
reviews while the site is new" above them. Replace them with real ones and that
line disappears on its own.

---

## On a phone

Most people here are on one, so the navigation is built for it rather than
squeezed into it.

The header collapses to the logo, a balance pill and a burger. The four or five
things people actually came to do sit in a **bottom tab bar**, one thumb away;
everything else lives in the drawer. All three renderings — desktop bar, drawer,
tab bar — come from a single list in `navItems()`. Three hand-written copies
drift the first time a link is added, and the phone is the one that quietly
loses a page.

`app.css` and `app.js` are requested with a version taken from the file's own
modification time. Without it they are cached for an hour, so a deploy leaves
people on the old stylesheet — which does not look like caching, it looks like a
broken site.

Every page is checked at 390px for horizontal overflow, which is the defect that
makes a site feel broken on a phone. Wide content (tables, the admin screens)
scrolls inside its own container so the page body never does.

---

## Where things live

```
src/server.js          every route
src/seed.js            categories and optional demo data
src/lib/db.js          schema, migrations, settings
src/lib/auth.js        sessions, admin roles, connection history, notices
src/lib/money.js       ledger, escrow, deposits, withdrawals
src/lib/antispam.js    every rule above
src/lib/referrals.js   codes, attachment and rewards
src/lib/google.js      Google sign-in, by hand, no library
src/lib/payments/      EPS and Cryptomus
src/lib/views.js       HTML layout and shared pieces
                       (About, Security, Terms, Privacy, Refunds, FAQ and
                        Contact are routes in server.js - they read the live
                        settings, so the fee and limits they quote are the ones
                        actually enforced)
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
