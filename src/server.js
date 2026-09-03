/* ---------------------------------------------------------------------------
   Work Remote Job - a microjob marketplace.

     npm start        then open http://localhost:4700

   Merchants post batches of small tasks and fund them up front. Workers do a
   task, send proof, and are paid when the merchant approves. The money sits in
   escrow in between, so a worker is never asked to trust that a buyer will pay
   and a buyer never pays for work they have not seen.
   --------------------------------------------------------------------------- */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const express = require('express');
const multer = require('multer');

const { db, DATA_DIR, getSetting, setSetting, numSetting, audit } = require('./lib/db');
const auth = require('./lib/auth');
const google = require('./lib/google');
const eps = require('./lib/payments/eps');
const cryptomus = require('./lib/payments/cryptomus');
const money = require('./lib/money');
const spam = require('./lib/antispam');
const V = require('./lib/views');

const PORT = Number(process.env.PORT) || 4700;
const HOST = process.env.HOST || '0.0.0.0';

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false, limit: '256kb' }));

/* Railway and most hosts poll this to decide whether a deploy came up. It
   touches the database on purpose: a process that is listening but cannot read
   its own data is not healthy, and saying so early is better than serving
   errors to people. */
app.get('/health', (req, res) => {
  try {
    db.prepare('SELECT 1').get();
    res.json({ ok: true, gateways: { eps: eps.configured(), cryptomus: cryptomus.configured() } });
  } catch (err) {
    res.status(503).json({ ok: false, error: err.message });
  }
});

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

// ------------------------------------------------------------------ session
function cookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

app.use((req, res, next) => {
  req.token = cookies(req).wrj_session || null;
  req.user = auth.userFor(req.token);
  next();
});

// A form posted from another site must not be able to move money. The token is
// derived from the session, so there is nothing extra to store.
const CSRF_SECRET = process.env.CSRF_SECRET || crypto.randomBytes(32).toString('hex');
function csrf(req) {
  if (!req.token) return '';
  return crypto.createHmac('sha256', CSRF_SECRET).update(req.token).digest('hex').slice(0, 32);
}
function csrfField(req) {
  return `<input type="hidden" name="_csrf" value="${V.esc(csrf(req))}">`;
}
function checkCsrf(req, res, next) {
  if (!req.user) return next();
  const given = String((req.body && req.body._csrf) || '');
  const want = csrf(req);
  if (given.length !== want.length ||
      !crypto.timingSafeEqual(Buffer.from(given), Buffer.from(want))) {
    return fail(res, 'That form expired. Please try again.');
  }
  next();
}
// Multipart bodies are not parsed yet at this point, so the token is not
// visible here. Those routes run the same check straight after their upload
// middleware instead - see /task/:id/submit.
app.post('*splat', (req, res, next) => {
  if (String(req.headers['content-type'] || '').startsWith('multipart/form-data')) return next();
  checkCsrf(req, res, next);
});

// ------------------------------------------------------------------ helpers
function flashOf(req) {
  if (!req.query.msg) return null;
  return { text: String(req.query.msg).slice(0, 300), kind: String(req.query.kind || 'info') };
}

function send(req, res, opts) {
  res.setHeader('Cache-Control', 'no-store');
  res.send(V.layout({
    ...opts,
    user: req.user,
    flash: flashOf(req),
    notices: req.user ? auth.unseenNotices(req.user.id) : [],
    csrf: csrf(req),
  }));
}

function back(res, url, msg, kind) {
  const q = msg ? `${url.includes('?') ? '&' : '?'}msg=${encodeURIComponent(msg)}&kind=${kind || 'info'}` : '';
  res.redirect(url + q);
}

function fail(res, msg) {
  res.status(400).send(V.layout({
    title: 'Something went wrong', user: null, body:
      `<div class="card pad"><h1>That did not work</h1><p class="muted">${V.esc(msg)}</p>
       <p><a href="/" class="btn">Back to the site</a></p></div>`,
  }));
}

function need(role) {
  return (req, res, next) => {
    if (!req.user) return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
    if (role && req.user.role !== role) return fail(res, 'That page is not for your account type.');
    next();
  };
}

function active(req, res, next) {
  if (req.user && req.user.status !== 'active') {
    return fail(res, 'Your account is suspended, so this action is not available.');
  }
  next();
}

// -------------------------------------------------------------------- files
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, path.join(DATA_DIR, 'proofs')),
    filename: (req, file, cb) => {
      const ext = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' }[file.mimetype] || '';
      cb(null, crypto.randomBytes(16).toString('hex') + ext);
    },
  }),
  limits: { fileSize: 4 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const ok = ['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype);
    cb(ok ? null : new Error('Proof must be a JPG, PNG or WebP image'), ok);
  },
});

app.get('/proof/:name', need(), (req, res) => {
  const name = path.basename(String(req.params.name));
  const file = path.join(DATA_DIR, 'proofs', name);
  if (!file.startsWith(path.join(DATA_DIR, 'proofs')) || !fs.existsSync(file)) return res.status(404).end();

  // Proof screenshots often show accounts and personal details. Only the two
  // people involved and an admin ever see one.
  const sub = db.prepare('SELECT worker_id, merchant_id FROM submissions WHERE proof_file = ?').get(name);
  const allowed = req.user.role === 'admin' ||
    (sub && (sub.worker_id === req.user.id || sub.merchant_id === req.user.id));
  if (!allowed) return res.status(403).end();

  res.setHeader('Cache-Control', 'private, max-age=3600');
  res.sendFile(file);
});

// ======================================================================
// PUBLIC
// ======================================================================
app.get('/', (req, res) => {
  if (req.user) return res.redirect(req.user.role === 'admin' ? '/admin' :
    req.user.role === 'merchant' ? '/merchant' : '/worker');

  const stats = {
    jobs: db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE status = 'active'").get().n,
    open: db.prepare("SELECT COALESCE(SUM(slots - slots_filled), 0) AS n FROM jobs WHERE status = 'active'").get().n,
    workers: db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'worker'").get().n,
    paid: db.prepare("SELECT COALESCE(SUM(amount), 0) AS n FROM ledger WHERE kind = 'task_earning'").get().n,
  };

  const latest = db.prepare(`
    SELECT j.*, c.name AS category FROM jobs j
    LEFT JOIN categories c ON c.id = j.category_id
    WHERE j.status = 'active' AND j.slots_filled < j.slots
    ORDER BY j.id DESC LIMIT 6
  `).all();

  send(req, res, {
    title: 'Small tasks, paid on approval',
    body: `
<section class="hero">
  <div class="hero-copy">
    <h1>Small tasks. Real money. Paid when your work is approved.</h1>
    <p class="lede">Buyers fund every job before it goes live, so the money for your
       task is already set aside before you start it.</p>
    <div class="btn-row">
      <a href="/register?role=worker" class="btn btn-lg">Start working</a>
      <a href="/register?role=merchant" class="btn btn-ghost btn-lg">Post a job</a>
    </div>
  </div>
  <div class="hero-stats">
    <div class="stat"><b>${stats.jobs}</b><span>open jobs</span></div>
    <div class="stat"><b>${stats.open}</b><span>tasks available</span></div>
    <div class="stat"><b>${stats.workers}</b><span>workers</span></div>
    <div class="stat"><b>${V.money(stats.paid)}</b><span>paid out</span></div>
  </div>
</section>

<section class="section">
  <h2>How it works</h2>
  <div class="three">
    <div class="card pad"><span class="step">1</span><h3>Pick a task</h3>
      <p class="muted">Every job says exactly what to do and what proof to send. One worker can do each job once.</p></div>
    <div class="card pad"><span class="step">2</span><h3>Do it and send proof</h3>
      <p class="muted">Your time on the task is recorded, so honest work is easy to tell apart from clicking through.</p></div>
    <div class="card pad"><span class="step">3</span><h3>Get paid</h3>
      <p class="muted">The buyer reviews it. Approved work is credited straight away from money already held in escrow.</p></div>
  </div>
</section>

<section class="section">
  <div class="section-head"><h2>Latest jobs</h2><a href="/jobs" class="link">See all</a></div>
  ${latest.length ? `<div class="job-grid">${latest.map(jobCard).join('')}</div>`
    : `<div class="empty">No jobs are open right now.</div>`}
</section>`,
  });
});

function jobCard(j) {
  const left = j.slots - j.slots_filled;
  return `<a class="job-card" href="/jobs/${j.id}">
    <div class="job-top">
      <span class="tag">${V.esc(j.category || 'Task')}</span>
      <b class="rate">${V.money(j.rate)}</b>
    </div>
    <h3>${V.esc(j.title)}</h3>
    <p class="muted clip">${V.esc(String(j.instructions).slice(0, 130))}</p>
    <div class="job-foot">
      <span>${left} of ${j.slots} left</span>
      <span>takes ${V.mmss(j.min_seconds)}+</span>
    </div>
  </a>`;
}

app.get('/jobs', (req, res) => {
  const cat = req.query.cat ? Number(req.query.cat) : null;
  const q = String(req.query.q || '').trim();
  const args = [];
  let where = "j.status = 'active' AND j.slots_filled < j.slots";
  if (cat) { where += ' AND j.category_id = ?'; args.push(cat); }
  if (q) { where += ' AND j.title LIKE ?'; args.push('%' + q + '%'); }

  const jobs = db.prepare(`
    SELECT j.*, c.name AS category FROM jobs j
    LEFT JOIN categories c ON c.id = j.category_id
    WHERE ${where} ORDER BY j.id DESC LIMIT 100
  `).all(...args);
  const cats = db.prepare('SELECT * FROM categories ORDER BY name').all();

  send(req, res, {
    title: 'Find work', active: 'jobs', wide: true,
    body: `
<div class="page-head">
  <div><h1>Find work</h1><p class="muted">${jobs.length} job${jobs.length === 1 ? '' : 's'} with open slots.</p></div>
  <form class="filters" method="get" action="/jobs">
    <input type="search" name="q" value="${V.esc(q)}" placeholder="Search jobs">
    <select name="cat">
      <option value="">All categories</option>
      ${cats.map(c => `<option value="${c.id}"${cat === c.id ? ' selected' : ''}>${V.esc(c.name)}</option>`).join('')}
    </select>
    <button class="btn btn-ghost" type="submit">Filter</button>
  </form>
</div>
${jobs.length ? `<div class="job-grid">${jobs.map(jobCard).join('')}</div>`
  : `<div class="empty">Nothing matches that. Try a different category.</div>`}`,
  });
});

app.get('/jobs/:id', (req, res) => {
  const job = db.prepare(`
    SELECT j.*, c.name AS category, u.name AS merchant_name FROM jobs j
    LEFT JOIN categories c ON c.id = j.category_id
    JOIN users u ON u.id = j.merchant_id
    WHERE j.id = ?
  `).get(Number(req.params.id));
  if (!job) return res.status(404).send(V.layout({ title: 'Not found', user: req.user,
    body: '<div class="card pad"><h1>No such job</h1></div>' }));

  const left = job.slots - job.slots_filled;
  let action;

  if (!req.user) {
    action = `<a href="/login?next=/jobs/${job.id}" class="btn btn-lg">Sign in to take this task</a>`;
  } else if (req.user.role !== 'worker') {
    action = `<p class="muted">Only worker accounts can take tasks.</p>`;
  } else {
    const check = spam.canStart(req.user, job);
    action = check.allowed
      ? `<form method="post" action="/jobs/${job.id}/start">${csrfField(req)}
           <button class="btn btn-lg" type="submit">Start this task</button>
         </form>
         <p class="hint">${check.remainingToday} more task${check.remainingToday === 1 ? '' : 's'} available to you today.</p>`
      : `<div class="alert alert-warn">${V.esc(check.reason)}</div>`;
  }

  send(req, res, {
    title: job.title, active: 'jobs',
    body: `
<div class="split-page">
  <div>
    <a class="back" href="/jobs">&larr; All jobs</a>
    <h1>${V.esc(job.title)}</h1>
    <p class="muted">Posted by ${V.esc(job.merchant_name)} · ${V.esc(job.category || 'Task')} · ${V.ago(job.created_at)}</p>

    <div class="card pad">
      <h2>What to do</h2>
      <div class="prose">${V.esc(job.instructions).replace(/\n/g, '<br>')}</div>
      <h2>Proof to send</h2>
      <div class="prose">${V.esc(job.proof_required).replace(/\n/g, '<br>')}</div>
    </div>
  </div>

  <aside>
    <div class="card pad sticky">
      <div class="pay"><b>${V.money(job.rate)}</b><span>per approved task</span></div>
      <dl class="kv">
        <dt>Slots left</dt><dd>${left} of ${job.slots}</dd>
        <dt>Expected time</dt><dd>at least ${V.mmss(job.min_seconds)}</dd>
        <dt>Time to finish</dt><dd>${job.hold_minutes} minutes once started</dd>
        ${job.country ? `<dt>Country</dt><dd>${V.esc(job.country)}</dd>` : ''}
      </dl>
      ${action}
      <p class="fine">Each worker can do this job once. Your time on the task is recorded.</p>
    </div>
  </aside>
</div>`,
  });
});

app.get('/how-it-works', (req, res) => send(req, res, {
  title: 'How it works', active: 'how',
  body: `
<h1>How it works</h1>
<div class="two">
  <div class="card pad">
    <h2>If you are working</h2>
    <ol class="steps">
      <li>Find a job and read what proof it needs before you start.</li>
      <li>Press Start. That opens your slot and begins timing the task.</li>
      <li>Do the work, then send your proof before the time window closes.</li>
      <li>The buyer reviews it. Approved work is credited to your balance immediately.</li>
      <li>Withdraw once you are over the minimum.</li>
    </ol>
    <p class="muted">You keep ${(100 - numSetting('commission_bps') / 100).toFixed(0)}% of the listed rate;
       the rest is the platform fee, shown on every task before you start.</p>
  </div>
  <div class="card pad">
    <h2>If you are hiring</h2>
    <ol class="steps">
      <li>Add funds to your wallet.</li>
      <li>Post a job: the instructions, the proof you want, the rate and how many people you need.</li>
      <li>The full cost is held in escrow the moment it goes live.</li>
      <li>Review each submission. Approve to pay, reject with a reason if it is wrong.</li>
      <li>Cancel any time - whatever has not been paid out comes back to you.</li>
    </ol>
  </div>
</div>
<div class="card pad">
  <h2>Why the money is safe either way</h2>
  <p>A job cannot go live unless it is funded, so a worker is never asked to trust
     that a buyer will pay. The money stays in escrow until the buyer approves the
     work, so a buyer never pays for work they have not seen.</p>
  <p class="muted">Balances are not a number in a box - every movement is a line in
     your wallet history, and the two can never disagree.</p>
</div>
<p><a class="btn" href="/rules">Read the rules on spam</a></p>`,
}));

app.get('/rules', (req, res) => send(req, res, {
  title: 'Rules',
  body: `
<h1>Rules</h1>
<p class="lede">This site only works if the proof is real. These rules are enforced
   by the system, not just written here.</p>

<div class="card pad">
  <h2>One job, one worker, once</h2>
  <p>You can do each job a single time. Not once a day - once. The system refuses a
     second attempt, and a second account doing the same job is what gets both closed.</p>

  <h2>Limits per day</h2>
  <p>At most <b>${numSetting('max_tasks_per_merchant_per_day')} tasks from the same buyer per day</b>,
     and <b>${numSetting('max_tasks_per_day')} tasks in total per day</b>. You can hold three tasks
     open at once. Limits reset at midnight UTC.</p>

  <h2>Time is recorded</h2>
  <p>The clock starts when you press Start and stops when you send proof. A task
     finished faster than the job's minimum time is flagged for the buyer to look at.
     It is not automatically rejected - but it is not hidden either.</p>

  <h2>One person, one account</h2>
  <p>Sign-in is Google only, and one Google account is one account here. Running
     several accounts to take the same job more than once is the thing that gets
     everybody involved closed, not just the extra one.</p>
  <p>We do record which connection each sign-in came from. If several accounts share
     one, everybody on it is <b>told</b> - not blocked. Shared wifi, families, offices
     and mobile networks all produce this honestly, so it is never treated as proof
     of anything on its own. If it applies to you, message support and it is noted on
     your account before it ever becomes a question.</p>

  <h2>Proof must be your own</h2>
  <p>The same proof text reused across tasks is detected and flagged. Sending someone
     else's screenshot is fraud, not a shortcut.</p>

  <h2>What happens when it goes wrong</h2>
  <p><b>${numSetting('auto_suspend_rejects')} rejected tasks within ${numSetting('auto_suspend_window_days')} days</b>
     suspends the account for ${numSetting('suspend_days')} days, automatically.</p>
  <p>Reports are reviewed by a person. An upheld report is a strike;
     <b>${numSetting('strikes_before_suspend')} strikes</b> suspends the account.
     Fraud closes it permanently, and a closed account does not get its balance back.</p>

  <h2>For buyers</h2>
  <p>Rejecting good work to avoid paying is itself a reportable offence. Workers can
     report a rejection, an admin can see the proof, and buyers who do it lose the
     ability to post.</p>
</div>`,
}));

// ======================================================================
// SIGN IN  (Google only - there are no passwords anywhere in this app)
// ======================================================================
app.get(['/login', '/register'], (req, res) => {
  if (req.user) return res.redirect('/');
  const next = String(req.query.next || '');

  if (!google.configured()) {
    return send(req, res, {
      title: 'Sign in',
      body: `<div class="narrow"><div class="card pad">
        <h1>Sign-in is not set up yet</h1>
        <p class="muted">This site uses Google sign-in only. The owner needs to add
           <code>GOOGLE_CLIENT_ID</code> and <code>GOOGLE_CLIENT_SECRET</code> before anyone can sign in.</p>
        <p class="muted">The steps are in the README.</p>
      </div></div>`,
    });
  }

  send(req, res, {
    title: 'Sign in',
    body: `
<div class="narrow signin">
  <h1>Sign in</h1>
  <p class="muted">One button for everything. If you have never been here before this
     creates your account; if you have, it signs you in.</p>

  <a class="google-btn" href="/auth/google${next ? '?next=' + encodeURIComponent(next) : ''}">
    <svg viewBox="0 0 48 48" width="20" height="20" aria-hidden="true">
      <path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.6l6.7-6.7C35.6 2.6 30.2 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.8 6.1C12.3 13.2 17.7 9.5 24 9.5z"/>
      <path fill="#4285F4" d="M46.1 24.6c0-1.6-.1-3.1-.4-4.6H24v9h12.4c-.5 2.9-2.2 5.4-4.7 7l7.6 5.9c4.4-4.1 6.8-10.1 6.8-17.3z"/>
      <path fill="#FBBC05" d="M10.4 28.7c-.5-1.4-.8-2.9-.8-4.7s.3-3.3.8-4.7l-7.8-6.1C.9 16.4 0 20.1 0 24s.9 7.6 2.6 10.8l7.8-6.1z"/>
      <path fill="#34A853" d="M24 48c6.5 0 11.9-2.1 15.9-5.8l-7.6-5.9c-2.1 1.4-4.8 2.3-8.3 2.3-6.3 0-11.7-3.7-13.6-9.1l-7.8 6.1C6.5 42.6 14.6 48 24 48z"/>
    </svg>
    <span>Continue with Google</span>
  </a>

  <div class="card pad why">
    <h2>Why only Google?</h2>
    <p class="muted">Anyone can invent a name and a phone number. A Google account is
       harder to mass-produce, so it is much more work to run a crowd of fake accounts
       here &mdash; which is what protects the people doing real work.</p>
    <p class="muted">We never see your Google password. We receive your name, email
       address and profile picture, and nothing else.</p>
  </div>
</div>`,
  });
});

app.get('/auth/google', (req, res) => {
  if (!google.configured()) return fail(res, 'Google sign-in is not configured yet.');
  const state = google.newState();
  const next = String(req.query.next || '');
  // The state lives in a short cookie and must come back unchanged, which is
  // what stops somebody sending a victim a pre-made sign-in link.
  res.setHeader('Set-Cookie', [
    `wrj_oauth=${state}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
    `wrj_next=${encodeURIComponent(next)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
  ]);
  res.redirect(google.authUrl(state));
});

app.get('/auth/google/callback', async (req, res) => {
  const jar = cookies(req);
  const expire = 'wrj_oauth=; HttpOnly; Path=/; Max-Age=0';

  try {
    if (req.query.error) throw new Error('Sign-in was cancelled.');
    const state = String(req.query.state || '');
    if (!state || !jar.wrj_oauth || state !== jar.wrj_oauth) {
      throw new Error('That sign-in link did not come from here. Start again from the sign-in page.');
    }
    const code = String(req.query.code || '');
    if (!code) throw new Error('Google did not send a sign-in code.');

    const profile = await google.exchange(code);
    const result = auth.signInWithGoogle(profile, req.ip);
    const s = auth.startSession(result.user.id);
    auth.recordLogin(result.user.id, req.ip, req.get('user-agent'));

    res.setHeader('Set-Cookie', [
      `wrj_session=${s.token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${s.maxAge}`,
      expire,
      'wrj_next=; HttpOnly; Path=/; Max-Age=0',
    ]);
    audit(result.user.id, result.created ? 'signup' : 'login', `user:${result.user.id}`, null, req.ip);

    if (result.created && result.user.role !== 'admin') return res.redirect('/welcome');
    const next = decodeURIComponent(jar.wrj_next || '');
    res.redirect(next.startsWith('/') ? next : '/');
  } catch (err) {
    res.setHeader('Set-Cookie', expire);
    fail(res, err.message);
  }
});

/* First visit: choose a side. Only offered while the account has done nothing,
   so nobody can flip roles to escape a history. */
function hasActivity(userId) {
  const a = db.prepare('SELECT COUNT(*) AS n FROM submissions WHERE worker_id = ?').get(userId).n;
  const b = db.prepare('SELECT COUNT(*) AS n FROM jobs WHERE merchant_id = ?').get(userId).n;
  const c = db.prepare('SELECT COUNT(*) AS n FROM ledger WHERE user_id = ?').get(userId).n;
  return a + b + c > 0;
}

app.get('/welcome', need(), (req, res) => {
  if (req.user.role === 'admin' || hasActivity(req.user.id)) return res.redirect('/');
  send(req, res, {
    title: 'Welcome',
    body: `
<div class="narrow-wide">
  <h1>Welcome, ${V.esc(req.user.name.split(' ')[0])}</h1>
  <p class="lede">Which side are you on? This can only be changed while your account is
     still empty, so pick the one you actually came for.</p>
  <form method="post" action="/welcome" class="pick-role">
    ${csrfField(req)}
    <button class="pick" name="role" value="worker" type="submit">
      <b>I want to work</b>
      <span>Do small tasks and get paid when the buyer approves them.</span>
    </button>
    <button class="pick" name="role" value="merchant" type="submit">
      <b>I want to hire</b>
      <span>Post tasks, fund them up front, and review the proof that comes back.</span>
    </button>
  </form>
</div>`,
  });
});

app.post('/welcome', need(), (req, res) => {
  const role = req.body.role === 'merchant' ? 'merchant' : 'worker';
  if (req.user.role === 'admin') return res.redirect('/');
  if (hasActivity(req.user.id)) return fail(res, 'Your account has already been used, so the role is fixed.');
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.user.id);
  audit(req.user.id, 'role_chosen', `user:${req.user.id}`, { role }, req.ip);
  res.redirect(role === 'merchant' ? '/merchant' : '/worker');
});

/* Local development only.

   Google sign-in needs credentials and a public redirect URI, which is a poor
   fit for working offline. This creates a session without Google - and it is
   fenced in three ways, all of which must hold:

     ALLOW_DEV_LOGIN=1 must be set explicitly,
     NODE_ENV must not be 'production',
     and the request must come from this machine.

   It is never reachable on a deployed site. If you find yourself wanting to
   relax any of these, do not - configure Google instead.
*/
app.get('/dev-login', (req, res) => {
  const enabled = process.env.ALLOW_DEV_LOGIN === '1' && process.env.NODE_ENV !== 'production';
  const local = ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.ip);
  if (!enabled || !local) return res.status(404).end();

  const email = String(req.query.email || '').trim().toLowerCase();
  if (!email) return fail(res, 'Add ?email=someone@example.com');

  const user = db.prepare('SELECT * FROM users WHERE lower(email) = ?').get(email);
  if (!user) return fail(res, 'No account with that email. Run the seed script first.');

  const s = auth.startSession(user.id);
  auth.recordLogin(user.id, req.ip, 'dev-login');
  res.setHeader('Set-Cookie',
    `wrj_session=${s.token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${s.maxAge}`);
  audit(user.id, 'dev_login', `user:${user.id}`, null, req.ip);
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  auth.endSession(req.token);
  res.setHeader('Set-Cookie', 'wrj_session=; HttpOnly; Path=/; Max-Age=0');
  res.redirect('/');
});

app.post('/notices/:id/seen', need(), (req, res) => {
  auth.markNoticeSeen(Number(req.params.id), req.user.id);
  back(res, req.get('referer') || '/');
});

// ======================================================================
// WORKER
// ======================================================================
app.get('/worker', need('worker'), (req, res) => {
  const u = req.user;
  const mine = db.prepare(`
    SELECT s.*, j.title, j.rate FROM submissions s JOIN jobs j ON j.id = s.job_id
    WHERE s.worker_id = ? ORDER BY s.id DESC LIMIT 8
  `).all(u.id);

  const counts = db.prepare(`
    SELECT
      SUM(CASE WHEN status = 'started' THEN 1 ELSE 0 END) AS open,
      SUM(CASE WHEN status = 'submitted' THEN 1 ELSE 0 END) AS waiting,
      SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved,
      SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected
    FROM submissions WHERE worker_id = ?
  `).get(u.id);

  const today = db.prepare(
    `SELECT COUNT(*) AS n FROM submissions WHERE worker_id = ? AND started_at >= ?
       AND status IN ('started','submitted','approved')`
  ).get(u.id, spam.todayStart()).n;
  const cap = numSetting('max_tasks_per_day');

  send(req, res, {
    title: 'Dashboard', active: 'dash',
    body: `
<div class="page-head"><div><h1>Hello, ${V.esc(u.name)}</h1>
  <p class="muted">${today} of ${cap} tasks used today. Resets at midnight UTC.</p></div>
  <a class="btn" href="/jobs">Find work</a></div>

<div class="stat-row">
  <div class="stat"><b>${V.money(money.balance(u.id))}</b><span>balance</span></div>
  <div class="stat"><b>${counts.open || 0}</b><span>in progress</span></div>
  <div class="stat"><b>${counts.waiting || 0}</b><span>waiting review</span></div>
  <div class="stat ok"><b>${counts.approved || 0}</b><span>approved</span></div>
  <div class="stat ${counts.rejected ? 'bad' : ''}"><b>${counts.rejected || 0}</b><span>rejected</span></div>
</div>

<div class="card">
  <div class="card-head"><h2>Recent tasks</h2><a class="link" href="/worker/tasks">All tasks</a></div>
  ${mine.length ? taskTable(mine) : '<div class="pad muted">You have not taken a task yet.</div>'}
</div>`,
  });
});

function taskTable(rows) {
  return `<div class="table-wrap"><table>
    <thead><tr><th>Job</th><th>Started</th><th>Time</th><th>Pay</th><th>State</th><th></th></tr></thead>
    <tbody>${rows.map(s => `<tr>
      <td>${V.esc(s.title)}</td>
      <td class="dim">${V.ago(s.started_at)}</td>
      <td class="num">${s.seconds_spent != null ? V.mmss(s.seconds_spent) : '--'}</td>
      <td class="num">${V.money(s.rate)}</td>
      <td>${V.statusPill(s.status)}</td>
      <td class="right">${s.status === 'started'
        ? `<a class="btn btn-sm" href="/task/${s.id}">Continue</a>`
        : `<a class="link" href="/task/${s.id}">Open</a>`}</td>
    </tr>`).join('')}</tbody>
  </table></div>`;
}

app.get('/worker/tasks', need('worker'), (req, res) => {
  const rows = db.prepare(`
    SELECT s.*, j.title, j.rate FROM submissions s JOIN jobs j ON j.id = s.job_id
    WHERE s.worker_id = ? ORDER BY s.id DESC LIMIT 200
  `).all(req.user.id);
  send(req, res, {
    title: 'My tasks', active: 'tasks', wide: true,
    body: `<h1>My tasks</h1>
      <div class="card">${rows.length ? taskTable(rows) : '<div class="pad muted">Nothing yet.</div>'}</div>`,
  });
});

app.post('/jobs/:id/start', need('worker'), active, (req, res) => {
  const jobId = Number(req.params.id);
  db.exec('BEGIN IMMEDIATE');
  try {
    const job = db.prepare('SELECT * FROM jobs WHERE id = ?').get(jobId);
    if (!job) throw new Error('No such job');

    const check = spam.canStart(req.user, job);
    if (!check.allowed) throw new Error(check.reason);

    // Re-read the count inside the transaction: two workers pressing Start at
    // the same moment must not both get the last slot.
    if (job.slots_filled >= job.slots) throw new Error('Someone just took the last slot.');

    const info = db.prepare(
      'INSERT INTO submissions (job_id, worker_id, merchant_id) VALUES (?, ?, ?)'
    ).run(jobId, req.user.id, job.merchant_id);
    db.prepare('UPDATE jobs SET slots_filled = slots_filled + 1 WHERE id = ?').run(jobId);
    db.exec('COMMIT');
    res.redirect('/task/' + Number(info.lastInsertRowid));
  } catch (err) {
    db.exec('ROLLBACK');
    // The unique index is the last line of defence and produces an ugly
    // message, so translate it.
    const msg = String(err.message).includes('UNIQUE')
      ? 'You have already done this job.' : err.message;
    back(res, '/jobs/' + jobId, msg, 'warn');
  }
});

app.get('/task/:id', need('worker'), (req, res) => {
  const s = db.prepare(`
    SELECT s.*, j.title, j.instructions, j.proof_required, j.rate, j.min_seconds, j.hold_minutes
    FROM submissions s JOIN jobs j ON j.id = s.job_id
    WHERE s.id = ? AND s.worker_id = ?
  `).get(Number(req.params.id), req.user.id);
  if (!s) return fail(res, 'That task is not yours.');

  const started = new Date(s.started_at.replace(' ', 'T') + 'Z').getTime();
  const deadline = started + s.hold_minutes * 60000;

  const form = s.status !== 'started' ? '' : `
    <form method="post" action="/task/${s.id}/submit" enctype="multipart/form-data" class="card pad">
      ${csrfField(req)}
      <h2>Send your proof</h2>
      <div class="prose muted">${V.esc(s.proof_required).replace(/\n/g, '<br>')}</div>
      ${V.field({ label: 'What you did', name: 'proof_text', type: 'textarea', rows: 5, required: true,
        hint: 'Include the details the buyer asked for - a username, an order number, whatever proves it.' })}
      <div class="field">
        <label for="f-proof">Screenshot <em>optional</em></label>
        <input id="f-proof" type="file" name="proof" accept="image/jpeg,image/png,image/webp">
        <span class="hint">JPG, PNG or WebP, up to 4MB.</span>
      </div>
      <div class="btn-row">
        <button class="btn btn-lg" type="submit">Send for review</button>
      </div>
    </form>
    <form method="post" action="/task/${s.id}/drop" class="drop-form"
          onsubmit="return confirm('Drop this task? Your slot goes back to the pool and you cannot take this job again.')">
      ${csrfField(req)}
      <button class="link-danger" type="submit">Drop this task</button>
    </form>`;

  const review = s.status === 'started' ? '' : `
    <div class="card pad">
      <h2>Your submission</h2>
      <div class="prose">${V.esc(s.proof_text || '').replace(/\n/g, '<br>')}</div>
      ${s.proof_file ? `<img class="proof-img" src="/proof/${V.esc(s.proof_file)}" alt="Proof screenshot">` : ''}
      <dl class="kv">
        <dt>Time spent</dt><dd>${V.mmss(s.seconds_spent)}</dd>
        <dt>State</dt><dd>${V.statusPill(s.status)}</dd>
        ${s.review_note ? `<dt>Buyer said</dt><dd>${V.esc(s.review_note)}</dd>` : ''}
      </dl>
      ${s.status === 'rejected' ? `
        <form method="post" action="/report" class="report-form">
          ${csrfField(req)}
          <input type="hidden" name="submission_id" value="${s.id}">
          <input type="hidden" name="against_id" value="${s.merchant_id}">
          <input type="hidden" name="reason" value="unfair_rejection">
          <p class="muted">Think this was rejected unfairly? An admin can see your proof.</p>
          <input type="text" name="detail" placeholder="What happened?" required>
          <button class="btn btn-ghost btn-sm" type="submit">Report this rejection</button>
        </form>` : ''}
    </div>`;

  send(req, res, {
    title: s.title, active: 'tasks',
    body: `
<a class="back" href="/worker/tasks">&larr; My tasks</a>
<h1>${V.esc(s.title)}</h1>
<p class="muted">${V.money(s.rate)} on approval · started ${V.ago(s.started_at)}</p>

${s.status === 'started' ? `<div class="timer" data-deadline="${deadline}" data-min="${s.min_seconds}">
  <span class="t-left">Time left to submit: <b>--:--</b></span>
  <span class="t-min">Spend at least ${V.mmss(s.min_seconds)} on this task.</span>
</div>` : ''}

<div class="card pad">
  <h2>What to do</h2>
  <div class="prose">${V.esc(s.instructions).replace(/\n/g, '<br>')}</div>
</div>
${form}${review}`,
  });
});

app.post('/task/:id/submit', need('worker'), active, upload.single('proof'), checkCsrf, (req, res) => {
  const s = db.prepare("SELECT * FROM submissions WHERE id = ? AND worker_id = ? AND status = 'started'")
    .get(Number(req.params.id), req.user.id);
  if (!s) return fail(res, 'That task is not open for submission.');

  const job = db.prepare('SELECT * FROM jobs WHERE id = ?').get(s.job_id);
  const text = String(req.body.proof_text || '').trim().slice(0, 4000);
  if (text.length < 4) return fail(res, 'Write what you actually did.');

  // Timing comes from the server's own record of when the slot opened. The
  // browser is never asked how long the task took.
  const started = new Date(s.started_at.replace(' ', 'T') + 'Z').getTime();
  const seconds = Math.max(0, Math.round((Date.now() - started) / 1000));

  const draft = { ...s, proof_text: text, proof_file: req.file ? req.file.filename : null, seconds_spent: seconds };
  const verdict = spam.inspectSubmission(draft, job);

  db.prepare(`
    UPDATE submissions SET status = 'submitted', proof_text = ?, proof_file = ?,
           seconds_spent = ?, submitted_at = datetime('now'), flagged = ?, flag_reason = ?
    WHERE id = ?
  `).run(text, draft.proof_file, seconds, verdict.flagged, verdict.reason, s.id);

  audit(req.user.id, 'submit', `submission:${s.id}`, { seconds, flagged: verdict.flagged }, req.ip);
  back(res, '/task/' + s.id, 'Sent for review.', 'ok');
});

app.post('/task/:id/drop', need('worker'), (req, res) => {
  const s = db.prepare("SELECT * FROM submissions WHERE id = ? AND worker_id = ? AND status = 'started'")
    .get(Number(req.params.id), req.user.id);
  if (!s) return fail(res, 'That task is not open.');

  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare("UPDATE submissions SET status = 'expired' WHERE id = ?").run(s.id);
    db.prepare('UPDATE jobs SET slots_filled = MAX(0, slots_filled - 1) WHERE id = ?').run(s.job_id);
    db.exec('COMMIT');
  } catch (err) { db.exec('ROLLBACK'); throw err; }
  back(res, '/worker/tasks', 'Task dropped.', 'info');
});

// ======================================================================
// MERCHANT
// ======================================================================
app.get('/merchant', need('merchant'), (req, res) => {
  const u = req.user;
  const jobs = db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE merchant_id = ? AND status = 'active'").get(u.id).n;
  const waiting = db.prepare("SELECT COUNT(*) AS n FROM submissions WHERE merchant_id = ? AND status = 'submitted'").get(u.id).n;
  const flagged = db.prepare("SELECT COUNT(*) AS n FROM submissions WHERE merchant_id = ? AND status = 'submitted' AND flagged = 1").get(u.id).n;
  const held = db.prepare(`
    SELECT COALESCE(SUM(e.held - e.released - e.refunded), 0) AS n
    FROM escrow e JOIN jobs j ON j.id = e.job_id
    WHERE j.merchant_id = ? AND j.status IN ('active','paused')
  `).get(u.id).n;

  send(req, res, {
    title: 'Dashboard', active: 'dash',
    body: `
<div class="page-head"><div><h1>Hello, ${V.esc(u.name)}</h1>
  <p class="muted">Everything you have running.</p></div>
  <a class="btn" href="/merchant/jobs/new">Post a job</a></div>

<div class="stat-row">
  <div class="stat"><b>${V.money(money.balance(u.id))}</b><span>available</span></div>
  <div class="stat"><b>${V.money(held)}</b><span>held for jobs</span></div>
  <div class="stat"><b>${jobs}</b><span>active jobs</span></div>
  <div class="stat ${waiting ? 'warn' : ''}"><b>${waiting}</b><span>to review</span></div>
  ${flagged ? `<div class="stat bad"><b>${flagged}</b><span>flagged</span></div>` : ''}
</div>

${waiting ? `<div class="alert alert-warn">
  ${waiting} submission${waiting === 1 ? '' : 's'} waiting.
  <a href="/merchant/review">Review now</a>
</div>` : ''}

<div class="card">
  <div class="card-head"><h2>Your jobs</h2><a class="link" href="/merchant/jobs">All jobs</a></div>
  ${merchantJobTable(db.prepare('SELECT * FROM jobs WHERE merchant_id = ? ORDER BY id DESC LIMIT 8').all(u.id))}
</div>`,
  });
});

function merchantJobTable(rows) {
  if (!rows.length) return '<div class="pad muted">You have not posted a job yet.</div>';
  return `<div class="table-wrap"><table>
    <thead><tr><th>Job</th><th>Rate</th><th>Filled</th><th>Held</th><th>State</th><th></th></tr></thead>
    <tbody>${rows.map(j => {
      const e = money.escrowRemaining(j.id);
      return `<tr>
        <td><a class="link" href="/jobs/${j.id}">${V.esc(j.title)}</a></td>
        <td class="num">${V.money(j.rate)}</td>
        <td class="num">${j.slots_filled} / ${j.slots}</td>
        <td class="num">${V.money(e)}</td>
        <td>${V.statusPill(j.status)}</td>
        <td class="right"><a class="link" href="/merchant/jobs/${j.id}">Manage</a></td>
      </tr>`;
    }).join('')}</tbody></table></div>`;
}

app.get('/merchant/jobs', need('merchant'), (req, res) => send(req, res, {
  title: 'My jobs', active: 'myjobs', wide: true,
  body: `<div class="page-head"><h1>My jobs</h1><a class="btn" href="/merchant/jobs/new">Post a job</a></div>
    <div class="card">${merchantJobTable(db.prepare('SELECT * FROM jobs WHERE merchant_id = ? ORDER BY id DESC').all(req.user.id))}</div>`,
}));

app.get('/merchant/jobs/new', need('merchant'), active, (req, res) => {
  const cats = db.prepare('SELECT * FROM categories ORDER BY name').all();
  send(req, res, {
    title: 'Post a job', active: 'myjobs',
    body: `
<div class="narrow-wide">
  <h1>Post a job</h1>
  <p class="muted">The full cost is held from your balance as soon as it goes live,
     and whatever is not paid out comes back to you.</p>
  <p class="muted">Available now: <b>${V.money(money.balance(req.user.id))}</b> ·
     <a href="/wallet">Add funds</a></p>

  <form method="post" action="/merchant/jobs/new" class="card pad">
    ${csrfField(req)}
    ${V.field({ label: 'Title', name: 'title', required: true, placeholder: 'Sign up and confirm your email' })}
    ${V.field({ label: 'Category', name: 'category_id', type: 'select',
      options: cats.map(c => ({ value: c.id, label: c.name })) })}
    ${V.field({ label: 'What the worker must do', name: 'instructions', type: 'textarea', rows: 7, required: true,
      hint: 'Number the steps. Vague instructions are the main cause of rejected work.' })}
    ${V.field({ label: 'Proof you want back', name: 'proof_required', type: 'textarea', rows: 4, required: true,
      placeholder: 'Your username, and a screenshot of the confirmation screen' })}
    <div class="row-2">
      ${V.field({ label: 'Pay per task', name: 'rate', required: true, placeholder: '5.00', hint: 'What one worker earns' })}
      ${V.field({ label: 'How many workers', name: 'slots', type: 'number', min: 1, required: true, value: '10' })}
    </div>
    <div class="row-2">
      ${V.field({ label: 'Minimum time (seconds)', name: 'min_seconds', type: 'number', min: 20, value: '60',
        hint: 'Anything faster gets flagged for you' })}
      ${V.field({ label: 'Time to finish (minutes)', name: 'hold_minutes', type: 'number', min: 5, value: '60',
        hint: 'Then the slot returns to the pool' })}
    </div>
    ${V.field({ label: 'Country', name: 'country', placeholder: 'Leave blank for anywhere' })}
    <div id="cost-preview" class="cost">Cost: <b>--</b></div>
    <button class="btn btn-lg" type="submit">Fund and publish</button>
  </form>
</div>`,
  });
});

app.post('/merchant/jobs/new', need('merchant'), active, (req, res) => {
  const b = req.body;
  const rate = money.parseAmount(b.rate);
  const slots = Math.floor(Number(b.slots));
  const title = String(b.title || '').trim();

  if (!title) return fail(res, 'Give the job a title.');
  if (!rate || rate <= 0) return fail(res, 'Enter a pay rate like 5.00');
  if (!Number.isFinite(slots) || slots < 1) return fail(res, 'How many workers do you need?');
  if (!String(b.instructions || '').trim()) return fail(res, 'Write what the worker must do.');
  if (!String(b.proof_required || '').trim()) return fail(res, 'Say what proof you want back.');

  const total = rate * slots;
  if (money.balance(req.user.id) < total) {
    return fail(res, `That job costs ${money.fmt(total)} and your balance is ${money.fmt(money.balance(req.user.id))}. Add funds first.`);
  }

  db.exec('BEGIN IMMEDIATE');
  try {
    const info = db.prepare(`
      INSERT INTO jobs (merchant_id, category_id, title, instructions, proof_required,
                        rate, slots, min_seconds, hold_minutes, country)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id, b.category_id ? Number(b.category_id) : null, title,
      String(b.instructions).trim(), String(b.proof_required).trim(),
      rate, slots,
      Math.max(numSetting('min_seconds_floor'), Number(b.min_seconds) || 60),
      Math.max(5, Number(b.hold_minutes) || 60),
      String(b.country || '').trim() || null
    );
    const jobId = Number(info.lastInsertRowid);
    money.fundJob(jobId, req.user.id, total);
    db.exec('COMMIT');
    audit(req.user.id, 'job_posted', `job:${jobId}`, { total, slots, rate }, req.ip);
    back(res, '/merchant/jobs/' + jobId, `Live. ${money.fmt(total)} is held in escrow.`, 'ok');
  } catch (err) {
    db.exec('ROLLBACK');
    fail(res, err.message);
  }
});

app.get('/merchant/jobs/:id', need('merchant'), (req, res) => {
  const job = db.prepare('SELECT * FROM jobs WHERE id = ? AND merchant_id = ?')
    .get(Number(req.params.id), req.user.id);
  if (!job) return fail(res, 'That job is not yours.');

  const e = money.escrowOf(job.id);
  const subs = db.prepare(`
    SELECT s.*, u.name AS worker FROM submissions s JOIN users u ON u.id = s.worker_id
    WHERE s.job_id = ? ORDER BY s.id DESC
  `).all(job.id);

  send(req, res, {
    title: job.title, active: 'myjobs', wide: true,
    body: `
<a class="back" href="/merchant/jobs">&larr; My jobs</a>
<div class="page-head"><div><h1>${V.esc(job.title)}</h1>
  <p class="muted">${V.statusPill(job.status)} · ${job.slots_filled} of ${job.slots} slots taken</p></div>
  <div class="btn-row">
    ${job.status === 'active' ? `<form method="post" action="/merchant/jobs/${job.id}/pause">${csrfField(req)}<button class="btn btn-ghost" type="submit">Pause</button></form>` : ''}
    ${job.status === 'paused' ? `<form method="post" action="/merchant/jobs/${job.id}/resume">${csrfField(req)}<button class="btn btn-ghost" type="submit">Resume</button></form>` : ''}
    ${job.status !== 'cancelled' && job.status !== 'completed' ? `
      <form method="post" action="/merchant/jobs/${job.id}/cancel"
            onsubmit="return confirm('Cancel this job? Unspent funds return to your balance. Work already submitted still needs a decision.')">
        ${csrfField(req)}<button class="btn btn-danger" type="submit">Cancel</button></form>` : ''}
  </div></div>

<div class="stat-row">
  <div class="stat"><b>${V.money(e.held)}</b><span>funded</span></div>
  <div class="stat ok"><b>${V.money(e.released)}</b><span>paid out</span></div>
  <div class="stat"><b>${V.money(e.held - e.released - e.refunded)}</b><span>still held</span></div>
  ${e.refunded ? `<div class="stat"><b>${V.money(e.refunded)}</b><span>returned</span></div>` : ''}
</div>

<div class="card">
  <div class="card-head"><h2>Submissions</h2></div>
  ${subs.length ? `<div class="table-wrap"><table>
    <thead><tr><th>Worker</th><th>Time</th><th>Sent</th><th>State</th><th></th></tr></thead>
    <tbody>${subs.map(s => `<tr${s.flagged ? ' class="flagged"' : ''}>
      <td>${V.esc(s.worker)}${s.flagged ? ' <span class="flag">flagged</span>' : ''}</td>
      <td class="num">${V.mmss(s.seconds_spent)}</td>
      <td class="dim">${s.submitted_at ? V.ago(s.submitted_at) : '--'}</td>
      <td>${V.statusPill(s.status)}</td>
      <td class="right">${s.status === 'submitted'
        ? `<a class="btn btn-sm" href="/merchant/review#s${s.id}">Review</a>` : ''}</td>
    </tr>`).join('')}</tbody></table></div>`
    : '<div class="pad muted">Nobody has taken this job yet.</div>'}
</div>`,
  });
});

for (const [action, status] of [['pause', 'paused'], ['resume', 'active']]) {
  app.post('/merchant/jobs/:id/' + action, need('merchant'), (req, res) => {
    db.prepare("UPDATE jobs SET status = ? WHERE id = ? AND merchant_id = ? AND status IN ('active','paused')")
      .run(status, Number(req.params.id), req.user.id);
    back(res, '/merchant/jobs/' + Number(req.params.id), status === 'paused' ? 'Paused.' : 'Live again.', 'ok');
  });
}

app.post('/merchant/jobs/:id/cancel', need('merchant'), (req, res) => {
  const id = Number(req.params.id);
  const job = db.prepare('SELECT * FROM jobs WHERE id = ? AND merchant_id = ?').get(id, req.user.id);
  if (!job) return fail(res, 'That job is not yours.');

  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare("UPDATE jobs SET status = 'cancelled' WHERE id = ?").run(id);
    // Work already sent still deserves a decision, so only untouched slots and
    // unspent money are released.
    db.prepare("UPDATE submissions SET status = 'expired' WHERE job_id = ? AND status = 'started'").run(id);
    const pending = db.prepare("SELECT COUNT(*) AS n FROM submissions WHERE job_id = ? AND status = 'submitted'").get(id).n;
    const keep = pending * job.rate;
    const remaining = money.escrowRemaining(id);
    const giveBack = Math.max(0, remaining - keep);
    if (giveBack > 0) {
      db.prepare('UPDATE escrow SET refunded = refunded + ? WHERE job_id = ?').run(giveBack, id);
      money.entry(job.merchant_id, 'job_refund', giveBack, { type: 'job', id },
        `Cancelled job #${id} - unused funds returned`);
    }
    db.exec('COMMIT');
    back(res, '/merchant/jobs/' + id,
      pending ? `Cancelled. ${money.fmt(giveBack)} returned; ${pending} submission${pending === 1 ? '' : 's'} still need a decision.`
              : `Cancelled. ${money.fmt(giveBack)} returned to your balance.`, 'ok');
  } catch (err) {
    db.exec('ROLLBACK');
    fail(res, err.message);
  }
});

app.get('/merchant/review', need('merchant'), (req, res) => {
  const subs = db.prepare(`
    SELECT s.*, j.title, j.rate, j.min_seconds, j.proof_required, u.name AS worker
    FROM submissions s JOIN jobs j ON j.id = s.job_id JOIN users u ON u.id = s.worker_id
    WHERE s.merchant_id = ? AND s.status = 'submitted'
    ORDER BY s.flagged DESC, s.id ASC
  `).all(req.user.id);

  send(req, res, {
    title: 'Review work', active: 'review',
    body: `
<h1>Review work</h1>
<p class="muted">${subs.length} waiting. Flagged ones are shown first &mdash; flagged does not mean bad,
   it means worth a closer look.</p>

${subs.length ? subs.map(s => `
<div class="card review" id="s${s.id}">
  <div class="card-head">
    <div><b>${V.esc(s.worker)}</b> <span class="dim">on</span> ${V.esc(s.title)}</div>
    <span class="dim">${V.ago(s.submitted_at)}</span>
  </div>
  <div class="pad">
    ${s.flagged ? `<div class="alert alert-warn"><b>Flagged:</b> ${V.esc(s.flag_reason)}</div>` : ''}
    <dl class="kv">
      <dt>Time spent</dt><dd class="${s.seconds_spent < s.min_seconds ? 'bad' : ''}">${V.mmss(s.seconds_spent)}
        <span class="dim">(job expects ${V.mmss(s.min_seconds)})</span></dd>
      <dt>Pays</dt><dd>${V.money(s.rate)}</dd>
    </dl>
    <h3>Proof</h3>
    <div class="prose">${V.esc(s.proof_text || '').replace(/\n/g, '<br>')}</div>
    ${s.proof_file ? `<img class="proof-img" src="/proof/${V.esc(s.proof_file)}" alt="Proof screenshot">` : ''}

    <div class="review-actions">
      <form method="post" action="/submissions/${s.id}/approve">
        ${csrfField(req)}<button class="btn" type="submit">Approve and pay ${V.money(s.rate)}</button>
      </form>
      <form method="post" action="/submissions/${s.id}/reject" class="reject-form">
        ${csrfField(req)}
        <input type="text" name="note" placeholder="Why is it being rejected?" required maxlength="200">
        <button class="btn btn-danger" type="submit">Reject</button>
      </form>
    </div>
    <p class="fine">Rejecting good work to avoid paying is reportable. The worker can ask an admin to look.</p>
  </div>
</div>`).join('') : '<div class="empty">Nothing is waiting for you.</div>'}`,
  });
});

app.post('/submissions/:id/approve', need('merchant'), (req, res) => {
  const id = Number(req.params.id);
  db.exec('BEGIN IMMEDIATE');
  try {
    const s = db.prepare("SELECT * FROM submissions WHERE id = ? AND merchant_id = ? AND status = 'submitted'")
      .get(id, req.user.id);
    if (!s) throw new Error('That submission is not waiting for you.');
    const job = db.prepare('SELECT * FROM jobs WHERE id = ?').get(s.job_id);

    const paid = money.payForSubmission(s, job);
    db.prepare("UPDATE submissions SET status = 'approved', reviewed_at = datetime('now') WHERE id = ?").run(id);

    // A job with every slot approved is finished; release anything left.
    const approved = db.prepare("SELECT COUNT(*) AS n FROM submissions WHERE job_id = ? AND status = 'approved'").get(job.id).n;
    if (approved >= job.slots) {
      db.prepare("UPDATE jobs SET status = 'completed' WHERE id = ?").run(job.id);
    }
    db.exec('COMMIT');
    audit(req.user.id, 'approve', `submission:${id}`, paid, req.ip);
    back(res, '/merchant/review', `Paid ${money.fmt(paid.net)} to the worker.`, 'ok');
  } catch (err) {
    db.exec('ROLLBACK');
    fail(res, err.message);
  }
});

app.post('/submissions/:id/reject', need('merchant'), (req, res) => {
  const id = Number(req.params.id);
  const note = String(req.body.note || '').trim().slice(0, 200);
  if (!note) return fail(res, 'Tell the worker why. A rejection without a reason is not allowed.');

  db.exec('BEGIN IMMEDIATE');
  let workerId;
  try {
    const s = db.prepare("SELECT * FROM submissions WHERE id = ? AND merchant_id = ? AND status = 'submitted'")
      .get(id, req.user.id);
    if (!s) throw new Error('That submission is not waiting for you.');
    workerId = s.worker_id;

    db.prepare("UPDATE submissions SET status = 'rejected', review_note = ?, reviewed_at = datetime('now') WHERE id = ?")
      .run(note, id);
    // The slot goes back so somebody else can do the work the buyer paid for.
    db.prepare('UPDATE jobs SET slots_filled = MAX(0, slots_filled - 1) WHERE id = ?').run(s.job_id);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    return fail(res, err.message);
  }

  const suspended = spam.afterRejection(workerId);
  audit(req.user.id, 'reject', `submission:${id}`, { note, suspended }, req.ip);
  back(res, '/merchant/review', 'Rejected, and the slot is open again.', 'info');
});

// ======================================================================
// WALLET
// ======================================================================
app.get('/wallet', need(), (req, res) => {
  const u = req.user;
  const rows = money.history(u.id);
  const deposits = db.prepare('SELECT * FROM deposits WHERE user_id = ? ORDER BY id DESC LIMIT 10').all(u.id);
  const withdrawals = db.prepare('SELECT * FROM withdrawals WHERE user_id = ? ORDER BY id DESC LIMIT 10').all(u.id);

  const rate = numSetting('usd_rate');
  const minDep = numSetting('min_deposit');

  const addFunds = u.role !== 'merchant' ? '' : `
    <div class="card pad">
      <h2>Add funds</h2>
      <p class="muted">Smallest deposit is ${V.money(minDep)}. Money lands in your balance
         only after the payment provider confirms it &mdash; never on our say-so.</p>

      ${eps.configured() ? `
      <div class="pay-option">
        <div class="pay-head"><b>bKash, Nagad, Rocket, card</b><span class="pill s-active">instant</span></div>
        <form method="post" action="/wallet/deposit/eps" class="pay-form">
          ${csrfField(req)}
          <input type="text" name="amount" placeholder="Amount in ${V.esc(getSetting('currency'))}" required inputmode="decimal">
          <button class="btn" type="submit">Pay with EPS</button>
        </form>
        <span class="hint">Whole amounts only, no paisa.</span>
      </div>` : ''}

      ${cryptomus.configured() ? `
      <div class="pay-option">
        <div class="pay-head"><b>Crypto</b><span class="pill s-active">USDT, BTC and others</span></div>
        <form method="post" action="/wallet/deposit/crypto" class="pay-form">
          ${csrfField(req)}
          <input type="number" name="usd" step="0.01" min="1" placeholder="Amount in USD" required
                 id="usd-input" data-rate="${rate}">
          <button class="btn" type="submit">Pay with crypto</button>
        </form>
        <span class="hint" id="usd-preview">Rate: $1 = ${V.money(rate)}. You are credited in
          ${V.esc(getSetting('currency'))} at that rate.</span>
      </div>` : ''}

      ${!eps.configured() && !cryptomus.configured() ? `
      <div class="alert alert-warn">No payment provider is switched on yet. Record a transfer below
        and an admin will confirm it by hand.</div>` : ''}

      <details class="manual">
        <summary>Paid another way? Record it here</summary>
        <p class="muted">Use this only if you sent money outside the site. An admin checks the
           reference against the account before crediting anything.</p>
        <form method="post" action="/wallet/deposit">
          ${csrfField(req)}
          <div class="row-2">
            ${V.field({ label: 'Amount', name: 'amount', required: true, placeholder: '500.00' })}
            ${V.field({ label: 'Method', name: 'method', type: 'select', options: [
              { value: 'bkash', label: 'bKash' }, { value: 'nagad', label: 'Nagad' },
              { value: 'bank', label: 'Bank transfer' }, { value: 'other', label: 'Other' }] })}
          </div>
          ${V.field({ label: 'Transaction reference', name: 'reference', required: true,
            hint: 'The ID from your payment app, so it can be matched' })}
          <button class="btn btn-ghost" type="submit">Record it</button>
        </form>
      </details>
    </div>`;

  const withdraw = u.role === 'worker' ? `
    <div class="card pad">
      <h2>Withdraw</h2>
      <p class="muted">Smallest withdrawal is ${V.money(numSetting('min_withdrawal'))}.
         The amount leaves your balance straight away and is paid out after review.</p>
      <form method="post" action="/wallet/withdraw">
        ${csrfField(req)}
        <div class="row-2">
          ${V.field({ label: 'Amount', name: 'amount', required: true })}
          ${V.field({ label: 'Method', name: 'method', type: 'select', options: [
            { value: 'bkash', label: 'bKash' }, { value: 'nagad', label: 'Nagad' },
            { value: 'bank', label: 'Bank transfer' }] })}
        </div>
        ${V.field({ label: 'Where to send it', name: 'detail', required: true,
          placeholder: 'Your number or account' })}
        <button class="btn" type="submit">Request withdrawal</button>
      </form>
    </div>` : '';

  send(req, res, {
    title: 'Wallet', active: 'wallet',
    body: `
<div class="page-head"><h1>Wallet</h1>
  <div class="big-balance">${V.money(money.balance(u.id))}</div></div>

<div class="two">
  ${addFunds}${withdraw}
  <div class="card">
    <div class="card-head"><h2>History</h2></div>
    ${rows.length ? `<div class="table-wrap"><table>
      <thead><tr><th>When</th><th>What</th><th class="right">Amount</th></tr></thead>
      <tbody>${rows.map(r => `<tr>
        <td class="dim">${V.ago(r.created_at)}</td>
        <td>${V.esc(r.note || r.kind)}</td>
        <td class="num right ${r.amount >= 0 ? 'pos' : 'neg'}">${r.amount >= 0 ? '+' : '-'}${V.money(Math.abs(r.amount))}</td>
      </tr>`).join('')}</tbody></table></div>` : '<div class="pad muted">Nothing yet.</div>'}
  </div>
</div>

${deposits.length ? `<div class="card"><div class="card-head"><h2>Deposits</h2></div>
  <div class="table-wrap"><table><thead><tr><th>When</th><th>Via</th><th>Reference</th><th class="right">Amount</th><th>State</th><th></th></tr></thead>
  <tbody>${deposits.map(d => `<tr><td class="dim">${V.ago(d.created_at)}</td>
    <td>${V.esc(d.provider === 'manual' ? d.method : d.provider)}</td>
    <td class="mono clip">${V.esc(String(d.provider_ref || d.reference || '').slice(0, 24))}</td>
    <td class="num right">${V.money(d.amount)}</td>
    <td>${V.statusPill(d.status)}</td>
    <td class="right">${d.status === 'pending' && d.pay_url
      ? `<a class="link" href="${V.esc(d.pay_url)}">Pay</a>` : ''}</td></tr>`).join('')}</tbody></table></div></div>` : ''}

${withdrawals.length ? `<div class="card"><div class="card-head"><h2>Withdrawals</h2></div>
  <div class="table-wrap"><table><thead><tr><th>When</th><th>Method</th><th class="right">Amount</th><th>State</th><th>Note</th></tr></thead>
  <tbody>${withdrawals.map(w => `<tr><td class="dim">${V.ago(w.created_at)}</td><td>${V.esc(w.method)}</td>
    <td class="num right">${V.money(w.amount)}</td><td>${V.statusPill(w.status)}</td>
    <td class="dim">${V.esc(w.note || '')}</td></tr>`).join('')}</tbody></table></div></div>` : ''}`,
  });
});

app.post('/wallet/deposit', need('merchant'), (req, res) => {
  const amount = money.parseAmount(req.body.amount);
  if (!amount || amount <= 0) return fail(res, 'Enter an amount like 500.00');
  const ref = String(req.body.reference || '').trim();
  if (!ref) return fail(res, 'The transaction reference is needed to match your payment.');

  db.prepare('INSERT INTO deposits (user_id, amount, method, reference) VALUES (?, ?, ?, ?)')
    .run(req.user.id, amount, String(req.body.method || 'other'), ref);
  back(res, '/wallet', 'Recorded. It will show in your balance once an admin confirms it.', 'ok');
});

app.post('/wallet/withdraw', need('worker'), active, (req, res) => {
  const amount = money.parseAmount(req.body.amount);
  if (!amount || amount <= 0) return fail(res, 'Enter an amount like 100.00');
  try {
    money.requestWithdrawal(req.user.id, amount,
      String(req.body.method || 'bkash'), String(req.body.detail || '').trim());
    back(res, '/wallet', 'Requested. It has left your balance and is queued for payout.', 'ok');
  } catch (err) {
    fail(res, err.message);
  }
});

// ======================================================================
// REPORTS
// ======================================================================
app.post('/report', need(), (req, res) => {
  const against = Number(req.body.against_id);
  const reason = String(req.body.reason || 'other').slice(0, 40);
  const detail = String(req.body.detail || '').trim().slice(0, 500);
  if (!against || against === req.user.id) return fail(res, 'That report does not make sense.');
  if (!detail) return fail(res, 'Say what happened.');

  db.prepare(`INSERT INTO reports (reporter_id, against_id, submission_id, job_id, reason, detail)
              VALUES (?, ?, ?, ?, ?, ?)`)
    .run(req.user.id, against,
         req.body.submission_id ? Number(req.body.submission_id) : null,
         req.body.job_id ? Number(req.body.job_id) : null,
         reason, detail);
  audit(req.user.id, 'report', `user:${against}`, { reason }, req.ip);
  back(res, req.get('referer') || '/', 'Reported. An admin will look at it.', 'ok');
});

// ======================================================================
// ADMIN
// ======================================================================
app.get('/admin', need('admin'), (req, res) => {
  const s = {
    users: db.prepare('SELECT COUNT(*) AS n FROM users').get().n,
    suspended: db.prepare("SELECT COUNT(*) AS n FROM users WHERE status = 'suspended'").get().n,
    jobs: db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE status = 'active'").get().n,
    reports: db.prepare("SELECT COUNT(*) AS n FROM reports WHERE status = 'open'").get().n,
    deposits: db.prepare("SELECT COUNT(*) AS n FROM deposits WHERE status = 'pending'").get().n,
    withdrawals: db.prepare("SELECT COUNT(*) AS n FROM withdrawals WHERE status = 'pending'").get().n,
    held: db.prepare('SELECT COALESCE(SUM(held - released - refunded), 0) AS n FROM escrow').get().n,
    fees: db.prepare("SELECT COALESCE(SUM(amount), 0) AS n FROM ledger WHERE kind = 'task_earning'").get().n,
  };
  const recent = db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 20').all();

  send(req, res, {
    title: 'Admin', active: 'admin', wide: true,
    body: `
<h1>Overview</h1>
<div class="stat-row">
  <div class="stat"><b>${s.users}</b><span>users</span></div>
  <div class="stat ${s.suspended ? 'bad' : ''}"><b>${s.suspended}</b><span>suspended</span></div>
  <div class="stat"><b>${s.jobs}</b><span>active jobs</span></div>
  <div class="stat ${s.reports ? 'warn' : ''}"><b>${s.reports}</b><span>open reports</span></div>
  <div class="stat ${s.deposits ? 'warn' : ''}"><b>${s.deposits}</b><span>deposits</span></div>
  <div class="stat ${s.withdrawals ? 'warn' : ''}"><b>${s.withdrawals}</b><span>withdrawals</span></div>
  <div class="stat"><b>${V.money(s.held)}</b><span>in escrow</span></div>
</div>
<div class="card"><div class="card-head"><h2>Recent activity</h2></div>
  <div class="table-wrap"><table><thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Subject</th><th>Detail</th></tr></thead>
  <tbody>${recent.map(a => `<tr><td class="dim">${V.ago(a.created_at)}</td>
    <td class="mono">${a.actor_id || '-'}</td><td>${V.esc(a.action)}</td>
    <td class="mono">${V.esc(a.subject || '')}</td>
    <td class="dim clip">${V.esc(String(a.detail || '').slice(0, 90))}</td></tr>`).join('')}
  </tbody></table></div></div>`,
  });
});

app.get('/admin/reports', need('admin'), (req, res) => {
  const rows = db.prepare(`
    SELECT r.*, a.name AS against_name, a.strikes, p.name AS reporter_name
    FROM reports r JOIN users a ON a.id = r.against_id JOIN users p ON p.id = r.reporter_id
    ORDER BY (r.status = 'open') DESC, r.id DESC LIMIT 100
  `).all();

  send(req, res, {
    title: 'Reports', active: 'reports', wide: true,
    body: `<h1>Reports</h1>
${rows.length ? rows.map(r => `
<div class="card">
  <div class="card-head">
    <div><b>${V.esc(r.reporter_name)}</b> <span class="dim">reported</span> <b>${V.esc(r.against_name)}</b>
      <span class="dim">(${r.strikes} strike${r.strikes === 1 ? '' : 's'})</span></div>
    ${V.statusPill(r.status)}
  </div>
  <div class="pad">
    <dl class="kv"><dt>Reason</dt><dd>${V.esc(r.reason)}</dd>
      <dt>Detail</dt><dd>${V.esc(r.detail || '')}</dd>
      ${r.submission_id ? `<dt>Submission</dt><dd><a class="link" href="/admin/submission/${r.submission_id}">#${r.submission_id}</a></dd>` : ''}
      ${r.outcome ? `<dt>Outcome</dt><dd>${V.esc(r.outcome)}</dd>` : ''}</dl>
    ${r.status === 'open' ? `<div class="review-actions">
      <form method="post" action="/admin/reports/${r.id}/uphold">${csrfField(req)}
        <input type="text" name="outcome" placeholder="What you decided" required maxlength="200">
        <button class="btn btn-danger" type="submit">Uphold &mdash; add a strike</button></form>
      <form method="post" action="/admin/reports/${r.id}/dismiss">${csrfField(req)}
        <button class="btn btn-ghost" type="submit">Dismiss</button></form>
    </div>` : ''}
  </div>
</div>`).join('') : '<div class="empty">No reports.</div>'}`,
  });
});

app.post('/admin/reports/:id/uphold', need('admin'), (req, res) => {
  const r = db.prepare("SELECT * FROM reports WHERE id = ? AND status = 'open'").get(Number(req.params.id));
  if (!r) return fail(res, 'That report is already closed.');
  const outcome = String(req.body.outcome || '').trim().slice(0, 200) || 'Upheld';

  db.prepare("UPDATE reports SET status = 'upheld', outcome = ?, reviewed_at = datetime('now') WHERE id = ?")
    .run(outcome, r.id);
  const suspended = spam.addStrike(r.against_id, outcome);
  audit(req.user.id, 'report_upheld', `user:${r.against_id}`, { outcome, suspended }, req.ip);
  back(res, '/admin/reports', suspended ? 'Upheld. That account is now suspended.' : 'Upheld. Strike added.', 'ok');
});

app.post('/admin/reports/:id/dismiss', need('admin'), (req, res) => {
  db.prepare("UPDATE reports SET status = 'dismissed', reviewed_at = datetime('now') WHERE id = ? AND status = 'open'")
    .run(Number(req.params.id));
  back(res, '/admin/reports', 'Dismissed.', 'info');
});

app.get('/admin/submission/:id', need('admin'), (req, res) => {
  const s = db.prepare(`
    SELECT s.*, j.title, j.proof_required, j.min_seconds, w.name AS worker, m.name AS merchant
    FROM submissions s JOIN jobs j ON j.id = s.job_id
    JOIN users w ON w.id = s.worker_id JOIN users m ON m.id = s.merchant_id
    WHERE s.id = ?
  `).get(Number(req.params.id));
  if (!s) return fail(res, 'No such submission.');
  send(req, res, {
    title: 'Submission', active: 'reports',
    body: `<a class="back" href="/admin/reports">&larr; Reports</a>
<h1>Submission #${s.id}</h1>
<div class="card pad">
  <dl class="kv">
    <dt>Job</dt><dd>${V.esc(s.title)}</dd>
    <dt>Worker</dt><dd>${V.esc(s.worker)}</dd>
    <dt>Buyer</dt><dd>${V.esc(s.merchant)}</dd>
    <dt>Time spent</dt><dd>${V.mmss(s.seconds_spent)} (expected ${V.mmss(s.min_seconds)})</dd>
    <dt>State</dt><dd>${V.statusPill(s.status)}</dd>
    ${s.flag_reason ? `<dt>Flagged</dt><dd>${V.esc(s.flag_reason)}</dd>` : ''}
    ${s.review_note ? `<dt>Buyer said</dt><dd>${V.esc(s.review_note)}</dd>` : ''}
  </dl>
  <h3>Proof required</h3><div class="prose muted">${V.esc(s.proof_required).replace(/\n/g, '<br>')}</div>
  <h3>Proof sent</h3><div class="prose">${V.esc(s.proof_text || '').replace(/\n/g, '<br>')}</div>
  ${s.proof_file ? `<img class="proof-img" src="/proof/${V.esc(s.proof_file)}" alt="Proof">` : ''}
</div>`,
  });
});

app.get('/admin/money', need('admin'), (req, res) => {
  const deps = db.prepare(`SELECT d.*, u.name, u.email FROM deposits d JOIN users u ON u.id = d.user_id
    ORDER BY (d.status = 'pending') DESC, d.id DESC LIMIT 60`).all();
  const wds = db.prepare(`SELECT w.*, u.name, u.email FROM withdrawals w JOIN users u ON u.id = w.user_id
    ORDER BY (w.status = 'pending') DESC, w.id DESC LIMIT 60`).all();

  send(req, res, {
    title: 'Money', active: 'money', wide: true,
    body: `<h1>Money</h1>
<div class="card"><div class="card-head"><h2>Deposits</h2></div>
<div class="table-wrap"><table>
  <thead><tr><th>User</th><th>Method</th><th>Reference</th><th class="right">Amount</th><th>State</th><th></th></tr></thead>
  <tbody>${deps.map(d => `<tr>
    <td>${V.esc(d.name)}<div class="dim">${V.esc(d.email)}</div></td>
    <td>${V.esc(d.method)}</td><td class="mono">${V.esc(d.reference || '')}</td>
    <td class="num right">${V.money(d.amount)}</td><td>${V.statusPill(d.status)}</td>
    <td class="right">${d.status === 'pending' ? `
      <form method="post" action="/admin/deposits/${d.id}/approve" class="inline">${csrfField(req)}
        <button class="btn btn-sm" type="submit">Confirm</button></form>
      <form method="post" action="/admin/deposits/${d.id}/reject" class="inline">${csrfField(req)}
        <button class="btn btn-ghost btn-sm" type="submit">Reject</button></form>` : ''}</td>
  </tr>`).join('') || '<tr><td colspan="6" class="muted pad">No deposits.</td></tr>'}</tbody>
</table></div></div>

<div class="card"><div class="card-head"><h2>Withdrawals</h2></div>
<div class="table-wrap"><table>
  <thead><tr><th>User</th><th>Method</th><th>Send to</th><th class="right">Amount</th><th>State</th><th></th></tr></thead>
  <tbody>${wds.map(w => `<tr>
    <td>${V.esc(w.name)}<div class="dim">${V.esc(w.email)}</div></td>
    <td>${V.esc(w.method)}</td><td class="mono">${V.esc(w.detail || '')}</td>
    <td class="num right">${V.money(w.amount)}</td><td>${V.statusPill(w.status)}</td>
    <td class="right">${w.status === 'pending' ? `
      <form method="post" action="/admin/withdrawals/${w.id}/pay" class="inline">${csrfField(req)}
        <button class="btn btn-sm" type="submit">Mark paid</button></form>
      <form method="post" action="/admin/withdrawals/${w.id}/reject" class="inline">${csrfField(req)}
        <input type="text" name="note" placeholder="Reason" required maxlength="120">
        <button class="btn btn-ghost btn-sm" type="submit">Reject</button></form>` : ''}</td>
  </tr>`).join('') || '<tr><td colspan="6" class="muted pad">No withdrawals.</td></tr>'}</tbody>
</table></div></div>`,
  });
});

app.post('/admin/deposits/:id/approve', need('admin'), (req, res) => {
  try {
    money.creditDeposit(Number(req.params.id), req.user.id);
    audit(req.user.id, 'deposit_approved', `deposit:${req.params.id}`, null, req.ip);
    back(res, '/admin/money', 'Credited.', 'ok');
  } catch (err) { fail(res, err.message); }
});

app.post('/admin/deposits/:id/reject', need('admin'), (req, res) => {
  db.prepare("UPDATE deposits SET status = 'rejected', reviewed_at = datetime('now') WHERE id = ? AND status = 'pending'")
    .run(Number(req.params.id));
  back(res, '/admin/money', 'Rejected.', 'info');
});

app.post('/admin/withdrawals/:id/pay', need('admin'), (req, res) => {
  try {
    money.settleWithdrawal(Number(req.params.id), true, 'Paid');
    audit(req.user.id, 'withdrawal_paid', `withdrawal:${req.params.id}`, null, req.ip);
    back(res, '/admin/money', 'Marked as paid.', 'ok');
  } catch (err) { fail(res, err.message); }
});

app.post('/admin/withdrawals/:id/reject', need('admin'), (req, res) => {
  try {
    money.settleWithdrawal(Number(req.params.id), false, String(req.body.note || '').slice(0, 120));
    back(res, '/admin/money', 'Rejected and the balance returned.', 'info');
  } catch (err) { fail(res, err.message); }
});

app.get('/admin/users', need('admin'), (req, res) => {
  const q = String(req.query.q || '').trim();
  const sql = `
    SELECT u.*,
      (SELECT COALESCE(SUM(amount), 0) FROM ledger WHERE user_id = u.id) AS balance,
      (SELECT COUNT(*) FROM submissions WHERE worker_id = u.id AND status = 'approved') AS approved,
      (SELECT COUNT(*) FROM submissions WHERE worker_id = u.id AND status = 'rejected') AS rejected
    FROM users u
    ${q ? 'WHERE u.name LIKE ? OR u.email LIKE ?' : ''}
    ORDER BY u.id DESC LIMIT 200`;
  const rows = db.prepare(sql).all(...(q ? ['%' + q + '%', '%' + q + '%'] : []));

  send(req, res, {
    title: 'Users', active: 'users', wide: true,
    body: `<div class="page-head"><h1>Users</h1>
      <form class="filters" method="get"><input type="search" name="q" value="${V.esc(q)}" placeholder="Name or email">
      <button class="btn btn-ghost" type="submit">Search</button></form></div>
<div class="card"><div class="table-wrap"><table>
  <thead><tr><th>User</th><th>Role</th><th class="right">Balance</th><th>Approved</th><th>Rejected</th><th>Strikes</th><th>State</th><th></th></tr></thead>
  <tbody>${rows.map(u => `<tr>
    <td>${V.esc(u.name)}<div class="dim">${V.esc(u.email)}</div></td>
    <td>${V.esc(u.role)}</td>
    <td class="num right">${V.money(u.balance)}</td>
    <td class="num">${u.approved}</td><td class="num ${u.rejected ? 'bad' : ''}">${u.rejected}</td>
    <td class="num">${u.strikes}</td>
    <td>${V.statusPill(u.status)}${u.suspend_reason ? `<div class="dim clip">${V.esc(u.suspend_reason)}</div>` : ''}</td>
    <td class="right">${u.role === 'admin' ? '' : (u.status === 'active' ? `
      <form method="post" action="/admin/users/${u.id}/suspend" class="inline">${csrfField(req)}
        <input type="text" name="reason" placeholder="Reason" required maxlength="120">
        <button class="btn btn-ghost btn-sm" type="submit">Suspend</button></form>` : `
      <form method="post" action="/admin/users/${u.id}/restore" class="inline">${csrfField(req)}
        <button class="btn btn-sm" type="submit">Restore</button></form>`)}</td>
  </tr>`).join('')}</tbody>
</table></div></div>`,
  });
});

app.post('/admin/users/:id/suspend', need('admin'), (req, res) => {
  const id = Number(req.params.id);
  const target = db.prepare('SELECT role FROM users WHERE id = ?').get(id);
  if (!target || target.role === 'admin') return fail(res, 'That account cannot be suspended here.');
  spam.suspend(id, String(req.body.reason || 'Suspended by an admin').slice(0, 120), numSetting('suspend_days'));
  audit(req.user.id, 'suspend', `user:${id}`, { reason: req.body.reason }, req.ip);
  back(res, '/admin/users', 'Suspended.', 'ok');
});

app.post('/admin/users/:id/restore', need('admin'), (req, res) => {
  db.prepare("UPDATE users SET status = 'active', suspended_until = NULL, suspend_reason = NULL, strikes = 0 WHERE id = ?")
    .run(Number(req.params.id));
  audit(req.user.id, 'restore', `user:${req.params.id}`, null, req.ip);
  back(res, '/admin/users', 'Restored, strikes cleared.', 'ok');
});

// ======================================================================
// DEPOSITS THROUGH A GATEWAY
// ======================================================================
function baseUrl(req) {
  return process.env.PUBLIC_URL || `${req.protocol}://${req.get('host')}`;
}

function recordEvent(provider, depositId, ref, verified, status, payload, ip) {
  db.prepare(`INSERT INTO gateway_events (provider, deposit_id, ref, verified, status, payload, ip)
              VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(provider, depositId || null, ref || null, verified ? 1 : 0, status || null,
         typeof payload === 'string' ? payload.slice(0, 20000) : JSON.stringify(payload).slice(0, 20000),
         ip || null);
}

/* Start an EPS payment: bKash, Nagad, Rocket, card, internet banking. */
app.post('/wallet/deposit/eps', need('merchant'), active, async (req, res) => {
  if (!eps.configured()) return fail(res, 'Card and mobile banking payments are not switched on yet.');

  const amount = money.parseAmount(req.body.amount);
  const min = numSetting('min_deposit');
  if (!amount || amount < min) return fail(res, `The smallest deposit is ${money.fmt(min)}`);

  // EPS works in whole taka; refuse anything that would round.
  if (amount % 100 !== 0) return fail(res, 'Enter a whole amount, without paisa.');

  const mtid = eps.newTransactionId();
  const info = db.prepare(`INSERT INTO deposits (user_id, amount, method, provider, provider_ref, reference)
                           VALUES (?, ?, ?, 'eps', ?, ?)`)
    .run(req.user.id, amount, 'eps', mtid, mtid);
  const depositId = Number(info.lastInsertRowid);

  try {
    const site = baseUrl(req);
    const started = await eps.initialize({
      orderId: depositId,
      merchantTransactionId: mtid,
      amount: amount / 100,
      ip: req.ip,
      customer: {
        name: req.user.name,
        email: req.user.email,
        phone: req.user.payout_detail || '01700000000',
        country: req.user.country === 'Bangladesh' ? 'BD' : 'BD',
      },
      urls: {
        success: `${site}/wallet/deposit/eps/return?mtid=${encodeURIComponent(mtid)}`,
        fail: `${site}/wallet/deposit/eps/return?mtid=${encodeURIComponent(mtid)}`,
        cancel: `${site}/wallet/deposit/eps/return?mtid=${encodeURIComponent(mtid)}`,
      },
    });

    db.prepare('UPDATE deposits SET pay_url = ? WHERE id = ?').run(started.redirectUrl, depositId);
    audit(req.user.id, 'deposit_started', `deposit:${depositId}`, { provider: 'eps', amount }, req.ip);
    res.redirect(started.redirectUrl);
  } catch (err) {
    money.failDeposit(depositId, 'init_failed');
    recordEvent('eps', depositId, mtid, 0, 'init_failed', { error: err.message }, req.ip);
    fail(res, `The payment could not be started: ${err.message}`);
  }
});

/* Where EPS sends the payer's browser back to.

   This proves nothing on its own - it is a URL the payer's browser was told to
   visit, and anyone can visit it. So it does not credit anything; it asks EPS
   what happened and shows the answer. */
app.get('/wallet/deposit/eps/return', need(), async (req, res) => {
  const mtid = String(req.query.mtid || '');
  const dep = db.prepare("SELECT * FROM deposits WHERE provider = 'eps' AND provider_ref = ?").get(mtid);
  if (!dep) return fail(res, 'That payment is not one of ours.');
  if (dep.user_id !== req.user.id && req.user.role !== 'admin') {
    return fail(res, 'That payment belongs to another account.');
  }

  let outcome = 'pending';
  let message = 'We are still waiting for the payment to settle.';
  try {
    const status = await eps.verify(mtid);
    recordEvent('eps', dep.id, mtid, 1, status.Status, status, req.ip);
    outcome = eps.classify(status.Status);

    if (outcome === 'paid') {
      const result = money.creditGatewayDeposit(dep.id, status.Status, status.TotalAmount, 'BDT');
      message = result.credited
        ? `Paid. ${money.fmt(dep.amount)} has been added to your balance.`
        : `Paid, and already added to your balance.`;
    } else if (outcome === 'failed') {
      money.failDeposit(dep.id, status.Status);
      message = `The payment did not go through (${V.esc(status.Status || 'failed')}). Nothing was charged to you by us.`;
    }
  } catch (err) {
    recordEvent('eps', dep.id, mtid, 0, 'verify_error', { error: err.message }, req.ip);
    message = `We could not confirm the payment yet: ${err.message}. If money left your account it will be credited once EPS confirms; contact support with reference ${mtid}.`;
  }

  send(req, res, {
    title: 'Payment', active: 'wallet',
    body: `
<div class="narrow-wide">
  <h1>${outcome === 'paid' ? 'Payment received' : outcome === 'failed' ? 'Payment not completed' : 'Payment pending'}</h1>
  <div class="alert alert-${outcome === 'paid' ? 'ok' : outcome === 'failed' ? 'stop' : 'warn'}">${message}</div>
  <div class="card pad">
    <dl class="kv">
      <dt>Reference</dt><dd class="mono">${V.esc(mtid)}</dd>
      <dt>Amount</dt><dd>${V.money(dep.amount)}</dd>
      <dt>Method</dt><dd>EPS (bKash, Nagad, card)</dd>
    </dl>
  </div>
  <div class="btn-row"><a class="btn" href="/wallet">Back to wallet</a>
    ${outcome !== 'paid' ? '<a class="btn btn-ghost" href="/support">Contact support</a>' : ''}</div>
</div>`,
  });
});

/* Start a Cryptomus payment. Crypto is priced in USD and converted at the rate
   in settings, shown to the payer before they commit. */
app.post('/wallet/deposit/crypto', need('merchant'), active, async (req, res) => {
  if (!cryptomus.configured()) return fail(res, 'Crypto payments are not switched on yet.');

  const usd = Number(String(req.body.usd || '').trim());
  if (!Number.isFinite(usd) || usd < 1) return fail(res, 'Enter an amount in USD, at least 1.');

  const rate = numSetting('usd_rate');                 // local units per 1 USD
  const credit = Math.round(usd * rate);
  const min = numSetting('min_deposit');
  if (credit < min) return fail(res, `That is under the smallest deposit of ${money.fmt(min)}`);

  const info = db.prepare(`INSERT INTO deposits (user_id, amount, method, provider, reference)
                           VALUES (?, ?, 'crypto', 'cryptomus', ?)`)
    .run(req.user.id, credit, `$${usd.toFixed(2)} @ ${rate / 100}`);
  const depositId = Number(info.lastInsertRowid);

  try {
    const site = baseUrl(req);
    const invoice = await cryptomus.createInvoice({
      orderId: depositId,
      amount: usd.toFixed(2),
      currency: 'USD',
      callbackUrl: `${site}/hooks/cryptomus`,
      successUrl: `${site}/wallet/deposit/crypto/return?id=${depositId}`,
      returnUrl: `${site}/wallet`,
    });

    db.prepare('UPDATE deposits SET provider_ref = ?, pay_url = ? WHERE id = ?')
      .run(invoice.uuid, invoice.url, depositId);
    audit(req.user.id, 'deposit_started', `deposit:${depositId}`,
          { provider: 'cryptomus', usd, credit }, req.ip);
    res.redirect(invoice.url);
  } catch (err) {
    money.failDeposit(depositId, 'init_failed');
    recordEvent('cryptomus', depositId, null, 0, 'init_failed', { error: err.message }, req.ip);
    fail(res, `The invoice could not be created: ${err.message}`);
  }
});

app.get('/wallet/deposit/crypto/return', need(), async (req, res) => {
  const dep = db.prepare("SELECT * FROM deposits WHERE id = ? AND provider = 'cryptomus'")
    .get(Number(req.query.id));
  if (!dep) return fail(res, 'That payment is not one of ours.');
  if (dep.user_id !== req.user.id && req.user.role !== 'admin') {
    return fail(res, 'That payment belongs to another account.');
  }

  // The webhook is the real mechanism. This is a courtesy check for somebody
  // staring at the screen, and it reaches the same conclusion the same way.
  let message = 'Waiting for the blockchain to confirm. This can take a few minutes.';
  let tone = 'warn';
  if (dep.status === 'approved') {
    message = `Confirmed. ${money.fmt(dep.amount)} has been added to your balance.`;
    tone = 'ok';
  } else if (dep.status === 'rejected') {
    message = 'That invoice was not paid.';
    tone = 'stop';
  } else {
    try {
      const info = await cryptomus.invoiceInfo({ uuid: dep.provider_ref, orderId: dep.id });
      recordEvent('cryptomus', dep.id, dep.provider_ref, 1, info.payment_status, info, req.ip);
      const state = cryptomus.classify(info.payment_status);
      if (state === 'paid') {
        money.creditGatewayDeposit(dep.id, info.payment_status, info.payment_amount, info.payer_currency);
        message = `Confirmed. ${money.fmt(dep.amount)} has been added to your balance.`;
        tone = 'ok';
      } else if (state === 'failed') {
        money.failDeposit(dep.id, info.payment_status);
        message = 'That invoice was not paid.';
        tone = 'stop';
      }
    } catch (err) {
      message = `Still waiting. ${err.message}`;
    }
  }

  send(req, res, {
    title: 'Crypto payment', active: 'wallet',
    body: `
<div class="narrow-wide">
  <h1>Crypto deposit</h1>
  <div class="alert alert-${tone}">${V.esc(message)}</div>
  <div class="card pad"><dl class="kv">
    <dt>Reference</dt><dd class="mono">${V.esc(dep.provider_ref || '')}</dd>
    <dt>Will credit</dt><dd>${V.money(dep.amount)}</dd>
    <dt>Priced at</dt><dd>${V.esc(dep.reference || '')}</dd>
  </dl></div>
  <div class="btn-row"><a class="btn" href="/wallet">Back to wallet</a>
    ${dep.pay_url && dep.status === 'pending'
      ? `<a class="btn btn-ghost" href="${V.esc(dep.pay_url)}">Open the invoice again</a>` : ''}</div>
</div>`,
  });
});

/* The Cryptomus webhook.

   No session, no CSRF - it is a server talking to a server, and the signature
   is what authenticates it. Anything that fails verification is written down
   and then ignored: an unverified callback must never move money, and it must
   never be answered with an error either, or a stranger gets to probe which
   deposit ids exist.
*/
app.post('/hooks/cryptomus', express.json({ limit: '256kb' }), (req, res) => {
  const payload = req.body || {};
  const ok = cryptomus.verifyWebhook(payload);
  const orderId = Number(payload.order_id) || null;

  recordEvent('cryptomus', orderId, payload.uuid, ok, payload.status, payload, req.ip);

  if (!ok) {
    audit(null, 'webhook_bad_signature', `cryptomus:${payload.uuid || '?'}`, null, req.ip);
    return res.status(200).json({ ok: true });
  }

  const dep = orderId
    ? db.prepare("SELECT * FROM deposits WHERE id = ? AND provider = 'cryptomus'").get(orderId)
    : null;
  if (!dep) return res.status(200).json({ ok: true });

  const state = cryptomus.classify(payload.status);
  try {
    if (state === 'paid') {
      const result = money.creditGatewayDeposit(
        dep.id, payload.status, payload.payment_amount, payload.payer_currency);
      if (result.credited) {
        audit(null, 'deposit_credited', `deposit:${dep.id}`,
              { provider: 'cryptomus', amount: dep.amount }, req.ip);
      }
    } else if (state === 'failed' && payload.is_final) {
      money.failDeposit(dep.id, payload.status);
    }
  } catch (err) {
    console.error('cryptomus webhook:', err.message);
  }

  // Always 200: Cryptomus retries on anything else, and a retry storm over a
  // bug on our side helps nobody.
  res.status(200).json({ ok: true });
});

app.get('/admin/gateway', need('admin'), (req, res) => {
  const events = db.prepare(`
    SELECT e.*, d.user_id, u.name AS user_name, d.amount
    FROM gateway_events e
    LEFT JOIN deposits d ON d.id = e.deposit_id
    LEFT JOIN users u ON u.id = d.user_id
    ORDER BY e.id DESC LIMIT 120
  `).all();
  const bad = db.prepare('SELECT COUNT(*) AS n FROM gateway_events WHERE verified = 0').get().n;

  send(req, res, {
    title: 'Gateway', active: 'gateway', wide: true,
    body: `<h1>Gateway activity</h1>
<div class="stat-row">
  <div class="stat"><b>${eps.configured() ? 'on' : 'off'}</b><span>EPS</span></div>
  <div class="stat"><b>${cryptomus.configured() ? 'on' : 'off'}</b><span>Cryptomus</span></div>
  <div class="stat ${bad ? 'bad' : ''}"><b>${bad}</b><span>unverified callbacks</span></div>
</div>
${bad ? `<div class="alert alert-warn">Unverified callbacks are recorded and ignored &mdash; they never
  move money. A few are normal (probes). A lot, with real references in them, means a key is wrong.</div>` : ''}
<div class="card"><div class="table-wrap"><table>
  <thead><tr><th>When</th><th>Provider</th><th>Deposit</th><th>User</th><th>Status</th><th>Signature</th><th>Reference</th></tr></thead>
  <tbody>${events.map(e => `<tr${e.verified ? '' : ' class="flagged"'}>
    <td class="dim">${V.ago(e.created_at)}</td>
    <td>${V.esc(e.provider)}</td>
    <td class="num">${e.deposit_id ? `#${e.deposit_id}` : '--'}</td>
    <td>${V.esc(e.user_name || '')}${e.amount ? `<div class="dim">${V.money(e.amount)}</div>` : ''}</td>
    <td>${V.esc(e.status || '')}</td>
    <td>${e.verified ? '<span class="pill s-approved">verified</span>' : '<span class="pill s-rejected">rejected</span>'}</td>
    <td class="mono clip">${V.esc(String(e.ref || '').slice(0, 30))}</td>
  </tr>`).join('') || '<tr><td colspan="7" class="muted pad">Nothing yet.</td></tr>'}</tbody>
</table></div></div>`,
  });
});

// ======================================================================
// SUPPORT
// ======================================================================
function telegramLinks() {
  const channel = getSetting('telegram_channel', '');
  const support = getSetting('telegram_support', '');
  if (!channel && !support) return '';
  return `<div class="tg-row">
    ${channel ? `<a class="tg" href="${V.esc(channel)}" target="_blank" rel="noopener">
      <b>Telegram channel</b><span>Announcements and new jobs</span></a>` : ''}
    ${support ? `<a class="tg" href="${V.esc(support)}" target="_blank" rel="noopener">
      <b>Telegram support</b><span>Message us directly</span></a>` : ''}
  </div>`;
}

app.get('/support', need(), (req, res) => {
  const tickets = db.prepare(
    'SELECT * FROM tickets WHERE user_id = ? ORDER BY updated_at DESC LIMIT 50'
  ).all(req.user.id);

  send(req, res, {
    title: 'Support', active: 'support',
    body: `
<div class="page-head"><div><h1>Support</h1>
  <p class="muted">Replies land right here, and we usually answer within a day.</p></div></div>

${telegramLinks()}

<div class="two">
  <div class="card pad">
    <h2>Start a conversation</h2>
    <form method="post" action="/support">
      ${csrfField(req)}
      ${V.field({ label: 'What is it about', name: 'topic', type: 'select', options: [
        { value: 'payment', label: 'Payment or withdrawal' },
        { value: 'rejection', label: 'A task was rejected unfairly' },
        { value: 'account', label: 'Account or suspension' },
        { value: 'shared_ip', label: 'Shared internet connection' },
        { value: 'job', label: 'A problem with a job' },
        { value: 'other', label: 'Something else' } ] })}
      ${V.field({ label: 'Subject', name: 'subject', required: true, placeholder: 'Short summary' })}
      ${V.field({ label: 'Message', name: 'body', type: 'textarea', rows: 6, required: true,
        hint: 'Include task or job numbers if you have them - it gets answered faster.' })}
      <button class="btn" type="submit">Send</button>
    </form>
  </div>

  <div class="card">
    <div class="card-head"><h2>Your conversations</h2></div>
    ${tickets.length ? `<div class="table-wrap"><table>
      <thead><tr><th>Subject</th><th>State</th><th>Updated</th></tr></thead>
      <tbody>${tickets.map(t => `<tr>
        <td><a class="link" href="/support/${t.id}">${V.esc(t.subject)}</a></td>
        <td>${V.statusPill(t.status)}</td>
        <td class="dim">${V.ago(t.updated_at)}</td>
      </tr>`).join('')}</tbody></table></div>`
      : '<div class="pad muted">Nothing yet.</div>'}
  </div>
</div>`,
  });
});

app.post('/support', need(), (req, res) => {
  const subject = String(req.body.subject || '').trim().slice(0, 120);
  const body = String(req.body.body || '').trim().slice(0, 4000);
  if (!subject || !body) return fail(res, 'Both a subject and a message are needed.');

  const open = db.prepare(
    "SELECT COUNT(*) AS n FROM tickets WHERE user_id = ? AND status != 'closed'"
  ).get(req.user.id).n;
  if (open >= 5) {
    return fail(res, 'You already have five open conversations. Reply in one of those instead.');
  }

  db.exec('BEGIN IMMEDIATE');
  try {
    const info = db.prepare('INSERT INTO tickets (user_id, subject, topic) VALUES (?, ?, ?)')
      .run(req.user.id, subject, String(req.body.topic || 'other'));
    const id = Number(info.lastInsertRowid);
    db.prepare('INSERT INTO ticket_messages (ticket_id, sender_id, from_staff, body) VALUES (?, ?, 0, ?)')
      .run(id, req.user.id, body);
    db.exec('COMMIT');
    res.redirect('/support/' + id);
  } catch (err) {
    db.exec('ROLLBACK');
    fail(res, err.message);
  }
});

function chatThread(ticket, messages, req, staffView) {
  return `
<div class="chat card">
  <div class="card-head">
    <div><b>${V.esc(ticket.subject)}</b>
      <div class="dim">${V.esc(ticket.topic || '')} · opened ${V.ago(ticket.created_at)}</div></div>
    ${V.statusPill(ticket.status)}
  </div>
  <div class="chat-body" id="chat-body" data-ticket="${ticket.id}" data-last="${messages.length ? messages[messages.length - 1].id : 0}">
    ${messages.map(m => `
      <div class="msg ${m.from_staff ? 'staff' : 'mine'}">
        <div class="who">${m.from_staff ? 'Support' : V.esc(ticket.user_name || 'You')}
          <span class="dim">${V.ago(m.created_at)}</span></div>
        <div class="bubble">${V.esc(m.body).replace(/\n/g, '<br>')}</div>
      </div>`).join('')}
  </div>
  ${ticket.status === 'closed' ? `<div class="pad muted">This conversation is closed.</div>` : `
  <form method="post" action="/support/${ticket.id}/reply" class="chat-form">
    ${csrfField(req)}
    <textarea name="body" rows="2" required placeholder="Write a reply"></textarea>
    <button class="btn" type="submit">Send</button>
  </form>`}
</div>`;
}

app.get('/support/:id', need(), (req, res) => {
  const id = Number(req.params.id);
  const ticket = db.prepare(`
    SELECT t.*, u.name AS user_name FROM tickets t JOIN users u ON u.id = t.user_id WHERE t.id = ?
  `).get(id);
  if (!ticket) return fail(res, 'No such conversation.');
  if (ticket.user_id !== req.user.id && req.user.role !== 'admin') {
    return fail(res, 'That conversation is not yours.');
  }
  const messages = db.prepare('SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY id').all(id);

  send(req, res, {
    title: ticket.subject, active: req.user.role === 'admin' ? 'support' : 'support',
    body: `<a class="back" href="${req.user.role === 'admin' ? '/admin/support' : '/support'}">&larr; Back</a>
      ${chatThread(ticket, messages, req, req.user.role === 'admin')}`,
  });
});

/* Polled by the open conversation so a reply appears without a refresh. Cheap:
   one indexed lookup, and only while somebody actually has the page open. */
app.get('/api/support/:id/messages', need(), (req, res) => {
  const id = Number(req.params.id);
  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(id);
  if (!ticket) return res.status(404).json({ error: 'No such conversation' });
  if (ticket.user_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not yours' });
  }
  const after = Number(req.query.after) || 0;
  const rows = db.prepare(
    'SELECT id, from_staff, body, created_at FROM ticket_messages WHERE ticket_id = ? AND id > ? ORDER BY id'
  ).all(id, after);
  res.json({ status: ticket.status, messages: rows });
});

app.post('/support/:id/reply', need(), (req, res) => {
  const id = Number(req.params.id);
  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(id);
  if (!ticket) return fail(res, 'No such conversation.');

  const staff = req.user.role === 'admin';
  if (ticket.user_id !== req.user.id && !staff) return fail(res, 'That conversation is not yours.');
  if (ticket.status === 'closed') return fail(res, 'That conversation is closed.');

  const body = String(req.body.body || '').trim().slice(0, 4000);
  if (!body) return fail(res, 'Write something first.');

  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare('INSERT INTO ticket_messages (ticket_id, sender_id, from_staff, body) VALUES (?, ?, ?, ?)')
      .run(id, req.user.id, staff ? 1 : 0, body);
    db.prepare("UPDATE tickets SET status = ?, updated_at = datetime('now') WHERE id = ?")
      .run(staff ? 'answered' : 'open', id);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    return fail(res, err.message);
  }
  res.redirect('/support/' + id);
});

app.get('/admin/support', need('admin'), (req, res) => {
  const rows = db.prepare(`
    SELECT t.*, u.name AS user_name, u.email,
      (SELECT COUNT(*) FROM ticket_messages WHERE ticket_id = t.id) AS msgs
    FROM tickets t JOIN users u ON u.id = t.user_id
    ORDER BY (t.status = 'open') DESC, t.updated_at DESC LIMIT 100
  `).all();

  send(req, res, {
    title: 'Support', active: 'support', wide: true,
    body: `<h1>Support</h1>
<div class="card"><div class="table-wrap"><table>
  <thead><tr><th>Subject</th><th>From</th><th>Topic</th><th>Messages</th><th>State</th><th>Updated</th><th></th></tr></thead>
  <tbody>${rows.map(t => `<tr>
    <td><a class="link" href="/support/${t.id}">${V.esc(t.subject)}</a></td>
    <td>${V.esc(t.user_name)}<div class="dim">${V.esc(t.email)}</div></td>
    <td class="dim">${V.esc(t.topic || '')}</td>
    <td class="num">${t.msgs}</td>
    <td>${V.statusPill(t.status)}</td>
    <td class="dim">${V.ago(t.updated_at)}</td>
    <td class="right">${t.status !== 'closed' ? `
      <form method="post" action="/support/${t.id}/close" class="inline">${csrfField(req)}
        <button class="btn btn-ghost btn-sm" type="submit">Close</button></form>` : ''}</td>
  </tr>`).join('') || '<tr><td colspan="7" class="muted pad">Nothing here.</td></tr>'}</tbody>
</table></div></div>`,
  });
});

app.post('/support/:id/close', need('admin'), (req, res) => {
  db.prepare("UPDATE tickets SET status = 'closed', updated_at = datetime('now') WHERE id = ?")
    .run(Number(req.params.id));
  back(res, '/admin/support', 'Closed.', 'ok');
});

// ---------------------------------------------------------- admin: devices
app.get('/admin/connections', need('admin'), (req, res) => {
  const ip = req.query.ip ? String(req.query.ip) : null;
  const min = Number(req.query.min) || 2;

  if (ip) {
    const accounts = auth.accountsOnIp(ip);
    return send(req, res, {
      title: 'Connection', active: 'connections', wide: true,
      body: `<a class="back" href="/admin/connections">&larr; All connections</a>
<h1 class="mono">${V.esc(ip)}</h1>
<p class="muted">${accounts.length} account${accounts.length === 1 ? '' : 's'} have signed in from here.</p>
<div class="alert alert-info">Shared addresses are normal &mdash; mobile networks, offices and
  families all produce this. Treat it as one signal among several, never on its own.</div>
<div class="card"><div class="table-wrap"><table>
  <thead><tr><th>User</th><th>Role</th><th>Joined</th><th>Sign-ins</th><th>Last seen</th><th>State</th></tr></thead>
  <tbody>${accounts.map(a => `<tr>
    <td>${V.esc(a.name)}<div class="dim">${V.esc(a.email)}</div></td>
    <td>${V.esc(a.role)}</td><td class="dim">${V.ago(a.created_at)}</td>
    <td class="num">${a.logins}</td><td class="dim">${V.ago(a.last_login)}</td>
    <td>${V.statusPill(a.status)}</td>
  </tr>`).join('')}</tbody></table></div></div>`,
    });
  }

  const rows = auth.sharedIps(min);
  send(req, res, {
    title: 'Connections', active: 'connections', wide: true,
    body: `<div class="page-head"><div><h1>Connections</h1>
      <p class="muted">Addresses with more than one account. Evidence, not a verdict.</p></div>
      <form class="filters" method="get">
        <select name="min">${[2, 3, 5, 10].map(n =>
          `<option value="${n}"${min === n ? ' selected' : ''}>${n}+ accounts</option>`).join('')}</select>
        <button class="btn btn-ghost" type="submit">Show</button></form></div>
<div class="card"><div class="table-wrap"><table>
  <thead><tr><th>Address</th><th>Accounts</th><th>Last seen</th><th></th></tr></thead>
  <tbody>${rows.map(r => `<tr>
    <td class="mono">${V.esc(r.ip)}</td>
    <td class="num ${r.accounts >= 5 ? 'bad' : ''}">${r.accounts}</td>
    <td class="dim">${V.ago(r.last_seen)}</td>
    <td class="right"><a class="link" href="/admin/connections?ip=${encodeURIComponent(r.ip)}">Look</a></td>
  </tr>`).join('') || '<tr><td colspan="4" class="muted pad">No shared connections.</td></tr>'}</tbody>
</table></div></div>`,
  });
});

// ======================================================================
app.use(express.static(path.join(__dirname, 'web'), { maxAge: '1h' }));

app.use((req, res) => {
  res.status(404).send(V.layout({
    title: 'Not found', user: req.user,
    body: '<div class="card pad"><h1>Page not found</h1><p><a class="btn" href="/">Back to the site</a></p></div>',
  }));
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send(V.layout({
    title: 'Error', user: null,
    body: `<div class="card pad"><h1>Something broke</h1><p class="muted">${V.esc(err.message)}</p></div>`,
  }));
});

// Housekeeping: abandoned slots go back in the pool, dead sessions get swept.
setInterval(() => {
  try { spam.releaseExpiredHolds(); auth.sweepSessions(); } catch (e) { console.error(e.message); }
}, 60000).unref();

app.listen(PORT, HOST, () => {
  spam.releaseExpiredHolds();
  const on = x => (x ? 'on' : 'off');
  console.log('');
  console.log('  Work Remote Job');
  console.log(`  http://localhost:${PORT}`);
  console.log('');
  console.log(`  data      ${DATA_DIR}`);
  console.log(`  sign-in   ${google.configured() ? 'Google' : 'NOT CONFIGURED - nobody can sign in'}`);
  console.log(`  admins    ${auth.adminEmails().join(', ') || 'none - set ADMIN_EMAILS'}`);
  console.log(`  payments  EPS ${on(eps.configured())}, Cryptomus ${on(cryptomus.configured())}`);
  if (process.env.ALLOW_DEV_LOGIN === '1') {
    console.log('  dev login ENABLED - /dev-login?email=... (this machine only)');
  }
  console.log('');
});
