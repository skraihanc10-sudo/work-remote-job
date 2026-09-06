/* ---------------------------------------------------------------------------
   Remote Work BD - a microjob marketplace.

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
const referrals = require('./lib/referrals');
const mail = require('./lib/mail');
const stats = require('./lib/stats');
const smtp = require('./lib/smtp');
const passwords = require('./lib/passwords');
const quality = require('./lib/quality');
const money = require('./lib/money');
const spam = require('./lib/antispam');
const V = require('./lib/views');

const PORT = Number(process.env.PORT) || 4700;
const HOST = process.env.HOST || '0.0.0.0';

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false, limit: '256kb' }));

/* One site, one hostname.

   Once a custom domain is added, the same site also answers on the Railway
   address. That is a problem rather than a convenience: the Google redirect URI
   matches exactly one host, session cookies are per host, and a person who
   signs in on one and comes back on the other is simply signed out. Search
   engines would also index both.

   So when PUBLIC_URL names a host, everything else redirects to it.

   Two exceptions. The platform's health check reaches the container on an
   internal hostname and must not be redirected, or the deploy is marked
   unhealthy and rolled back. And a payment gateway calling a webhook is a
   server, not a browser - some follow redirects, some quietly do not, and a
   lost webhook is a lost deposit.
*/
const CANONICAL_HOST = (() => {
  try {
    return process.env.PUBLIC_URL ? new URL(process.env.PUBLIC_URL).host : '';
  } catch {
    console.warn('PUBLIC_URL is not a valid URL, so no canonical host is enforced');
    return '';
  }
})();

app.use((req, res, next) => {
  if (!CANONICAL_HOST) return next();
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  if (req.path === '/health' || req.path.startsWith('/hooks/')) return next();

  const host = req.get('host');
  if (!host || host === CANONICAL_HOST) return next();

  return res.redirect(301, process.env.PUBLIC_URL.replace(/\/$/, '') + req.originalUrl);
});

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
    /* The canonical address of this page, without the query string.

       Search engines otherwise treat /jobs, /jobs?page=1 and the same page
       reached with a tracking parameter as three different pages competing
       with each other. The path is what identifies a page here; nothing on
       this site changes its content based on a query except pagination. */
    canonical: baseUrl(req).replace(/\/$/, '') + req.path,
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

/* Countries the sign-up form offers. Bangladesh first because that is where
   most people here are; the rest are the places workers actually sign up
   from. "Other" catches everybody else rather than pretending the list is
   complete. */
const COUNTRIES = [
  'Bangladesh', 'India', 'Pakistan', 'Nepal', 'Sri Lanka', 'Indonesia',
  'Philippines', 'Vietnam', 'Malaysia', 'Egypt', 'Nigeria', 'Kenya',
  'Morocco', 'Algeria', 'United Arab Emirates', 'Saudi Arabia', 'Qatar',
  'United Kingdom', 'United States', 'Canada', 'Australia', 'Other',
];

/* Where to go after signing in.

   Only ever somewhere on this site. Taking the parameter at face value turns
   the sign-in page into an open redirect: a link that looks like ours, sends
   people through a real login, and lands them on somebody else's page. The
   second slash is the one that matters - "//evil.test" is a URL to another
   host, not a path here.
*/
function safeNext(value) {
  const v = String(value || '');
  if (!v.startsWith('/') || v.startsWith('//') || /^\/[\\]/.test(v)) return '';
  return v;
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

/* The tab icon, drawn rather than stored.

   An SVG favicon is one file that is sharp at every size a browser asks for,
   which a 32px PNG is not. Served from here rather than as a static file so
   it always matches the mark the header is drawing.
*/
/* ====================================================================
   Telling search engines what is here, and what is not.

   Both are generated rather than kept as files, so they follow PUBLIC_URL.
   Moving to a new domain then needs nothing beyond that one variable, and a
   sitemap advertising the old host is worse than no sitemap at all.
   ==================================================================== */

// Only the pages a stranger can actually open. Anything behind a sign-in, or
// carrying a token, is not listed here and is refused in robots.txt as well.
const PUBLIC_PAGES = [
  ['/', 1.0, 'daily'],
  ['/jobs', 0.9, 'hourly'],
  ['/how-it-works', 0.7, 'monthly'],
  ['/about', 0.6, 'monthly'],
  ['/faq', 0.6, 'monthly'],
  ['/payments', 0.6, 'weekly'],
  ['/activity', 0.5, 'hourly'],
  ['/leaderboard', 0.5, 'daily'],
  ['/security', 0.5, 'monthly'],
  ['/terms', 0.4, 'yearly'],
  ['/privacy-policy', 0.4, 'yearly'],
  ['/refunds', 0.4, 'yearly'],
  ['/contact', 0.4, 'yearly'],
  ['/signup', 0.7, 'monthly'],
  ['/login', 0.5, 'monthly'],
];

app.get('/robots.txt', (req, res) => {
  const site = baseUrl(req).replace(/\/$/, '');
  res.type('text/plain');
  res.setHeader('Cache-Control', 'public, max-age=3600');

  /* Everything private is refused by path.

     Not because a crawler could read any of it - all of it needs a session -
     but because a crawler asking costs the site work, and a token in a URL
     that a crawler followed can end up in somebody's logs. The reset and
     verify links are one-use, so a bot that fetched one would burn it.
  */
  res.send([
    'User-agent: *',
    'Allow: /',
    '',
    'Disallow: /admin',
    'Disallow: /wallet',
    'Disallow: /account',
    'Disallow: /worker',
    'Disallow: /merchant',
    'Disallow: /task',
    'Disallow: /support',
    'Disallow: /referrals',
    'Disallow: /proof/',
    'Disallow: /payout-proof/',
    'Disallow: /hooks/',
    'Disallow: /dev-login',
    'Disallow: /logout',
    'Disallow: /verify',
    'Disallow: /reset',
    'Disallow: /forgot',
    'Disallow: /unsubscribe',
    'Disallow: /r/',
    '',
    `Sitemap: ${site}/sitemap.xml`,
    '',
  ].join('\n'));
});

app.get('/sitemap.xml', (req, res) => {
  const site = baseUrl(req).replace(/\/$/, '');
  const esc = u => u.replace(/&/g, '&amp;');

  // Live jobs are worth listing: they are public, they change often, and they
  // are the reason somebody would find this site by searching at all.
  const jobs = db.prepare(
    "SELECT id, created_at FROM jobs WHERE status = 'active' ORDER BY id DESC LIMIT 500"
  ).all();

  const day = d => String(d || '').slice(0, 10) || new Date().toISOString().slice(0, 10);

  const urls = PUBLIC_PAGES.map(([path, priority, freq]) =>
    `  <url><loc>${esc(site + path)}</loc>` +
    `<changefreq>${freq}</changefreq>` +
    `<priority>${priority.toFixed(1)}</priority></url>`
  ).concat(jobs.map(j =>
    `  <url><loc>${esc(`${site}/jobs/${j.id}`)}</loc>` +
    `<lastmod>${day(j.created_at)}</lastmod>` +
    `<changefreq>daily</changefreq><priority>0.6</priority></url>`
  ));

  res.type('application/xml');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.join('\n')}
</urlset>`);
});

app.get('/favicon.svg', (req, res) => {
  res.type('image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <path fill="#0A7CF0" d="M4 60V32C4 16.536 16.536 4 32 4h24a4 4 0 0 1 4 4v24c0 15.464-12.536 28-28 28H4Z"/>
  <g fill="#fff">
    <rect x="14" y="44" width="9" height="12" rx="1"/>
    <rect x="27" y="33" width="9" height="23" rx="1"/>
    <rect x="40" y="24" width="9" height="32" rx="1"/>
  </g>
  <path fill="#fff" d="M18 42V32C18 21.507 26.507 13 37 13h13v9H37c-5.523 0-10 4.477-10 10v10h-9Z"/>
</svg>`);
});

// Older browsers and bookmark bars still ask for this by name.
/* Browsers that still ask by name get the real mark rather than the drawn
   fallback, so the tab icon is the actual logo wherever it appears. */
app.get('/favicon.ico', (req, res) => {
  const real = path.join(__dirname, 'web', 'assets', 'mark.png');
  res.redirect(301, fs.existsSync(real) ? '/assets/mark.png' : '/favicon.svg');
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
/* Home page numbers.

   Every figure is counted from the database, not typed into a settings box.
   A marketplace that inflates its own numbers is lying to the people deciding
   whether to trust it with their time, and the moment one number is invented
   nobody can tell which of the others are real.
*/
function homeStats() {
  return {
    jobs: db.prepare("SELECT COUNT(*) AS n FROM jobs").get().n,
    active: db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE status = 'active'").get().n,
    slots: db.prepare("SELECT COALESCE(SUM(slots - slots_filled), 0) AS n FROM jobs WHERE status = 'active'").get().n,
    users: db.prepare("SELECT COUNT(*) AS n FROM users WHERE role != 'admin'").get().n,
    workers: db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'worker'").get().n,
    merchants: db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'merchant'").get().n,
    done: db.prepare("SELECT COUNT(*) AS n FROM submissions WHERE status = 'approved'").get().n,
    paid: db.prepare("SELECT COALESCE(SUM(amount), 0) AS n FROM ledger WHERE kind = 'task_earning'").get().n,
    today: db.prepare(
      "SELECT COUNT(*) AS n FROM submissions WHERE status = 'approved' AND reviewed_at >= ?"
    ).get(spam.todayStart()).n,
  };
}

// Icons for the counter strip, drawn rather than loaded, so nothing here
// depends on an image host and they inherit the colour around them.
const COUNTER_ICONS = {
  jobs: '<path d="M3 7h18v13H3z"/><path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M3 12h18"/>',
  users: '<circle cx="9" cy="8" r="3"/><path d="M2 20a7 7 0 0 1 14 0"/><path d="M17 6a3 3 0 0 1 0 6"/><path d="M19 20a6 6 0 0 0-3-5"/>',
  done: '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.5 2.5L16 9.5"/>',
  paid: '<circle cx="12" cy="12" r="9"/><path d="M12 7v10"/><path d="M14.8 9.5c-.5-.9-1.6-1.3-2.8-1.3-1.6 0-2.6.8-2.6 1.9 0 2.7 5.6 1.4 5.6 4.2 0 1.2-1.1 2-2.9 2-1.3 0-2.4-.5-2.9-1.4"/>',
};

function counter(icon, value, label) {
  return `<div class="counter">
    <span class="counter-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${COUNTER_ICONS[icon]}</svg></span>
    <b>${value}</b>
    <span class="counter-label">${V.esc(label)}</span>
  </div>`;
}

app.get('/', (req, res) => {
  if (req.user) return res.redirect(req.user.role === 'admin' ? '/admin' :
    req.user.role === 'merchant' ? '/merchant' : '/worker');

  const s = homeStats();
  const latest = db.prepare(`
    SELECT j.*, c.name AS category FROM jobs j
    LEFT JOIN categories c ON c.id = j.category_id
    WHERE j.status = 'active' AND j.slots_filled < j.slots
    ORDER BY j.id DESC LIMIT 6
  `).all();

  const reviews = db.prepare(
    'SELECT * FROM testimonials WHERE visible = 1 ORDER BY sort, id LIMIT 6'
  ).all();

  // The activity strip. Real rows only - where there is nothing yet the section
  // says so rather than being filled with invented movement.
  const feed = db.prepare(`
    SELECT j.id, j.title, j.rate, j.slots, j.slots_filled, j.created_at, u.name AS buyer
    FROM jobs j JOIN users u ON u.id = j.merchant_id
    WHERE j.status IN ('active','completed') ORDER BY j.id DESC LIMIT 6
  `).all();

  const refDep = (numSetting('referral_deposit_bps') / 100).toFixed(0);

  send(req, res, {
    title: 'Best microjob site to make money online',
    body: `
<section class="hero2">
  <div class="hero2-copy">
    <h1>Microjobs and freelancing<br>to make money online</h1>
    <p class="hero2-sub">Small gigs. Real payouts.
      <span class="bn">ছোট ছোট কাজ, সত্যিকারের টাকা।</span></p>
    <p class="hero2-line">Every job is funded before it goes live.
      <span class="bn">কাজ পোস্ট হওয়ার আগেই টাকা জমা থাকে &mdash; তাই পেমেন্ট নিয়ে চিন্তা নেই।</span></p>
    <a href="/login?want=worker" class="btn btn-lg">Earn money
      <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor"
        stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M5 12h13"/><path d="M13 6l6 6-6 6"/></svg></a>
  </div>
  <div class="hero2-art" aria-hidden="true">
    <svg viewBox="0 0 420 360" width="100%" height="100%">
      <defs>
        <linearGradient id="cA" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#F79E45"/><stop offset="1" stop-color="#E8622A"/></linearGradient>
        <linearGradient id="cB" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#A78BFA"/><stop offset="1" stop-color="#7C5CE0"/></linearGradient>
        <linearGradient id="cC" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#34D399"/><stop offset="1" stop-color="#0E9F6E"/></linearGradient>
        <linearGradient id="cD" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#F472B6"/><stop offset="1" stop-color="#DB4F93"/></linearGradient>
      </defs>
      <g stroke="#DCE4F0" stroke-width="1" fill="none" opacity=".9">
        ${[0, 1, 2, 3, 4].map(i => `<path d="M${60 + i * 66} 40 L${170 + i * 66} 150 L${60 + i * 66} 260 L${-50 + i * 66} 150 Z"/>`).join('')}
      </g>
      <g>
        <path d="M120 190 L175 158 L230 190 L175 222 Z" fill="url(#cA)"/>
        <path d="M120 190 L175 222 L175 300 L120 268 Z" fill="url(#cA)" opacity=".78"/>
        <path d="M230 190 L175 222 L175 300 L230 268 Z" fill="url(#cA)" opacity=".55"/>

        <path d="M250 78 L292 54 L334 78 L292 102 Z" fill="url(#cB)"/>
        <path d="M250 78 L292 102 L292 158 L250 134 Z" fill="url(#cB)" opacity=".78"/>
        <path d="M334 78 L292 102 L292 158 L334 134 Z" fill="url(#cB)" opacity=".55"/>

        <path d="M74 96 L104 78 L134 96 L104 114 Z" fill="url(#cC)"/>
        <path d="M74 96 L104 114 L104 152 L74 134 Z" fill="url(#cC)" opacity=".78"/>
        <path d="M134 96 L104 114 L104 152 L134 134 Z" fill="url(#cC)" opacity=".55"/>

        <path d="M276 208 L308 190 L340 208 L308 226 Z" fill="url(#cD)"/>
        <path d="M276 208 L308 226 L308 264 L276 246 Z" fill="url(#cD)" opacity=".78"/>
        <path d="M340 208 L308 226 L308 264 L340 246 Z" fill="url(#cD)" opacity=".55"/>
      </g>
      <path d="M352 30 C398 44 384 84 350 76 C322 70 336 40 366 52" stroke="#1F9D4D"
        stroke-width="2.4" fill="none" stroke-linecap="round"/>
      <path d="M56 296 C104 330 156 322 196 300" stroke="#1F9D4D" stroke-width="2.4"
        fill="none" stroke-linecap="round"/>
      <path d="M188 292 l12 8 -13 6" stroke="#1F9D4D" stroke-width="2.4" fill="none"
        stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
  </div>
</section>

<section class="counters">
  <div class="wrap counters-grid">
    ${counter('jobs', s.jobs, 'Jobs posted')}
    ${counter('users', s.users, 'Total users')}
    ${counter('done', s.done, 'Tasks done')}
    ${counter('paid', V.money(s.paid), 'Paid out')}
  </div>
  <p class="counters-note">Counted from our own records. Nothing on this page is
     rounded up or invented.</p>
</section>

<section class="band">
  <div class="wrap">
    <span class="band-eyebrow">Remote Work BD</span>
    <h2 class="band-title">Recent activity</h2>
    <div class="band-card">
      ${feed.length ? feed.map(j => {
        const pct = Math.round((j.slots_filled / Math.max(1, j.slots)) * 100);
        return `<div class="act-row">
          <a class="btn btn-sm" href="/jobs/${j.id}">View</a>
          <span class="act-who">${V.esc(shortName(j.buyer))}</span>
          <span class="act-bar">
            <span class="act-count">${j.slots_filled} of ${j.slots}</span>
            <span class="bar"><i style="width:${pct}%"></i></span>
          </span>
          <span class="act-rate">${V.money(j.rate)}</span>
          <span class="act-time">${V.ago(j.created_at)}</span>
        </div>`;
      }).join('') : `<div class="act-empty">
        <b>Nothing has happened here yet.</b>
        <span>This feed fills itself from real jobs. We would rather show an empty
          box than invent movement on the page that asks you to trust us.</span>
      </div>`}
    </div>
    ${feed.length ? '<div class="band-more"><a href="/activity">See all activity</a></div>' : ''}
  </div>
</section>

<section class="services">
  <div class="wrap">
    <span class="eyebrow bar-eyebrow">We provide</span>
    <h2 class="big-title">Services</h2>
    <div class="three">
      <div class="svc-card">
        <span class="svc-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
          stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8"/><path d="M12 16v4"/></svg></span>
        <h3>Work</h3>
        <ul>
          <li>Pick the jobs you like</li>
          <li>Complete the task properly</li>
          <li>Send the proof it asks for</li>
          <li>Get paid on approval</li>
        </ul>
      </div>
      <div class="svc-card">
        <span class="svc-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
          stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <path d="M4 7h16v13H4z"/><path d="M9 7V5h6v2"/><path d="M9 13l2 2 4-4"/></svg></span>
        <h3>Post a job</h3>
        <ul>
          <li>Write what you need done</li>
          <li>Set the rate and how many workers</li>
          <li>Fund it up front, held in escrow</li>
          <li>Review each proof yourself</li>
        </ul>
      </div>
      <div class="svc-card">
        <span class="svc-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
          stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <path d="M3 7h18v10H3z"/><circle cx="12" cy="12" r="2.4"/><path d="M7 12h.01M17 12h.01"/></svg></span>
        <h3>Deposit and withdraw</h3>
        <ul>
          <li>bKash, Nagad, card or crypto</li>
          <li>Money credited once it clears</li>
          <li>Withdraw over ${V.money(numSetting('min_withdrawal'))}</li>
          <li>Every movement in your history</li>
        </ul>
      </div>
    </div>
  </div>
</section>

<section class="wrap">
  <div class="promo">
    <h2>Bring a friend, earn ${V.money(numSetting('referral_flat'))}</h2>
    <p>Share your link. When somebody you invited finishes their first task, you get
       <b>${V.money(numSetting('referral_flat'))}</b> &mdash; and <b>${refDep}% of what they
       deposit</b> if they come as a buyer.
       It comes out of our commission, never out of their earnings.
       <span class="bn">আপনার লিংকে কেউ জয়েন করে প্রথম কাজ শেষ করলেই
       ${V.money(numSetting('referral_flat'))} টাকা পাবেন।</span></p>
    <a href="/login?want=worker" class="btn btn-lg btn-white">Start now</a>
  </div>
</section>

<section class="section">
  <div class="section-head"><h2>Latest jobs</h2><a href="/jobs" class="link">See all</a></div>
  ${latest.length ? `<div class="job-grid">${latest.map(jobCard).join('')}</div>`
    : `<div class="empty">No jobs are open right now.</div>`}
</section>

${reviews.length ? `
<section class="section">
  <div class="section-head center">
    <h2>What people say</h2>
    ${reviews.some(r => r.is_demo) ? '<p class="muted">Example reviews while the site is new.</p>' : ''}
  </div>
  <div class="review-wall">
    ${reviews.map(r => `
      <figure class="quote">
        <blockquote>${V.esc(r.body)}</blockquote>
        <figcaption>
          <span class="avatar-initial">${V.esc(r.name.charAt(0))}</span>
          <span class="who-block"><b>${V.esc(r.name)}</b><span class="dim">${V.esc(r.role || '')}</span></span>
          ${r.earned ? `<span class="earned">${V.esc(r.earned)}</span>` : ''}
        </figcaption>
      </figure>`).join('')}
  </div>
</section>` : ''}

<section class="wrap">
  <div class="findwork">
    <div>
      <span>So what are you waiting for?</span>
      <h2>Find great work</h2>
    </div>
    <a href="/login?want=worker" class="btn btn-lg btn-white">Start now
      <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor"
        stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M5 12h13"/><path d="M13 6l6 6-6 6"/></svg></a>
  </div>
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
  <div><h1>Find work ${V.bn('কাজ খুঁজুন')}</h1>
    <p class="muted">${jobs.length} job${jobs.length === 1 ? '' : 's'} with open slots.
      <span class="bn">নির্দেশনা ভালো করে পড়ে তবেই কাজ শুরু করুন &mdash; ঠিকমতো না করলে বায়ার বাতিল করে দিতে পারে।</span></p></div>
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
      <div class="pay"><b>${V.money(job.rate)}</b><span>per approved task ${V.bn('প্রতি কাজে')}</span></div>
      <dl class="kv">
        <dt>Slots left ${V.bn('বাকি আছে')}</dt><dd>${left} of ${job.slots}</dd>
        <dt>Expected time ${V.bn('সময় লাগবে')}</dt><dd>at least ${V.mmss(job.min_seconds)}</dd>
        <dt>Time to finish ${V.bn('শেষ করার সময়')}</dt><dd>${job.hold_minutes} minutes once started</dd>
        ${job.country ? `<dt>Country</dt><dd>${V.esc(job.country)}</dd>` : ''}
      </dl>
      ${action}
      <p class="fine">Each worker can do this job once. Your time on the task is recorded.<br>
        ${V.bn('একটি কাজ একজন একবারই করতে পারবেন। আপনি কত সময় নিলেন তা রেকর্ড হয়।')}</p>
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
// THE WRITTEN PAGES
// ======================================================================
/* Everything here describes what the software actually does. That is the whole
   point of writing it rather than pasting a template: a policy that does not
   match the system is worse than none, because the first person to be treated
   differently from what it promised has a genuine complaint.

   Contact details come from settings, and each page says plainly when one has
   not been filled in yet rather than printing a blank line.
*/
function contactBlock() {
  const email = getSetting('business_email', '');
  const phone = getSetting('business_phone', '');
  const address = getSetting('business_address', '');
  const reg = getSetting('business_reg', '');
  const tg = getSetting('telegram_support', '');

  const rows = [];
  if (email) rows.push(['Email', V.esc(email)]);
  if (phone) rows.push(['Phone', V.esc(phone)]);
  if (address) rows.push(['Address', V.br(address)]);
  if (reg) rows.push(['Registration', V.esc(reg)]);
  if (tg) rows.push(['Telegram', `<a href="${V.esc(tg)}" target="_blank" rel="noopener">${V.esc(tg)}</a>`]);
  rows.push(['Support', '<a href="/support">Open a conversation inside your account</a>']);

  return `<dl class="kv">${rows.map(r => `<dt>${r[0]}</dt><dd>${r[1]}</dd>`).join('')}</dl>`;
}

function pageHead(title, crumb) {
  return `<div class="page-hero">
    <div class="wrap">
      <h1>${V.esc(title)}</h1>
      <p class="crumb"><a href="/">Home</a> / ${V.esc(crumb || title)}</p>
    </div>
  </div>`;
}

function docPage(req, res, { title, lead, body }) {
  send(req, res, {
    title,
    body: `${pageHead(title)}
<div class="doc">
  ${lead ? `<p class="lede">${lead}</p>` : ''}
  ${body}
  <p class="fine">Last updated ${new Date().toLocaleDateString('en-GB', { month: 'long', year: 'numeric' })}.</p>
</div>`,
  });
}

// -------------------------------------------------------------------- about
app.get('/about', (req, res) => {
  const s = homeStats();
  docPage(req, res, {
    title: 'About us',
    lead: `Remote Work BD is a microjob marketplace built in Bangladesh. Buyers post
      small online tasks and fund them up front; workers do a task, send proof, and are
      paid as soon as it is approved.`,
    body: `
<h2>Why it exists</h2>
<p>Two things go wrong on sites like this, and both come down to trust running one
   way only.</p>
<p>Workers finish a task and then find the buyer has gone, or the budget ran out, or
   the work was rejected with no reason. Buyers pay for a hundred sign-ups and receive
   a hundred screenshots from three people using twenty accounts.</p>
<p>So the money is held in escrow, and the rules that stop farming are enforced by the
   system rather than written in a page nobody reads. A worker never has to trust that
   a buyer will pay, because the money was already set aside. A buyer never pays for
   work they have not seen.</p>

<h2>How we make money</h2>
<p>A percentage of each approved task, taken from the amount the buyer already agreed
   to pay. It is currently <b>${(numSetting('commission_bps') / 100).toFixed(0)}%</b>, shown on
   every task before a worker starts it, and it is the only thing we charge. No fee to
   join, no fee to post a job, no monthly cost.</p>

<h2>Where things stand</h2>
<div class="stat-row">
  <div class="stat"><b>${s.workers}</b><span>workers</span></div>
  <div class="stat"><b>${s.merchants}</b><span>buyers</span></div>
  <div class="stat"><b>${s.done}</b><span>tasks approved</span></div>
  <div class="stat"><b>${V.money(s.paid)}</b><span>paid to workers</span></div>
</div>
<p class="muted">Counted from our own records, not rounded up. The site is new, and
   these numbers say so honestly rather than being dressed up.</p>

<h2>Contact</h2>
${contactBlock()}`,
  });
});

// ----------------------------------------------------------------- security
app.get('/security', (req, res) => {
  docPage(req, res, {
    title: 'Security',
    lead: `This page describes what actually protects your account and your money here,
      including the parts we have not built yet. A security page that only lists
      strengths is a marketing page.`,
    body: `
<h2>Your account</h2>
<p><b>There are no passwords in this system.</b> Not hashed, not encrypted &mdash; none
   exist. Sign-in is Google only, so there is no credential here to steal, guess, reuse
   from another leak, or reset by social engineering. We never see your Google password.</p>
<p>From Google we receive your name, email address and profile picture. Nothing else,
   and we cannot read your Gmail, contacts or files.</p>
<p>Your session is a random token stored in our database, not a token you carry. Signing
   out deletes it, so it stops working immediately &mdash; everywhere.</p>

<h2>Your money</h2>
<p><b>Balances are not stored as a number.</b> Your balance is the sum of every entry in
   your wallet history, so the figure on screen and the history behind it cannot disagree.
   If a payout is ever disputed, it can be reconstructed line by line.</p>
<p>Amounts are held as whole units of the smallest denomination, never as decimals, so no
   amount drifts by fractions over time.</p>
<p>When a buyer posts a job, the full cost leaves their balance immediately and is held
   in escrow. It can only move to a worker on approval, or back to the buyer on
   cancellation. A buyer cannot spend money that is already promised to workers.</p>
<p>Deposits are only credited when the payment provider confirms them to our server
   directly. Returning to a success page proves nothing &mdash; anyone can open a page &mdash;
   so we ask the provider what happened rather than believing the browser.</p>

<h2>Fraud and multiple accounts</h2>
<p>One Google account is one account here. Each job can be done once per worker, ever,
   enforced by the database itself and not only by a check that could be raced.</p>
<p>Time on a task is measured from our own record of when you started, never from
   anything your browser reports. Work submitted implausibly fast, or with proof text
   already used on another task, is flagged for the buyer with the reason attached.</p>
<p>We record the internet address of each sign-in. If several accounts appear on one
   connection, everyone on it is <b>told</b> &mdash; not blocked. Shared wifi, families,
   offices and mobile networks all produce this honestly, so it is treated as one signal
   for a person to weigh, never as proof on its own.</p>

<h2>The site itself</h2>
<ul>
  <li>Served only over HTTPS.</li>
  <li>Session cookies are HttpOnly and same-site, so page scripts cannot read them and
      another site cannot send them.</li>
  <li>Every form that changes anything carries a token tied to your session, so a form
      on someone else's site cannot act as you.</li>
  <li>Proof screenshots are visible only to the worker, the buyer for that task, and an
      administrator. They are not public and are not guessable by URL.</li>
  <li>Every administrator action &mdash; a suspension, a balance change, a decision on a
      report &mdash; is written to an audit log with who did it and when.</li>
</ul>

<h2>What we have not built</h2>
<p>Stated plainly, because you deserve to know what you are relying on.</p>
<ul>
  <li><b>No two-factor authentication of our own.</b> Your account is exactly as
      protected as your Google account, so put two-factor authentication on that.</li>
  <li><b>No email notifications.</b> Nothing is sent to you; you find out about an
      approval or a decision by opening the site.</li>
  <li><b>Payouts are processed by a person.</b> Withdrawals are reviewed and paid by
      hand, so they are not instant.</li>
  <li><b>We are not a bank.</b> Money held here is not insured or guaranteed by anyone.
      Withdraw earnings you are not about to use.</li>
</ul>

<h2>Telling us about a problem</h2>
<p>If you find a security problem, please report it through
   <a href="/support">support</a> before telling anyone else, and give us a reasonable
   chance to fix it. We will not take action against anyone who reports a genuine issue
   in good faith and does not access other people's data while proving it.</p>`,
  });
});

// -------------------------------------------------------------------- terms
app.get('/terms', (req, res) => {
  docPage(req, res, {
    title: 'Terms of service',
    lead: `Plain rules for using Remote Work BD. By signing in you agree to them.`,
    body: `
<h2>Accounts</h2>
<ul>
  <li>You need a Google account with a verified email address.</li>
  <li><b>One person, one account.</b> Running more than one is the thing most likely to
      get every account involved closed.</li>
  <li>You must be at least 18, or old enough to work legally where you live.</li>
  <li>Do not share your account with anyone.</li>
</ul>

<h2>For workers</h2>
<ul>
  <li>Do the task as it is written and send the proof it asks for.</li>
  <li>Each job can be done once. At most
      <b>${numSetting('max_tasks_per_merchant_per_day')}</b> tasks from one buyer per day
      and <b>${numSetting('max_tasks_per_day')}</b> in total per day.</li>
  <li>Proof must be your own work. Reusing proof, editing screenshots or submitting for
      work you did not do is fraud, not a shortcut.</li>
  <li><b>${numSetting('auto_suspend_rejects')}</b> rejected tasks within
      <b>${numSetting('auto_suspend_window_days')}</b> days suspends an account
      automatically for <b>${numSetting('suspend_days')}</b> days.</li>
</ul>

<h2>For buyers</h2>
<ul>
  <li>A job must be funded before it goes live. The full cost is held in escrow.</li>
  <li>Write instructions somebody can actually follow, and say exactly what proof you
      want. Vague instructions cause most rejections.</li>
  <li>Review submissions in reasonable time and give a reason with every rejection.</li>
  <li><b>Rejecting good work to avoid paying is a breach of these terms.</b> Workers can
      report it, an administrator can see the proof, and buyers who do it lose the
      ability to post.</li>
  <li>Do not ask for anything illegal, anything requiring somebody's personal documents,
      or anything that breaks another platform's rules in a way that could get a worker's
      own accounts closed.</li>
</ul>

<h2>Money</h2>
<ul>
  <li>We take <b>${(numSetting('commission_bps') / 100).toFixed(0)}%</b> of each approved
      task. It is shown before a worker starts.</li>
  <li>The smallest withdrawal is <b>${V.money(numSetting('min_withdrawal'))}</b>.</li>
  <li>Withdrawals are checked and paid by a person, so allow a little time.</li>
  <li>Balances are not a deposit account. We are not a bank and money here is not insured.</li>
</ul>

<h2>Suspension and closure</h2>
<p>We may suspend an account while we look into something, and close one for fraud,
   multiple accounts, or repeated breaches. Where an account is closed for fraud, money
   in it may be withheld and used to refund buyers whose jobs were affected.</p>
<p>If you think a decision was wrong, say so through <a href="/support">support</a>.
   A person reads it.</p>

<h2>What we do not promise</h2>
<p>We do not guarantee that work will be available, that any particular job will be
   approved, or that the site will be uninterrupted. We are the marketplace and the
   escrow between two parties; the work itself is between the buyer and the worker.</p>

<h2>Changes</h2>
<p>If these terms change in a way that affects you, the site will tell you. Continuing
   to use it after that means you accept the change.</p>`,
  });
});

// ------------------------------------------------------------------ privacy
app.get('/privacy-policy', (req, res) => {
  docPage(req, res, {
    title: 'Privacy',
    lead: `What we hold about you, why, and what we do not hold. Everything below
      describes the system as it actually is.`,
    body: `
<h2>What we hold</h2>
<ul>
  <li><b>From Google:</b> your name, email address and profile picture. That is the whole
      list. We cannot read your Gmail, contacts or files.</li>
  <li><b>What you type here:</b> your country, your payout details, the proof you send with
      a task, and anything you write to support.</li>
  <li><b>What the system records:</b> which tasks you took and when you started and
      finished them, every movement of money in your wallet, and the internet address and
      browser of each sign-in.</li>
</ul>
<p><b>We do not hold a password for you</b>, because none exists. There is no analytics or
   advertising tracker on this site, and no third party is given your data to profile you.</p>

<h2>Why we hold it</h2>
<ul>
  <li>To run your account and pay you.</li>
  <li>To settle a dispute. When a rejection is challenged, the proof, the timings and the
      wallet history are what let a person decide fairly.</li>
  <li>To stop fraud. Sign-in addresses and task timings are how one person running many
      accounts is told apart from many people sharing a connection.</li>
  <li>To keep records a business is required to keep.</li>
</ul>

<h2>Who sees it</h2>
<ul>
  <li><b>Your proof screenshots</b> are visible to you, the buyer of that task, and an
      administrator. Nobody else, and they are not public.</li>
  <li><b>Your name</b> is shown to a buyer whose job you take, and on any review you
      leave. Your email address is not shown to other users.</li>
  <li><b>Payment providers</b> receive what they need to take a payment. We never see or
      store your card number.</li>
  <li>We do not sell your data, and we do not pass it to anyone for marketing.</li>
</ul>

<h2>Shared connections</h2>
<p>We record the address each sign-in came from. If several accounts appear on one, the
   people on it are told &mdash; nothing is restricted. We do this openly rather than
   quietly, which is why the notice explains itself and why your own account page shows
   you the same sign-in list an administrator sees.</p>

<h2>How long</h2>
<p>Account and money records are kept while your account exists and for as long
   afterwards as tax and dispute rules require. Proof screenshots are kept while the task
   they belong to could still be disputed. Support conversations are kept so a later
   question has its history.</p>

<h2>Your choices</h2>
<ul>
  <li>Ask what we hold about you, and we will tell you.</li>
  <li>Ask us to correct something wrong.</li>
  <li>Ask us to close your account. Withdraw your balance first &mdash; we cannot pay out
      to an account that no longer exists. Records tied to money already moved are kept,
      because deleting one side of a transaction is not something we can honestly do.</li>
</ul>
<p>Message <a href="/support">support</a> for any of these.</p>

<h2>Cookies</h2>
<p>One cookie holds your sign-in, and two short-lived ones carry you through the Google
   sign-in and back. No advertising cookies, no third-party trackers, and nothing that
   follows you to other sites.</p>

<h2>Children</h2>
<p>This site is not for anyone under 18.</p>

<h2>Changes</h2>
<p>If this changes in a way that affects you, the site will say so rather than quietly
   updating the date at the bottom.</p>

<h2>Contact</h2>
${contactBlock()}`,
  });
});

// ------------------------------------------------------------------ refunds
app.get('/refunds', (req, res) => {
  docPage(req, res, {
    title: 'Refunds and cancellation',
    lead: `What happens to money that has not been paid out yet.`,
    body: `
<h2>Cancelling a job</h2>
<p>A buyer can cancel any job at any time. Everything still held in escrow and not yet
   paid out returns to their balance immediately.</p>
<p>Work already submitted still needs a decision. Cancelling does not make those
   submissions disappear, and it does not let anyone avoid paying for work already done
   and approvable &mdash; the money for them stays held until you approve or reject each one.</p>

<h2>Slots nobody took</h2>
<p>If a job finishes with unfilled slots, the money for those slots was never spent and
   comes back when the job is cancelled or completed.</p>

<h2>Deposits</h2>
<p>Money added to your balance is for buying work on this site. We do not send deposits
   back to a card or wallet as a matter of routine, because that is how payment systems
   get used for moving money rather than buying anything.</p>
<p>If you deposited by mistake, or a payment was taken twice, contact
   <a href="/support">support</a> with the transaction reference and we will sort it out.</p>

<h2>A rejection you think was unfair</h2>
<p>Report it from the task page. An administrator can see your proof, the buyer's reason
   and how long you spent, and can credit you directly if the rejection was wrong.</p>

<h2>Withdrawals</h2>
<p>A withdrawal leaves your balance as soon as you request it, so the same money cannot
   be withdrawn twice. If we cannot pay it &mdash; wrong number, account closed &mdash; it is
   returned to your balance in full with the reason.</p>

<h2>Chargebacks</h2>
<p>Reversing a payment through your bank or wallet after spending the balance closes the
   account. If something is wrong, ask us first &mdash; it is faster and it does not cost
   you the account.</p>`,
  });
});

// ---------------------------------------------------------------------- faq
app.get('/faq', (req, res) => {
  const items = [
    ['Is it free to join?',
     'Yes. Free to join, free to post a job. We only take a percentage of each approved task.'],
    ['How do I get paid?',
     'The buyer approves your work and the money is credited to your balance immediately, from funds they had already set aside. Withdraw once you are over ' + V.money(numSetting('min_withdrawal')) + '.'],
    ['Why do I need a Google account?',
     'So one person is one account. Anyone can invent a name and a phone number; a crowd of Google accounts costs real effort. It is what protects people doing honest work. We never see your Google password.'],
    ['Can I do the same job twice?',
     'No. Each job can be done once per worker, ever. You can take at most ' + numSetting('max_tasks_per_merchant_per_day') + ' tasks from the same buyer per day and ' + numSetting('max_tasks_per_day') + ' in total per day.'],
    ['Why was my task flagged?',
     'Usually because it was submitted faster than the job expects, or the proof text matched something you sent on another task. Flagged does not mean rejected - it means the buyer is asked to look closely. Genuine work passes.'],
    ['My work was rejected and I think that is wrong.',
     'Report it from the task page. An administrator can see your proof, the reason the buyer gave and your time on the task, and can credit you if the rejection was unfair.'],
    ['Several people in my house use this site. Is that a problem?',
     'No, and you do not need to do anything. You may see a notice saying several accounts share your connection - that is us being open about what we record, not an accusation. Message support and it is noted on your account.'],
    ['How long do withdrawals take?',
     'They are checked and paid by a person, so not instantly. The amount leaves your balance right away so it cannot be requested twice.'],
    ['Can I be a worker and a buyer?',
     'One account is one side at a time. You can ask to switch from your account page; an administrator reviews it. Your balance and history stay exactly as they are.'],
    ['I did not get an email about my task.',
     'We do not send email at all yet. Everything - approvals, decisions, notices - appears when you open the site.'],
  ];

  docPage(req, res, {
    title: 'Questions',
    lead: 'The things people ask most.',
    body: `<div class="faq">${items.map((q, i) => `
      <details class="faq-item"${i === 0 ? ' open' : ''}>
        <summary>${V.esc(q[0])}</summary>
        <div class="faq-a">${V.esc(q[1])}</div>
      </details>`).join('')}</div>
      <p class="muted">Something not here? <a href="/support">Ask support</a> &mdash; a person answers.</p>`,
  });
});

// ------------------------------------------------------------------ contact
app.get('/contact', (req, res) => {
  docPage(req, res, {
    title: 'Contact',
    lead: 'The fastest way to reach us is from inside your account, because we can see your tasks and payments next to your message.',
    body: `
<div class="two">
  <div class="card pad">
    <h2>Support</h2>
    <p class="muted">Signed in, this opens a conversation attached to your account.
       Replies appear on the same page.</p>
    <a class="btn" href="/support">Open support</a>
  </div>
  <div class="card pad">
    <h2>Message us elsewhere</h2>
    ${supportChannels() || '<p class="muted">Our chat channels are not published yet.</p>'}
  </div>
</div>

<h2>Details</h2>
${contactBlock()}

<h2>Reporting abuse</h2>
<p>If a buyer is rejecting good work, or an account is being used to farm tasks, report it
   from the page it happened on &mdash; the report arrives with the task or job attached,
   which is what lets us act on it quickly.</p>`,
  });
});

// ======================================================================
// SIGN IN  (Google only - there are no passwords anywhere in this app)
// ======================================================================
/* The two ways in.

   Google first, because it is the stronger of the two here: anybody can
   invent a name and an address, but a crowd of Google accounts costs real
   effort, and that effort is what protects honest workers from somebody
   farming a job with twenty identities.

   The password form exists because not everybody has a Google account, or
   wants to use it. Accounts made that way have to confirm their address
   before they can work or withdraw, which puts a real inbox behind each one.
*/
function authPage(req, res, mode) {
  if (req.user) return res.redirect('/');
  const next = String(req.query.next || '');
  const want = req.query.want === 'merchant' ? 'merchant' : '';
  const nextField = next ? `<input type="hidden" name="next" value="${V.esc(next)}">` : '';
  const signup = mode === 'signup';

  const googleBtn = google.configured() ? `
    <a class="google-btn" href="/auth/google?want=${V.esc(want)}${next ? '&next=' + encodeURIComponent(next) : ''}">
      <svg viewBox="0 0 48 48" width="18" height="18" aria-hidden="true">
        <path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.6l6.7-6.7C35.6 2.6 30.2 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.8 6.1C12.3 13.2 17.7 9.5 24 9.5z"/>
        <path fill="#4285F4" d="M46.1 24.6c0-1.6-.1-3.1-.4-4.6H24v9h12.4c-.5 2.9-2.2 5.4-4.7 7l7.6 5.9c4.4-4.1 6.8-10.1 6.8-17.3z"/>
        <path fill="#FBBC05" d="M10.4 28.7c-.5-1.4-.8-2.9-.8-4.7s.3-3.3.8-4.7l-7.8-6.1C.9 16.4 0 20.1 0 24s.9 7.6 2.6 10.8l7.8-6.1z"/>
        <path fill="#34A853" d="M24 48c6.5 0 11.9-2.1 15.9-5.8l-7.6-5.9c-2.1 1.4-4.8 2.3-8.3 2.3-6.3 0-11.7-3.7-13.6-9.1l-7.8 6.1C6.5 42.6 14.6 48 24 48z"/>
      </svg>
      <span>Continue with Google</span>
    </a>
    <div class="or"><span>or ${signup ? 'sign up' : 'sign in'} with your details</span></div>` : '';

  const hiring = signup && want === 'merchant';

  const points = signup ? (hiring ? [
    'Post a batch of tasks and fund it up front',
    'Only workers on this site can take your jobs',
    'Approve or reject each submission yourself',
    'Whatever is not paid out comes back to you',
  ] : [
    'Get access to every task on the board',
    'Withdraw what you earn, from ' + V.money(numSetting('min_withdrawal')) + ' upwards',
    'Join with a referral code if you have one',
    'One account per person - that is what keeps the work fair',
  ]) : [
    'Pick up where you left off',
    'See what you have earned and what is still in review',
    'Manage your account and payout details',
    'Get help from support whenever you need it',
  ];

  send(req, res, {
    title: signup ? 'Create your account' : 'Sign in',
    bare: true,
    body: `
<div class="auth-split">
  <div class="auth-tell">
    <span class="eyebrow">${signup ? (hiring ? 'Create a buyer account' : 'Create your account') : 'Welcome back'}</span>
    <h1>${signup
      ? (hiring ? 'Hire on <b>Remote Work BD</b>' : 'Join <b>Remote Work BD</b> today')
      : 'Sign in to <b>Remote Work BD</b>'}</h1>
    <p>${signup
      ? (hiring
        ? 'A buyer account is for posting work, not doing it. You fund a job up front, workers complete it, and you approve what you are happy with.'
        : 'Create your account to take on tasks and get paid for what you finish. Every job here is funded before it goes live, so the money for your work is already set aside.')
      : 'Sign in to reach your dashboard, carry on with your tasks, manage your balance and keep using Remote Work BD.'}</p>
    <ul class="auth-points">
      ${points.map(x => `<li>${V.esc(x)}</li>`).join('')}
    </ul>
    <div class="auth-note">
      <b>${signup ? (hiring ? 'What a buyer account can do' : 'Simple and secure registration') : 'Secure account access'}</b>
      <p>${signup
        ? (hiring
          ? 'A buyer posts and reviews work. It cannot take tasks for money - that is a worker account, and the two are kept apart so nobody can quietly do their own jobs. You can ask an admin to switch later.'
          : 'Please use real details. Your email has to be confirmed before you can take work or withdraw, and one person may hold one account.')
        : 'Use the email or username you registered with. If you signed up with Google, use the Google button instead.'}</p>
    </div>
  </div>

  <div class="auth-form">
    <div class="auth-card">
      <h2>${signup ? 'Sign up with your details' : 'Sign in to your account'}</h2>
      <p class="sub">${signup
        ? 'Fill in the fields below to create your new account. <span class="bn">নিচের তথ্যগুলো দিয়ে অ্যাকাউন্ট খুলুন।</span>'
        : 'Enter your details below to reach your account. <span class="bn">আপনার তথ্য দিয়ে লগইন করুন।</span>'}</p>

      ${signup ? `
      <div class="role-pick" role="group" aria-label="What kind of account">
        <a class="${hiring ? '' : 'on'}" href="/signup${next ? '?next=' + encodeURIComponent(next) : ''}">
          <b>I want to work</b><span>Do tasks, get paid<br>কাজ করে টাকা আয়</span></a>
        <a class="${hiring ? 'on' : ''}" href="/signup?want=merchant${next ? '&next=' + encodeURIComponent(next) : ''}">
          <b>I want to hire</b><span>Post tasks, fund them<br>কাজ দেব, টাকা দেব</span></a>
      </div>` : ''}

      ${googleBtn}

      <form method="post" action="${signup ? '/signup' : '/login'}" class="auth-fields">
        ${nextField}
        <input type="hidden" name="want" value="${hiring || want === 'merchant' ? 'merchant' : 'worker'}">
        ${signup ? `
          <label for="a-name">Name</label>
          <input id="a-name" name="name" required maxlength="80" autocomplete="name"
                 placeholder="Your full name" value="${V.esc(req.query.name || '')}">

          <label for="a-email">Email address</label>
          <input id="a-email" name="email" type="email" required autocomplete="email"
                 placeholder="you@example.com" value="${V.esc(req.query.email || '')}">

          <label for="a-username">Username</label>
          <input id="a-username" name="username" required autocomplete="username"
                 placeholder="Letters, numbers, dot or underscore" value="${V.esc(req.query.username || '')}">

          <label for="a-ref">Referral code <em>optional</em></label>
          <input id="a-ref" name="ref" placeholder="If somebody invited you"
                 value="${V.esc(req.query.ref || cookies(req).wrj_ref || '')}">

          <label for="a-pass">Password</label>
          <input id="a-pass" name="password" type="password" required minlength="8"
                 autocomplete="new-password" placeholder="At least 8 characters">

          <label for="a-pass2">Confirm password</label>
          <input id="a-pass2" name="password2" type="password" required minlength="8"
                 autocomplete="new-password" placeholder="Type it again">

          <label for="a-country">Country</label>
          <select id="a-country" name="country">
            <option value="">Select your country</option>
            ${COUNTRIES.map(c => `<option value="${V.esc(c)}"${req.query.country === c ? ' selected' : ''}>${V.esc(c)}</option>`).join('')}
          </select>

          <label class="check">
            <input type="checkbox" name="agree" value="1" required>
            <span>I agree to the <a href="/terms" target="_blank">Terms &amp; conditions</a>
              and the <a href="/privacy-policy" target="_blank">Privacy policy</a>.
              <span class="bn">এক ব্যক্তি একটির বেশি অ্যাকাউন্ট খুললে সব বন্ধ করে দেওয়া হবে।</span></span>
          </label>

          <button class="btn btn-lg btn-block" type="submit">Create my account</button>
          <p class="swap">Already have an account? <a href="/login${next ? '?next=' + encodeURIComponent(next) : ''}">Sign in</a></p>
        ` : `
          <label for="a-id">Email address or username</label>
          <input id="a-id" name="identifier" required autocomplete="username"
                 placeholder="Your email or username" value="${V.esc(req.query.id || '')}">

          <label for="a-pass">Password</label>
          <input id="a-pass" name="password" type="password" required
                 autocomplete="current-password" placeholder="Your password">

          <div class="auth-row">
            <span></span>
            <a href="/forgot">Forgotten your password?</a>
          </div>

          <button class="btn btn-lg btn-block" type="submit">Sign in</button>
          <p class="swap">No account yet? <a href="/signup${next ? '?next=' + encodeURIComponent(next) : ''}">Create one</a></p>
        `}
      </form>

      <p class="fine">${signup
        ? 'Check your details are right before you submit.'
        : 'Use your correct sign-in details to reach your account safely.'}</p>
    </div>
  </div>
</div>`,
  });
}

app.get(['/login', '/signin'], (req, res) => authPage(req, res, 'login'));
app.get(['/signup', '/register'], (req, res) => authPage(req, res, 'signup'));

/* Re-show the form with what they typed still in it. Losing eight fields
   because one was wrong is how people give up on signing up. */
function backToForm(res, path, body, msg) {
  // `want` is in the list because losing it drops a buyer back onto the worker
  // form, and they would not notice until an admin asked why they cannot post.
  const keep = ['name', 'email', 'username', 'ref', 'country', 'want'];
  const q = keep
    .filter(k => body[k])
    .map(k => `${k}=${encodeURIComponent(String(body[k]).slice(0, 120))}`)
    .join('&');
  res.redirect(`${path}?${q}${q ? '&' : ''}msg=${encodeURIComponent(msg)}&kind=fail`);
}

app.post('/signup', (req, res) => {
  if (req.user) return res.redirect('/');
  const b = req.body || {};

  if (!b.agree) {
    return backToForm(res, '/signup', b, 'Please accept the terms and the privacy policy.');
  }
  if (String(b.password || '') !== String(b.password2 || '')) {
    return backToForm(res, '/signup', b, 'The two passwords are not the same.');
  }

  let user;
  try {
    user = auth.signUpWithPassword({
      name: b.name, email: b.email, username: b.username, password: b.password,
      country: b.country, role: b.want === 'merchant' ? 'merchant' : 'worker',
      ip: req.ip,
    });
  } catch (err) {
    return backToForm(res, '/signup', b, err.message);
  }

  // Referral, if they came in on somebody's link. Only ever at creation.
  try {
    const code = String(b.ref || cookies(req).wrj_ref || '').trim();
    if (code) referrals.attach(user.id, code);
  } catch { /* a bad code is not a reason to fail a sign-up */ }

  try {
    mail.verifyEmail(user, auth.issueToken(user.id, 'verify'));
    mail.welcome(user);
  } catch (err) { console.error('welcome mail:', err.message); }

  const session = auth.startSession(user.id);
  res.setHeader('Set-Cookie', [
    `wrj_session=${session.token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${session.maxAge}`,
    'wrj_ref=; HttpOnly; Path=/; Max-Age=0',
  ]);
  auth.recordLogin(user.id, req.ip, req.get('user-agent'));
  audit(user.id, 'signup', `user:${user.id}`, { via: 'password' }, req.ip);

  back(res, safeNext(b.next) || '/',
    mail.enabled()
      ? 'Welcome. Check your email and confirm your address to start working.'
      : 'Welcome. Your account is ready.',
    'ok');
});

app.post('/login', (req, res) => {
  if (req.user) return res.redirect('/');
  const b = req.body || {};
  let user;
  try {
    user = auth.signInWithPassword({ identifier: b.identifier, password: b.password, ip: req.ip });
  } catch (err) {
    return res.redirect('/login?id=' + encodeURIComponent(String(b.identifier || '').slice(0, 120))
      + '&msg=' + encodeURIComponent(err.message) + '&kind=fail');
  }

  const session = auth.startSession(user.id);
  res.setHeader('Set-Cookie',
    `wrj_session=${session.token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${session.maxAge}`);
  auth.recordLogin(user.id, req.ip, req.get('user-agent'));
  audit(user.id, 'login', `user:${user.id}`, { via: 'password' }, req.ip);
  res.redirect(safeNext(b.next) || '/');
});

// ------------------------------------------------------- confirming an email
app.get('/verify', (req, res) => {
  const user = auth.useToken(String(req.query.t || ''), 'verify');
  if (!user) {
    return send(req, res, {
      title: 'That link has expired',
      body: `<div class="narrow"><div class="card pad">
        <h1>That link has expired</h1>
        <p class="muted">Confirmation links last 24 hours and work once. Sign in and
           ask for a new one - it takes a second.</p>
        <p><a class="btn" href="/login">Sign in</a></p>
      </div></div>`,
    });
  }
  auth.markVerified(user.id);
  if (req.user && req.user.id === user.id) {
    return back(res, '/', 'Your email address is confirmed. Everything is open to you now.', 'ok');
  }
  back(res, '/login', 'Your email address is confirmed. Please sign in.', 'ok');
});

app.post('/resend-verification', need(), (req, res) => {
  if (req.user.email_verified) return back(res, '/account', 'Your email is already confirmed.', 'info');
  mail.verifyEmail(req.user, auth.issueToken(req.user.id, 'verify'));
  back(res, '/account',
    mail.enabled()
      ? 'Sent. Check your inbox, and your spam folder if it is not there.'
      : 'Mail is not switched on yet, so nothing could be sent. Contact support.',
    mail.enabled() ? 'ok' : 'warn');
});

// -------------------------------------------------------- forgotten password
app.get('/forgot', (req, res) => {
  if (req.user) return res.redirect('/account');
  send(req, res, {
    title: 'Reset your password', bare: true,
    body: `
<div class="auth-split one">
  <div class="auth-form">
    <div class="auth-card">
      <h2>Reset your password</h2>
      <p class="sub">Give us the email address on your account and we will send a link to it.</p>
      <form method="post" action="/forgot" class="auth-fields">
        <label for="f-email">Email address</label>
        <input id="f-email" name="email" type="email" required autocomplete="email"
               placeholder="you@example.com">
        <button class="btn btn-lg btn-block" type="submit">Send the link</button>
        <p class="swap">Remembered it? <a href="/login">Sign in</a></p>
      </form>
    </div>
  </div>
</div>`,
  });
});

/* Always the same answer, whether or not the address is on an account.

   Anything else turns this form into a way of asking "does this person have
   an account here", which is not ours to answer.
*/
app.post('/forgot', (req, res) => {
  const email = auth.normalizeEmail((req.body || {}).email);
  const said = 'If that address has an account, a reset link is on its way. Check your spam folder too.';

  if (auth.tooManyFailures('reset:' + email, req.ip)) return back(res, '/login', said, 'ok');
  auth.recordAttempt('reset:' + email, req.ip, false);

  const user = db.prepare('SELECT * FROM users WHERE lower(email) = ?').get(email);
  if (user && user.password_hash) {
    mail.resetPassword(user, auth.issueToken(user.id, 'reset'));
  } else if (user && !user.password_hash) {
    // They have an account, but it signs in with Google. Telling them that by
    // email is safe - it goes to the address that owns the account.
    mail.queue({
      userId: user.id, kind: 'reset',
      subject: 'Signing in to Remote Work BD',
      heading: 'Your account signs in with Google',
      intro: 'You asked to reset a password, but this account has never had one.',
      lines: ['Use the "Continue with Google" button and you will be straight in.'],
      button: { label: 'Sign in with Google', href: mail.siteUrl() + '/login' },
    });
  }
  back(res, '/login', said, 'ok');
});

app.get('/reset', (req, res) => {
  const token = String(req.query.t || '');
  // Looked at but not spent: spending it here would burn the link on a page
  // load, and a mail scanner that follows links would lock people out.
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const row = db.prepare(`
    SELECT 1 FROM email_tokens WHERE kind = 'reset' AND used_at IS NULL AND expires_at > ?
  `).get(now);

  if (!token || !row) {
    return send(req, res, {
      title: 'That link has expired',
      body: `<div class="narrow"><div class="card pad">
        <h1>That link has expired</h1>
        <p class="muted">Reset links last one hour and work once.</p>
        <p><a class="btn" href="/forgot">Send a new one</a></p>
      </div></div>`,
    });
  }

  send(req, res, {
    title: 'Choose a new password', bare: true,
    body: `
<div class="auth-split one">
  <div class="auth-form">
    <div class="auth-card">
      <h2>Choose a new password</h2>
      <p class="sub">At least 8 characters. Everything signed in as you will be signed out.</p>
      <form method="post" action="/reset" class="auth-fields">
        <input type="hidden" name="t" value="${V.esc(token)}">
        <label for="r-pass">New password</label>
        <input id="r-pass" name="password" type="password" required minlength="8"
               autocomplete="new-password" placeholder="At least 8 characters">
        <label for="r-pass2">Confirm it</label>
        <input id="r-pass2" name="password2" type="password" required minlength="8"
               autocomplete="new-password" placeholder="Type it again">
        <button class="btn btn-lg btn-block" type="submit">Save the new password</button>
      </form>
    </div>
  </div>
</div>`,
  });
});

app.post('/reset', (req, res) => {
  const b = req.body || {};
  if (String(b.password || '') !== String(b.password2 || '')) {
    return back(res, '/reset?t=' + encodeURIComponent(String(b.t || '')),
      'The two passwords are not the same.', 'fail');
  }

  const user = auth.useToken(String(b.t || ''), 'reset');
  if (!user) return back(res, '/forgot', 'That link has expired. Ask for a new one.', 'fail');

  try {
    auth.setPassword(user.id, b.password, user);
  } catch (err) {
    return back(res, '/forgot', err.message, 'fail');
  }
  // A confirmed reset also confirms the address: only its owner saw the link.
  auth.markVerified(user.id);
  mail.passwordChanged(user);
  back(res, '/login', 'Your password is changed. Please sign in with it.', 'ok');
});

// ---------------------------------------------------------------- unsubscribe
app.get('/unsubscribe', (req, res) => {
  const id = mail.checkUnsubToken(String(req.query.t || ''));
  if (!id) return fail(res, 'That unsubscribe link is not valid.');
  db.prepare('UPDATE users SET email_opt_out = 1 WHERE id = ?').run(id);
  send(req, res, {
    title: 'Unsubscribed',
    body: `<div class="narrow"><div class="card pad">
      <h1>You are unsubscribed</h1>
      <p class="muted">You will not get announcements or updates from us any more.</p>
      <p class="muted">Messages about your own money and your account security still go
         out - a receipt for a payment is not something we can decide to withhold.</p>
      <p><a class="btn" href="/account">Change this back</a></p>
    </div></div>`,
  });
});

// One-click unsubscribe, as the List-Unsubscribe-Post header promises.
app.post('/unsubscribe', (req, res) => {
  const id = mail.checkUnsubToken(String(req.query.t || (req.body || {}).t || ''));
  if (!id) return res.status(400).send('bad token');
  db.prepare('UPDATE users SET email_opt_out = 1 WHERE id = ?').run(id);
  res.send('unsubscribed');
});

app.get('/auth/google', (req, res) => {
  if (!google.configured()) return fail(res, 'Google sign-in is not configured yet.');
  const state = google.newState();
  const next = String(req.query.next || '');
  // Somebody who pressed "Post a job" meant to hire. Google does not carry that
  // for us, so it rides along in a short cookie and is applied when the account
  // is created - otherwise every new account silently becomes a worker and the
  // button lied.
  const want = req.query.want === 'merchant' ? 'merchant' : '';
  // A referral code survives the trip to Google the same way the chosen side
  // does, because the account does not exist until we come back.
  const ref = String(req.query.ref || cookies(req).wrj_ref || '').trim().slice(0, 12);
  // The state lives in a short cookie and must come back unchanged, which is
  // what stops somebody sending a victim a pre-made sign-in link.
  res.setHeader('Set-Cookie', [
    `wrj_oauth=${state}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
    `wrj_next=${encodeURIComponent(next)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
    `wrj_want=${want}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
    `wrj_ref=${encodeURIComponent(ref)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`,
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

    // Apply the side they picked before signing in, but only on a brand new
    // account - never silently re-role somebody who already has a history.
    if (result.created) {
      const code = decodeURIComponent(jar.wrj_ref || '');
      if (code) referrals.attach(result.user.id, code, req.ip);
    }

    if (result.created && jar.wrj_want === 'merchant' && result.user.role !== 'admin') {
      db.prepare("UPDATE users SET role = 'merchant' WHERE id = ?").run(result.user.id);
      result.user.role = 'merchant';
    }

    res.setHeader('Set-Cookie', [
      `wrj_session=${s.token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${s.maxAge}`,
      expire,
      'wrj_next=; HttpOnly; Path=/; Max-Age=0',
      'wrj_want=; HttpOnly; Path=/; Max-Age=0',
      'wrj_ref=; HttpOnly; Path=/; Max-Age=0',
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
  const st = quality.workerStanding(u.id);

  send(req, res, {
    title: 'Dashboard', active: 'dash',
    body: `
<div class="page-head"><div><h1>Hello, ${V.esc(u.name)}</h1>
  <p class="muted">${today} of ${cap} tasks used today. Resets at midnight UTC.</p></div>
  <a class="btn" href="/jobs">Find work</a></div>

<div class="card pad level-card">
  <div>
    <span class="pill lvl">${V.esc(st.name)}</span>
    <b>${st.note}</b>
    <div class="dim">${st.rate === null
      ? 'Your level rises as buyers approve your work. Nothing decided yet.'
      : `${st.rate}% of your ${st.decided} decided tasks were approved.`}</div>
  </div>
  ${st.next ? `<div class="dim right-note">
    ${Math.max(0, st.next.tasks - st.approved)} more approved tasks at ${st.next.minRate}%
    or better reaches <b>${st.next.name}</b>, which opens jobs closed to lower levels.
  </div>` : '<div class="dim right-note">Gold is the top level. Every job is open to you.</div>'}
</div>

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
    SELECT s.*, j.title, j.instructions, j.proof_required, j.rate, j.min_seconds,
           j.hold_minutes, j.ttr_days
    FROM submissions s JOIN jobs j ON j.id = s.job_id
    WHERE s.id = ? AND s.worker_id = ?
  `).get(Number(req.params.id), req.user.id);
  if (!s) return fail(res, 'That task is not yours.');

  const started = new Date(s.started_at.replace(' ', 'T') + 'Z').getTime();
  const deadline = started + s.hold_minutes * 60000;

  const form = s.status !== 'started' ? '' : `
    <form method="post" action="/task/${s.id}/submit" enctype="multipart/form-data" class="card pad">
      ${csrfField(req)}
      <h2>Send your proof ${V.bn('প্রমাণ পাঠান')}</h2>
      <div class="prose muted">${V.esc(s.proof_required).replace(/\n/g, '<br>')}</div>
      ${V.field({ label: 'What you did', name: 'proof_text', type: 'textarea', rows: 5, required: true,
        hint: 'Include the details the buyer asked for - a username, an order number, whatever proves it. / বায়ার যা চেয়েছে তা লিখুন - ইউজারনেম, অর্ডার নম্বর, যা প্রমাণ করে।' })}
      <div class="field">
        <label for="f-proof">Screenshot <em>optional</em> ${V.bn('স্ক্রিনশট')}</label>
        <input id="f-proof" type="file" name="proof" accept="image/jpeg,image/png,image/webp">
        <span class="hint">JPG, PNG or WebP, up to 4MB.</span>
      </div>
      <div class="alert alert-info">
        <b>Copying somebody else's proof, or sending the same thing twice, is caught.</b>
        ${V.bn('অন্যের প্রমাণ কপি করলে বা একই জিনিস বারবার পাঠালে ধরা পড়বে - অ্যাকাউন্ট বন্ধ হয়ে যেতে পারে।')}
      </div>
      <div class="btn-row">
        <button class="btn btn-lg" type="submit">Send for review</button>
      </div>
    </form>
    <form method="post" action="/task/${s.id}/drop" class="drop-form"
          onsubmit="return confirm('Drop this task? Your slot goes back to the pool and you cannot take this job again.\n\nকাজটি বাদ দেবেন? স্লট ফেরত যাবে এবং এই কাজটি আর নিতে পারবেন না।')">
      ${csrfField(req)}
      <button class="link-danger" type="submit">Drop this task ${V.bn('কাজটি বাদ দিন')}</button>
    </form>`;

  const job = { ttr_days: s.ttr_days };
  const waitHours = s.status === 'submitted' ? quality.hoursLeft(s, job) : null;
  const canRate = quality.canWorkerRate(s.id, req.user.id);

  const rating = !canRate ? '' : `
    <form method="post" action="/task/${s.id}/rate" class="card pad">
      ${csrfField(req)}
      <h2>How was this buyer?</h2>
      <p class="muted">Only workers who actually did a job can rate, and only once.
         Other workers see this before they start.</p>
      <div class="stars">
        ${[5, 4, 3, 2, 1].map(n => `<input type="radio" id="st${n}" name="stars" value="${n}"${n === 5 ? ' checked' : ''}>
          <label for="st${n}" title="${n} out of 5">&#9733;</label>`).join('')}
      </div>
      ${V.field({ label: 'Anything to add', name: 'comment', type: 'textarea', rows: 3,
        hint: 'Clear instructions? Reviewed quickly? Optional.' })}
      <button class="btn" type="submit">Send rating</button>
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
      ${s.status === 'submitted' && waitHours !== null ? `
        <p class="fine">The buyer has ${waitHours < 48 ? waitHours + ' hours' : Math.round(waitHours / 24) + ' days'}
           left to review this. If they do not, it is approved and paid automatically &mdash;
           you are never left waiting indefinitely.</p>` : ''}
    </div>${rating}`;

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
  mail.taskSubmitted(s, job, req.user);
  back(res, '/task/' + s.id, 'Sent for review.', 'ok');
});

app.post('/task/:id/rate', need('worker'), (req, res) => {
  const sub = db.prepare('SELECT * FROM submissions WHERE id = ? AND worker_id = ?')
    .get(Number(req.params.id), req.user.id);
  if (!sub) return fail(res, 'That task is not yours.');
  try {
    const stars = quality.rateBuyer({
      submissionId: sub.id, workerId: req.user.id,
      stars: req.body.stars, comment: req.body.comment,
    });
    audit(req.user.id, 'rate_buyer', `submission:${sub.id}`, { stars }, req.ip);
    back(res, `/task/${sub.id}`, 'Thanks - your rating is recorded.', 'ok');
  } catch (err) {
    back(res, `/task/${sub.id}`, err.message, 'warn');
  }
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
        <td class="right">
          <a class="link" href="/merchant/jobs/new?clone=${j.id}">Clone</a>
          <a class="link" href="/merchant/jobs/${j.id}">Manage</a>
        </td>
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
  const templates = db.prepare('SELECT * FROM job_templates ORDER BY sort, id').all();

  // Starting from a template, or cloning an existing job of theirs. Either way
  // the form arrives filled in - a blank instructions box is where vague jobs,
  // and then rejected work, come from.
  let pre = { title: '', instructions: '', proof_required: '', min_seconds: 60,
              category_id: '', rate: '', slots: 10, country: '',
              ttr_days: numSetting('default_ttr_days'), min_level: 0 };

  if (req.query.template) {
    const t = templates.find(x => x.id === Number(req.query.template));
    if (t) pre = { ...pre, title: t.title, instructions: t.instructions,
                   proof_required: t.proof, min_seconds: t.min_seconds,
                   category_id: t.category_id || '' };
  } else if (req.query.clone) {
    const j = db.prepare('SELECT * FROM jobs WHERE id = ? AND merchant_id = ?')
      .get(Number(req.query.clone), req.user.id);
    if (j) pre = { title: j.title, instructions: j.instructions, proof_required: j.proof_required,
                   min_seconds: j.min_seconds, category_id: j.category_id || '',
                   rate: (j.rate / 100).toFixed(2), slots: j.slots, country: j.country || '',
                   ttr_days: j.ttr_days, min_level: j.min_level };
  }
  send(req, res, {
    title: 'Post a job', active: 'myjobs',
    body: `
<div class="narrow-wide">
  <h1>Post a job</h1>
  <p class="muted">The full cost is held from your balance as soon as it goes live,
     and whatever is not paid out comes back to you.</p>
  <p class="muted">Available now: <b>${V.money(money.balance(req.user.id))}</b> ·
     <a href="/wallet">Add funds</a></p>

  ${req.query.template || req.query.clone ? '' : `
  <div class="card pad">
    <h2>Start from a template</h2>
    <p class="muted">Each one is a complete job you can edit. Writing from a blank box
       is where vague instructions come from, and vague instructions are what most
       rejected work comes from.</p>
    <div class="tpl-grid">
      ${templates.map(t => `<a class="tpl" href="/merchant/jobs/new?template=${t.id}">
        <b>${V.esc(t.name)}</b><span>${V.esc(t.title)}</span></a>`).join('')}
    </div>
    <p class="fine">Or fill in the form below yourself.</p>
  </div>`}

  <form method="post" action="/merchant/jobs/new" class="card pad">
    ${csrfField(req)}
    ${req.query.clone ? '<div class="alert alert-info">Copied from one of your jobs. Change what you need and publish.</div>' : ''}
    ${V.field({ label: 'Title', name: 'title', required: true, value: pre.title, placeholder: 'Sign up and confirm your email' })}
    ${V.field({ label: 'Category', name: 'category_id', type: 'select', value: pre.category_id,
      options: [{ value: '', label: 'Choose a category' }]
        .concat(cats.map(c => ({ value: c.id, label: c.name }))) })}
    ${V.field({ label: 'What the worker must do', name: 'instructions', type: 'textarea', rows: 9, required: true,
      value: pre.instructions,
      hint: 'Number the steps, and say what you will reject as well as what you want.' })}
    ${V.field({ label: 'Proof you want back', name: 'proof_required', type: 'textarea', rows: 4, required: true,
      value: pre.proof_required,
      placeholder: 'Your username, and a screenshot of the confirmation screen' })}
    <div class="row-2">
      ${V.field({ label: 'Pay per task', name: 'rate', required: true, value: pre.rate, placeholder: '5.00', hint: 'What one worker earns' })}
      ${V.field({ label: 'How many workers', name: 'slots', type: 'number', min: 1, required: true, value: pre.slots })}
    </div>
    <div class="row-2">
      ${V.field({ label: 'Minimum time (seconds)', name: 'min_seconds', type: 'number', min: 20, value: pre.min_seconds,
        hint: 'Anything faster gets flagged for you' })}
      ${V.field({ label: 'Time to finish (minutes)', name: 'hold_minutes', type: 'number', min: 5, value: '60',
        hint: 'Then the slot returns to the pool' })}
    </div>
    <div class="row-2">
      ${V.field({ label: 'Days to review', name: 'ttr_days', type: 'number', min: 1, value: pre.ttr_days,
        hint: 'You get this long to decide. Miss it and submissions approve themselves and are paid.' })}
      <div class="field">
        <label for="f-min_level">Minimum worker level</label>
        <select id="f-min_level" name="min_level">
          ${quality.LEVELS.map(l => `<option value="${l.level}"${Number(pre.min_level) === l.level ? ' selected' : ''}>${V.esc(l.name)}${l.level ? ' and above' : ' - anyone'}</option>`).join('')}
        </select>
        <span class="hint">Higher levels mean a proven record, and a smaller pool of workers.</span>
      </div>
    </div>
    ${V.field({ label: 'Country', name: 'country', value: pre.country, placeholder: 'Leave blank for anywhere' })}
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
                        rate, slots, min_seconds, hold_minutes, country, ttr_days, min_level)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id, b.category_id ? Number(b.category_id) : null, title,
      String(b.instructions).trim(), String(b.proof_required).trim(),
      rate, slots,
      Math.max(numSetting('min_seconds_floor'), Number(b.min_seconds) || 60),
      Math.max(5, Number(b.hold_minutes) || 60),
      String(b.country || '').trim() || null,
      Math.min(numSetting('max_ttr_days'), Math.max(1, Number(b.ttr_days) || numSetting('default_ttr_days'))),
      Math.min(3, Math.max(0, Number(b.min_level) || 0))
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
    SELECT s.*, j.title, j.rate, j.min_seconds, j.proof_required, j.ttr_days, u.name AS worker
    FROM submissions s JOIN jobs j ON j.id = s.job_id JOIN users u ON u.id = s.worker_id
    WHERE s.merchant_id = ? AND s.status = 'submitted'
    ORDER BY s.flagged DESC, s.id ASC
  `).all(req.user.id).map(x => ({
    ...x,
    hoursLeft: quality.hoursLeft(x, { ttr_days: x.ttr_days }),
    standing: quality.workerStanding(x.worker_id),
  }));

  // Soonest deadline first inside each group, so the ones about to approve
  // themselves are the ones in front of you.
  subs.sort((a, b) => (b.flagged - a.flagged) || ((a.hoursLeft ?? 1e9) - (b.hoursLeft ?? 1e9)));
  const urgent = subs.filter(x => x.hoursLeft !== null && x.hoursLeft <= 24).length;
  const clean = subs.filter(x => !x.flagged);

  send(req, res, {
    title: 'Review work', active: 'review',
    body: `
<h1>Review work</h1>
<p class="muted">${subs.length} waiting. Flagged ones come first, then whatever is closest
   to its deadline. Flagged does not mean bad &mdash; it means worth a closer look.</p>

${urgent ? `<div class="alert alert-warn"><b>${urgent} ${urgent === 1 ? 'submission is' : 'submissions are'} within a day of the deadline.</b>
  When it passes they are approved and paid automatically. That is the deal you set when
  you chose the review window.</div>` : ''}

${clean.length > 1 ? `
<div class="card pad bulk">
  <div>
    <b>${clean.length} unflagged submissions</b>
    <span class="dim">Nothing about these looked unusual. You can still open each one.</span>
  </div>
  <form method="post" action="/merchant/review/approve-clean"
        onsubmit="return confirm('Approve ${clean.length} submissions and pay ${V.money(clean.reduce((t, x) => t + x.rate, 0))}?\n\nOnly the ones with nothing flagged are included.')">
    ${csrfField(req)}
    <button class="btn" type="submit">Approve all ${clean.length} &mdash; ${V.money(clean.reduce((t, x) => t + x.rate, 0))}</button>
  </form>
</div>` : ''}

${subs.length ? subs.map(s => `
<div class="card review" id="s${s.id}">
  <div class="card-head">
    <div><b>${V.esc(s.worker)}</b>
      <span class="pill lvl">${V.esc(s.standing.name)}</span>
      ${s.standing.rate !== null ? `<span class="dim">${s.standing.rate}% approved over ${s.standing.decided}</span>` : '<span class="dim">no history yet</span>'}
      <div class="dim">on ${V.esc(s.title)} &middot; sent ${V.ago(s.submitted_at)}</div></div>
    <span class="${s.hoursLeft !== null && s.hoursLeft <= 24 ? 'pill s-rejected' : 'pill s-submitted'}">
      ${s.hoursLeft === null ? '' : s.hoursLeft <= 0 ? 'approving now'
        : s.hoursLeft < 48 ? s.hoursLeft + 'h to decide' : Math.round(s.hoursLeft / 24) + 'd to decide'}</span>
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

/* Approve everything that was not flagged, in one go.

   Deliberately excludes flagged submissions. The whole point of the flag is
   that a person should look at it, and a button that waves those through in a
   batch would quietly undo the check.
*/
app.post('/merchant/review/approve-clean', need('merchant'), (req, res) => {
  const rows = db.prepare(
    "SELECT id FROM submissions WHERE merchant_id = ? AND status = 'submitted' AND flagged = 0"
  ).all(req.user.id);

  let paid = 0, total = 0;
  const problems = [];

  for (const row of rows) {
    db.exec('BEGIN IMMEDIATE');
    try {
      const sub = db.prepare("SELECT * FROM submissions WHERE id = ? AND status = 'submitted'").get(row.id);
      if (!sub) { db.exec('COMMIT'); continue; }
      const job = db.prepare('SELECT * FROM jobs WHERE id = ?').get(sub.job_id);
      const result = money.payForSubmission(sub, job);
      db.prepare("UPDATE submissions SET status = 'approved', reviewed_at = datetime('now') WHERE id = ?")
        .run(sub.id);
      db.exec('COMMIT');
      mail.taskApproved(sub, job, result.net, false);
      paid++; total += result.net;
    } catch (err) {
      db.exec('ROLLBACK');
      problems.push(err.message);
    }
  }

  audit(req.user.id, 'bulk_approve', null, { paid, total }, req.ip);
  back(res, '/merchant/review',
    problems.length
      ? `Approved ${paid}. ${problems.length} could not be paid: ${problems[0]}`
      : `Approved ${paid} and paid ${money.fmt(total)}.`,
    problems.length ? 'warn' : 'ok');
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
    // Queued after the commit, never inside it: a receipt must describe money
    // that has actually moved.
    mail.taskApproved(s, job, paid.net, false);
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

  const rejected = db.prepare('SELECT * FROM submissions WHERE id = ?').get(id);
  const rejectedJob = db.prepare('SELECT * FROM jobs WHERE id = ?').get(rejected.job_id);
  mail.taskRejected(rejected, rejectedJob, note);
  if (suspended) {
    const w = db.prepare('SELECT suspend_reason, suspended_until FROM users WHERE id = ?').get(workerId);
    mail.accountSuspended(workerId, w.suspend_reason, w.suspended_until);
  }
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

  /* Adding money.

     One flow whichever way they pay: choose the method, choose an amount in
     dollars, go. The amount is in dollars for both because the crypto side is
     priced that way, and quoting one minimum in dollars and another in taka on
     the same page is how people end up entering the wrong number.

     What will actually be charged and credited is shown before they commit.
     Nobody should discover the exchange rate on the payment provider's page.
  */
  const minUsd = numSetting('min_deposit_usd');
  const methods = [
    cryptomus.configured() ? {
      id: 'crypto', action: '/wallet/deposit/crypto',
      name: 'USDT and other crypto',
      note: 'USDT, BTC, ETH and more. Usually confirmed within minutes.',
      badge: 'no bank needed',
    } : null,
    eps.configured() ? {
      id: 'eps', action: '/wallet/deposit/eps',
      name: 'bKash, Nagad, Rocket or card',
      note: `Paid in ${V.esc(getSetting('currency'))} at ${V.money(rate)} to the dollar.`,
      badge: 'instant',
    } : null,
  ].filter(Boolean);

  const quick = [1, 5, 10, 25, 50, 100].filter(x => x * 100 >= minUsd);

  const addFunds = u.role !== 'merchant' ? '' : `
    <div class="card pad">
      <h2>Add funds ${V.bn('টাকা যোগ করুন')}</h2>
      <p class="muted">Smallest deposit is $${(minUsd / 100).toFixed(2)}. Money lands in your
         balance only once the payment provider confirms it &mdash; never on our say-so.<br>
         ${V.bn(`সর্বনিম্ন $${(minUsd / 100).toFixed(2)} ডলার। পেমেন্ট প্রোভাইডার নিশ্চিত করার পরেই টাকা ব্যালেন্সে যোগ হবে।`)}</p>

      ${methods.length ? `
      <form method="post" action="${methods[0].action}" id="deposit-form" class="deposit">
        ${csrfField(req)}

        <span class="lbl">How do you want to pay? ${V.bn('কীভাবে টাকা দেবেন?')}</span>
        <div class="pay-pick">
          ${methods.map((m, i) => `
            <label class="pay ${i === 0 ? 'on' : ''}">
              <input type="radio" name="method" value="${m.id}" data-action="${m.action}"
                     ${i === 0 ? 'checked' : ''}>
              <span class="pay-body">
                <b>${V.esc(m.name)} <i class="pill s-active">${V.esc(m.badge)}</i></b>
                <span>${m.note}</span>
              </span>
            </label>`).join('')}
        </div>

        <span class="lbl">How much? ${V.bn('কত টাকা?')}</span>
        <div class="amt-quick">
          ${quick.map(x => `<button type="button" class="amt" data-usd="${x}">$${x}</button>`).join('')}
        </div>

        <div class="amt-row">
          <span class="amt-sign">$</span>
          <input type="number" name="usd" id="usd-input" step="0.01"
                 min="${(minUsd / 100).toFixed(2)}" required inputmode="decimal"
                 placeholder="${(minUsd / 100).toFixed(2)}" data-rate="${rate}"
                 data-currency="${V.esc(getSetting('currency_symbol'))}">
          <span class="amt-usd">USD</span>
        </div>

        <p class="amt-out" id="amt-out" aria-live="polite">
          Enter an amount and you will see exactly what lands in your balance.</p>

        <button class="btn btn-lg" type="submit">Continue to payment</button>
        <p class="fine">You will be taken to the provider to pay. Nothing is added here until
           they confirm it, so closing the page by accident costs you nothing.<br>
           ${V.bn('পেমেন্ট করতে প্রোভাইডারের পেজে যাবেন। ভুলে পেজ বন্ধ হয়ে গেলেও কোনো টাকা কাটবে না।')}</p>
      </form>`
      : `<div class="alert alert-warn">
          <b>No payment provider is switched on yet.</b>
          Record a transfer below and an admin will confirm it by hand.</div>`}

      <details class="manual">
        <summary>Paid another way? Record it here ${V.bn('অন্যভাবে পাঠিয়েছেন? এখানে লিখুন')}</summary>
        <p class="muted">Use this only if you sent money outside the site. An admin checks the
           reference against the account before crediting anything.</p>
        <form method="post" action="/wallet/deposit">
          ${csrfField(req)}
          <div class="row-2">
            ${V.field({ label: `Amount in ${V.esc(getSetting('currency'))}`, name: 'amount', required: true, placeholder: '500.00' })}
            ${V.field({ label: 'Method', name: 'method', type: 'select', options: [
              { value: 'bkash', label: 'bKash' }, { value: 'nagad', label: 'Nagad' },
              { value: 'rocket', label: 'Rocket' },
              { value: 'bank', label: 'Bank transfer' }, { value: 'other', label: 'Other' }] })}
          </div>
          ${V.field({ label: 'Transaction reference', name: 'reference', required: true,
            hint: 'The ID from your payment app, so it can be matched' })}
          <button class="btn btn-ghost" type="submit">Record it</button>
        </form>
      </details>
    </div>`;

  /* Taking money out.

     The account fields are separate on purpose. An admin about to send real
     money has to read the holder's name apart from the number to check they
     match, and a bank transfer needs four things that will not fit in one
     line of free text.

     The warning about personal accounts is the one thing on this page that
     stops a payment failing: bKash and Nagad refuse a normal send to an agent
     or merchant wallet, and the money bounces back days later with nobody
     sure why.
  */
  const pending = db.prepare(
    "SELECT * FROM withdrawals WHERE user_id = ? AND status = 'pending' ORDER BY id DESC"
  ).all(u.id);

  const saved = {
    method: u.payout_method || 'bkash',
    number: u.payout_detail || '',
    name: u.payout_name || u.name || '',
    bank: u.payout_bank || '',
    branch: u.payout_branch || '',
  };

  const withdraw = u.role !== 'worker' ? '' : `
    <div class="card pad">
      <h2>Withdraw <span class="bn">টাকা তুলুন</span></h2>
      <p class="muted">Smallest withdrawal is ${V.money(numSetting('min_withdrawal'))}.
         The amount leaves your balance straight away and is paid out after an admin
         checks it.<br>
         ${V.bn(`সর্বনিম্ন ${V.money(numSetting('min_withdrawal'))} টাকা। রিকোয়েস্ট করলেই ব্যালেন্স থেকে কেটে যাবে, অ্যাডমিন দেখে পাঠিয়ে দেবে।`)}</p>

      ${pending.length ? `
      <div class="alert alert-info">
        <b>${pending.length} withdrawal${pending.length === 1 ? '' : 's'} waiting.</b>
        You can cancel any of them below until an admin pays it.
        ${V.bn('অ্যাডমিন পাঠানোর আগ পর্যন্ত আপনি নিজেই বাতিল করতে পারবেন।')}
      </div>` : ''}

      <div class="alert alert-warn">
        <b>Use a personal account, not an agent or merchant one.</b>
        <span class="bn">এজেন্ট বা মার্চেন্ট নম্বরে টাকা পাঠানো যায় না &mdash; অবশ্যই
          পার্সোনাল bKash / Nagad / Rocket নম্বর দিন।</span>
        A send to an agent or merchant wallet is refused by bKash and Nagad, and the
        payment comes back days later with nobody sure why.
      </div>

      <form method="post" action="/wallet/withdraw" class="withdraw" id="withdraw-form">
        ${csrfField(req)}

        ${V.field({ label: 'Amount', name: 'amount', required: true,
          hint: `In ${V.esc(getSetting('currency'))}. You have ${V.money(money.balance(u.id))}. / আপনার ব্যালেন্সে আছে ${V.money(money.balance(u.id))}।` })}

        <div class="field">
          <label for="w-method">Send it to ${V.bn('কোথায় পাঠাব')}</label>
          <select id="w-method" name="method">
            ${[['bkash', 'bKash (personal)'], ['nagad', 'Nagad (personal)'],
               ['rocket', 'Rocket (personal)'], ['bank', 'Bank transfer']]
              .map(([v, l]) => `<option value="${v}"${saved.method === v ? ' selected' : ''}>${l}</option>`).join('')}
          </select>
        </div>

        ${V.field({ label: 'Account holder name', name: 'account_name', required: true,
          value: saved.name,
          hint: 'Exactly as it is registered on the account. / অ্যাকাউন্টে যে নাম আছে হুবহু সেটাই দিন - নাম না মিললে পেমেন্ট ফেরত আসে।' })}

        ${V.field({ label: 'Number or account', name: 'account_number', required: true,
          value: saved.number, placeholder: '01XXXXXXXXX',
          hint: 'Your personal wallet number, or the account number for a bank. / আপনার পার্সোনাল নম্বর, অথবা ব্যাংক হলে অ্যাকাউন্ট নম্বর।' })}

        <div id="bank-only" class="bank-fields" hidden>
          <div class="row-2">
            ${V.field({ label: 'Bank name', name: 'bank_name', value: saved.bank,
              placeholder: 'For example Dutch-Bangla Bank' })}
            ${V.field({ label: 'Branch name', name: 'branch', value: saved.branch,
              placeholder: 'The branch the account is held at' })}
          </div>
        </div>

        <button class="btn" type="submit">Request withdrawal</button>
        <p class="fine">Nothing is sent until an admin checks it. You can cancel while it waits.<br>
           ${V.bn('অ্যাডমিন যাচাই করার আগে কিছুই পাঠানো হয় না। অপেক্ষার সময় আপনি বাতিল করতে পারবেন।')}</p>
      </form>
    </div>` ;

  const pendingList = (u.role !== 'worker' || !pending.length) ? '' : `
    <div class="card">
      <div class="card-head"><h2>Waiting to be paid ${V.bn('পেমেন্টের অপেক্ষায়')}</h2></div>
      <div class="table-wrap"><table>
        <thead><tr><th>Asked</th><th>Amount</th><th>To</th><th></th></tr></thead>
        <tbody>${pending.map(w => `<tr>
          <td class="dim">${V.ago(w.created_at)}</td>
          <td class="num">${V.money(w.amount)}</td>
          <td>${V.esc(w.method)}<div class="dim">${V.esc(w.detail || '')}</div></td>
          <td class="right">
            <form method="post" action="/wallet/withdraw/${w.id}/cancel"
                  onsubmit="return confirm('Cancel this withdrawal? ${V.esc(V.money(w.amount))} goes back to your balance.')">
              ${csrfField(req)}
              <button class="btn btn-ghost btn-sm" type="submit">Cancel</button>
            </form>
          </td>
        </tr>`).join('')}</tbody>
      </table></div>
    </div>`;

  send(req, res, {
    title: 'Wallet', active: 'wallet',
    body: `
<div class="page-head"><h1>Wallet</h1>
  <div class="big-balance">${V.money(money.balance(u.id))}</div></div>

${pendingList}

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
  // Money leaving the site is the one action worth being strict about: an
  // unconfirmed address means we have no way to reach whoever this is.
  if (!req.user.email_verified) {
    return back(res, '/account',
      'Confirm your email address before withdrawing. It is the only way we can reach you about a payout.',
      'warn');
  }
  const amount = money.parseAmount(req.body.amount);
  if (!amount || amount <= 0) return fail(res, 'Enter an amount like 100.00');

  const b = req.body || {};
  const method = ['bkash', 'nagad', 'rocket', 'bank'].includes(b.method) ? b.method : 'bkash';

  try {
    money.requestWithdrawal(req.user.id, amount, method, {
      accountName: b.account_name,
      accountNumber: b.account_number,
      bankName: b.bank_name,
      branch: b.branch,
    });
    back(res, '/wallet',
      'Requested. It has left your balance and is waiting for an admin. You can cancel it until they pay it.',
      'ok');
  } catch (err) {
    fail(res, err.message);
  }
});

/* Take back a withdrawal that has not been paid yet. */
app.post('/wallet/withdraw/:id/cancel', need('worker'), (req, res) => {
  try {
    const amount = money.cancelWithdrawal(Number(req.params.id), req.user.id);
    audit(req.user.id, 'withdrawal_cancelled', `withdrawal:${req.params.id}`, { amount }, req.ip);
    back(res, '/wallet', `Cancelled. ${money.fmt(amount)} is back in your balance.`, 'ok');
  } catch (err) {
    back(res, '/wallet', err.message, 'fail');
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
/* ====================================================================
   The admin dashboard.

   Built around one question: what needs me right now? Everything that can be
   waiting for a person is at the top, and everything else is context under it.
   A dashboard that opens with a wall of totals trains people to skim past the
   one number that mattered.

   Nothing here is stored. Every figure is counted from the rows it describes,
   so the dashboard cannot drift away from the truth it is reporting.
   ==================================================================== */

// A bar chart in plain SVG. No library: the CSP forbids one, and this is
// twenty lines against a hundred kilobytes.
function chart(rows, key, { colour = 'var(--green)', money: asMoney = false, height = 60 } = {}) {
  const values = rows.map(r => r[key]);
  const peak = Math.max(1, ...values);
  const w = 100 / rows.length;

  return `<div class="chart">
    <svg viewBox="0 0 100 ${height}" preserveAspectRatio="none" role="img"
         aria-label="${rows.length} day trend">
      ${rows.map((r, i) => {
        const h = (r[key] / peak) * (height - 4);
        return `<rect x="${(i * w + w * 0.16).toFixed(2)}" y="${(height - h).toFixed(2)}"
          width="${(w * 0.68).toFixed(2)}" height="${Math.max(h, r[key] ? 1 : 0).toFixed(2)}"
          fill="${colour}" rx="0.6"><title>${V.esc(r.label)}: ${asMoney ? V.money(r[key]) : r[key]}</title></rect>`;
      }).join('')}
    </svg>
    <div class="chart-foot"><span>${V.esc(rows[0].label)}</span><span>${V.esc(rows[rows.length - 1].label)}</span></div>
  </div>`;
}

function kpi(value, label, { href, tone = '', note = '' } = {}) {
  const inner = `<b>${value}</b><span>${V.esc(label)}</span>${note ? `<em>${V.esc(note)}</em>` : ''}`;
  return href
    ? `<a class="kpi ${tone}" href="${href}">${inner}</a>`
    : `<div class="kpi ${tone}">${inner}</div>`;
}

app.get('/admin', need('admin'), (req, res) => {
  const days = [7, 14, 30, 90].includes(Number(req.query.days)) ? Number(req.query.days) : 14;
  const p = stats.people();
  const m = stats.money();
  const w = stats.work();
  const q = stats.queue();
  const trend = stats.series(days);
  const risky = stats.buyers(50).filter(b => b.behaviour.concerns.length);

  // Everything that is actually waiting for a person, in one list.
  const todo = [
    { n: q.reports, label: 'reports to judge', href: '/admin/reports' },
    { n: m.pendingWithdrawals, label: 'withdrawals to pay', href: '/admin/money' },
    { n: m.pendingDeposits, label: 'deposits to check', href: '/admin/money' },
    { n: q.roleRequests, label: 'role changes to approve', href: '/admin/roles' },
    { n: q.tickets, label: 'support tickets open', href: '/admin/support' },
    { n: q.mailFailed, label: 'emails failed to send', href: '/admin/mail?status=failed' },
    { n: risky.length, label: 'buyers worth a look', href: '/admin/buyers' },
  ].filter(x => x.n > 0);

  const recent = db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 12').all();

  send(req, res, {
    title: 'Dashboard', active: 'admin', wide: true,
    body: `
<div class="page-head">
  <div><h1>Dashboard</h1>
    <p class="muted">Everything is counted live from the records themselves, so nothing here
       can drift away from what actually happened.</p></div>
  <div class="range">
    ${[7, 14, 30, 90].map(d => `<a class="${d === days ? 'on' : ''}" href="/admin?days=${d}">${d}d</a>`).join('')}
  </div>
</div>

${m.balanced ? '' : `<div class="alert alert-stop">
  <b>The books do not balance.</b>
  Deposits and adjustments come to ${V.money(m.inflow)}, but balances plus escrow plus
  everything withdrawn comes to ${V.money(m.balances + m.escrow + m.outflow)}
  &mdash; a difference of ${V.money(Math.abs(m.drift))}.
  Money has been created or destroyed somewhere. Stop and find it before anything else.</div>`}

${w.overdue ? `<div class="alert alert-warn">
  <b>${w.overdue} submission(s) are past their review deadline and still unpaid.</b>
  The sweep runs every minute, so a number here that does not fall means it is not running.</div>` : ''}

${todo.length ? `
<div class="todo">
  <b>Waiting for you</b>
  <div class="todo-row">
    ${todo.map(x => `<a href="${x.href}"><span class="n">${x.n}</span> ${V.esc(x.label)}</a>`).join('')}
  </div>
</div>` : `<div class="todo clear"><b>Nothing is waiting for you.</b>
  <span>No open reports, no unpaid withdrawals, no failed email.</span></div>`}

<h2 class="sec">Money</h2>
<div class="kpi-row">
  ${kpi(V.money(m.balances), 'held in user balances', { note: 'what people could withdraw today' })}
  ${kpi(V.money(m.escrow), 'in escrow', { note: 'funded jobs not yet paid out', href: '/admin/buyers' })}
  ${kpi(V.money(m.fees), 'our commission', { tone: 'ok', note: 'earned across all approved work' })}
  ${kpi(V.money(m.withdrawn), 'paid out', { note: 'withdrawals settled' })}
  ${kpi(V.money(m.pendingWithdrawalValue), 'withdrawals waiting',
    { tone: m.pendingWithdrawals ? 'warn' : '', href: '/admin/money',
      note: `${m.pendingWithdrawals} request${m.pendingWithdrawals === 1 ? '' : 's'}` })}
</div>

<div class="two">
  <div class="card pad">
    <div class="card-head"><h3>Deposits in</h3><span class="dim">${days} days</span></div>
    ${chart(trend, 'deposits', { colour: 'var(--band)', money: true })}
    <dl class="kv tight">
      <dt>Deposited all time</dt><dd>${V.money(m.deposited)}</dd>
      <dt>Added by an admin</dt><dd>${V.money(m.adminAdded)}</dd>
      ${m.adminTaken ? `<dt>Taken by an admin</dt><dd>${V.money(m.adminTaken)}</dd>` : ''}
    </dl>
  </div>
  <div class="card pad">
    <div class="card-head"><h3>Paid to workers</h3><span class="dim">${days} days</span></div>
    ${chart(trend, 'paid', { colour: 'var(--green)', money: true })}
    <dl class="kv tight">
      <dt>Earned by workers all time</dt><dd>${V.money(m.earned)}</dd>
      <dt>Referral rewards paid</dt><dd>${V.money(m.referralPaid)}</dd>
      <dt class="fine-dt">Rewards come out of our commission, never out of anybody's earnings</dt><dd></dd>
    </dl>
  </div>
</div>

<h2 class="sec">Work</h2>
<div class="kpi-row">
  ${kpi(w.waiting, 'waiting on a buyer', { tone: w.waiting ? 'warn' : '', note: 'submitted, not yet judged' })}
  ${kpi(w.open, 'in progress', { note: 'started, not yet sent' })}
  ${kpi(w.approved, 'approved', { tone: 'ok' })}
  ${kpi(w.rejected, 'rejected', { tone: w.rejected ? 'bad' : '' })}
  ${kpi(w.approvalRate === null ? '--' : w.approvalRate + '%', 'approval rate',
    { note: 'across every decision made' })}
  ${kpi(w.autoApproved, 'auto-approved', { note: 'buyer missed the deadline' })}
</div>

<div class="two">
  <div class="card pad">
    <div class="card-head"><h3>Tasks approved</h3><span class="dim">${days} days</span></div>
    ${chart(trend, 'tasks', { colour: 'var(--green)' })}
  </div>
  <div class="card pad">
    <div class="card-head"><h3>New accounts</h3><span class="dim">${days} days</span></div>
    ${chart(trend, 'signups', { colour: 'var(--violet)' })}
  </div>
</div>

<h2 class="sec">People</h2>
<div class="kpi-row">
  ${kpi(p.workers, 'workers', { href: '/admin/users?role=worker' })}
  ${kpi(p.merchants, 'buyers', { href: '/admin/buyers' })}
  ${kpi(p.active7, 'workers active', { note: 'took a task in the last 7 days' })}
  ${kpi(p.buying7, 'buyers active', { note: 'posted a job in the last 7 days' })}
  ${kpi(p.new7, 'joined this week', { note: `${p.newToday} in the last day` })}
  ${kpi(p.suspended, 'suspended', { tone: p.suspended ? 'bad' : '', href: '/admin/users?status=suspended' })}
  ${kpi(p.unverified, 'unconfirmed email', { tone: p.unverified ? 'warn' : '',
    note: 'cannot take work or withdraw' })}
</div>

<div class="two">
  <div class="card">
    <div class="card-head"><h3>Jobs</h3><a class="link" href="/admin/jobs">All jobs</a></div>
    <div class="pad">
      <dl class="kv tight">
        <dt>Live now</dt><dd>${w.jobsActive}</dd>
        <dt>Slots still open</dt><dd>${w.slotsOpen}</dd>
        <dt>Completed</dt><dd>${w.jobsCompleted}</dd>
        <dt>Cancelled</dt><dd>${w.jobsCancelled}</dd>
        <dt>Flagged and waiting</dt><dd>${w.flagged}</dd>
      </dl>
    </div>
  </div>

  <div class="card">
    <div class="card-head"><h3>Buyers worth a look</h3><a class="link" href="/admin/buyers">All buyers</a></div>
    ${risky.length ? `<div class="table-wrap"><table>
      <thead><tr><th>Buyer</th><th>Why</th></tr></thead>
      <tbody>${risky.slice(0, 5).map(b => `<tr>
        <td><a class="link" href="/admin/users/${b.id}">${V.esc(b.name)}</a></td>
        <td class="dim">${V.esc(b.behaviour.concerns[0])}</td>
      </tr>`).join('')}</tbody></table></div>`
      : `<div class="pad muted">No buyer is rejecting an unusual amount of work,
         letting deadlines lapse, or carrying upheld reports.</div>`}
  </div>
</div>

<div class="two">
  <div class="card">
    <div class="card-head"><h3>Busiest workers</h3></div>
    ${(() => { const t = stats.topWorkers(6); return t.length ? `<div class="table-wrap"><table>
      <thead><tr><th>Worker</th><th class="right">Approved</th><th class="right">Earned</th></tr></thead>
      <tbody>${t.map(x => `<tr>
        <td><a class="link" href="/admin/users/${x.id}">${V.esc(x.name)}</a></td>
        <td class="num right">${x.approved}</td>
        <td class="num right">${V.money(x.earned)}</td></tr>`).join('')}</tbody>
      </table></div>` : '<div class="pad muted">Nobody has had work approved yet.</div>'; })()}
  </div>
  <div class="card">
    <div class="card-head"><h3>Biggest buyers</h3></div>
    ${(() => { const t = stats.topBuyers(6); return t.length ? `<div class="table-wrap"><table>
      <thead><tr><th>Buyer</th><th class="right">Jobs</th><th class="right">Funded</th></tr></thead>
      <tbody>${t.map(x => `<tr>
        <td><a class="link" href="/admin/users/${x.id}">${V.esc(x.name)}</a></td>
        <td class="num right">${x.jobs}</td>
        <td class="num right">${V.money(x.funded)}</td></tr>`).join('')}</tbody>
      </table></div>` : '<div class="pad muted">Nobody has funded a job yet.</div>'; })()}
  </div>
</div>

<div class="card">
  <div class="card-head"><h3>Recent activity</h3><span class="dim">every action leaves a record</span></div>
  <div class="table-wrap"><table>
    <thead><tr><th>When</th><th>Who</th><th>Did</th><th>To</th><th>Detail</th></tr></thead>
    <tbody>${recent.map(a => `<tr>
      <td class="dim">${V.ago(a.created_at)}</td>
      <td class="mono">${a.actor_id || 'system'}</td>
      <td>${V.esc(a.action)}</td>
      <td class="mono">${V.esc(a.subject || '')}</td>
      <td class="dim clip">${V.esc(String(a.detail || '').slice(0, 80))}</td></tr>`).join('')}
    </tbody></table></div>
</div>`,
  });
});

/* Every buyer, and how they treat the people working for them.

   Its own page because judging a buyer needs different numbers from judging a
   worker. A worker is judged on the quality of what they send; a buyer is
   judged on whether they pay for what they receive.
*/
app.get('/admin/buyers', need('admin'), (req, res) => {
  const all = stats.buyers(200);
  const flagged = all.filter(b => b.behaviour.concerns.length);

  send(req, res, {
    title: 'Buyers', active: 'buyers', wide: true,
    body: `
<div class="page-head">
  <div><h1>Buyers</h1>
    <p class="muted">Anyone who can post work. Sorted so that the accounts worth
       questioning come first.</p></div>
  <a class="btn btn-ghost" href="/admin/users?role=worker">Workers instead</a>
</div>

${flagged.length ? `<div class="alert alert-warn">
  <b>${flagged.length} buyer${flagged.length === 1 ? '' : 's'} worth a closer look.</b>
  None of these is proof of anything on its own &mdash; a high rejection rate can just be
  bad instructions. Read the detail, and look at the work before acting.</div>` : ''}

<div class="card">
  ${all.length ? `<div class="table-wrap"><table>
  <thead><tr>
    <th>Buyer</th><th class="right">Balance</th><th class="right">In escrow</th>
    <th class="right">Paid out</th><th class="right">Jobs</th>
    <th class="right">Approved</th><th class="right">Rejected</th>
    <th class="right">Lapsed</th><th>Concerns</th><th></th>
  </tr></thead>
  <tbody>${all.map(b => {
    const x = b.behaviour;
    return `<tr class="${x.concerns.length ? 'row-warn' : ''}">
      <td><a class="link" href="/admin/users/${b.id}">${V.esc(b.name)}</a>
        <div class="dim">${V.esc(b.email)}</div></td>
      <td class="num right">${V.money(b.balance)}</td>
      <td class="num right">${V.money(x.held)}</td>
      <td class="num right">${V.money(x.paidOut)}</td>
      <td class="num right">${x.jobs}<div class="dim">${x.jobsActive} live</div></td>
      <td class="num right">${x.approved}</td>
      <td class="num right ${x.rejectRate !== null && x.rejectRate >= 40 ? 'bad' : ''}">
        ${x.rejected}${x.rejectRate !== null ? `<div class="dim">${x.rejectRate}%</div>` : ''}</td>
      <td class="num right ${x.lapsed ? 'warn-t' : ''}">${x.lapsed}</td>
      <td class="dim clip">${x.concerns.length ? V.esc(x.concerns[0]) : '&mdash;'}</td>
      <td class="right"><a class="link" href="/admin/users/${b.id}">Open</a></td>
    </tr>`;
  }).join('')}</tbody></table></div>`
    : '<div class="pad muted">Nobody has a buyer account yet.</div>'}
</div>

<div class="card pad">
  <h3>What these columns mean</h3>
  <dl class="kv">
    <dt>In escrow</dt><dd>Money they have funded that has not been paid out yet. It is
      theirs until work is approved, and comes back to them if a job is cancelled.</dd>
    <dt>Rejected</dt><dd>A high rate over a lot of decisions is the shape of a buyer
      taking free work &mdash; but it is also the shape of a buyer whose instructions are
      unclear. Look at the actual submissions before deciding.</dd>
    <dt>Lapsed</dt><dd>Submissions they never reviewed, which the site approved and paid
      on their behalf when the deadline passed. Workers are never left waiting, but a
      buyer who does this constantly is not running their jobs.</dd>
  </dl>
</div>`,
  });
});

app.get('/admin/jobs', need('admin'), (req, res) => {
  const status = ['active', 'completed', 'cancelled'].includes(req.query.status) ? req.query.status : null;
  const rows = db.prepare(`
    SELECT j.*, u.name AS buyer,
      (SELECT COUNT(*) FROM submissions WHERE job_id = j.id AND status = 'submitted') AS waiting,
      (SELECT COUNT(*) FROM submissions WHERE job_id = j.id AND status = 'approved') AS approved
    FROM jobs j JOIN users u ON u.id = j.merchant_id
    ${status ? 'WHERE j.status = ?' : ''}
    ORDER BY j.id DESC LIMIT 200
  `).all(...(status ? [status] : []));

  send(req, res, {
    title: 'Jobs', active: 'jobs', wide: true,
    body: `
<div class="page-head"><div><h1>Jobs</h1>
  <p class="muted">Every job posted, and what has happened to it.</p></div>
  <div class="range">
    <a class="${!status ? 'on' : ''}" href="/admin/jobs">All</a>
    <a class="${status === 'active' ? 'on' : ''}" href="/admin/jobs?status=active">Live</a>
    <a class="${status === 'completed' ? 'on' : ''}" href="/admin/jobs?status=completed">Done</a>
    <a class="${status === 'cancelled' ? 'on' : ''}" href="/admin/jobs?status=cancelled">Cancelled</a>
  </div>
</div>

<div class="card">${rows.length ? `<div class="table-wrap"><table>
  <thead><tr><th>Job</th><th>Buyer</th><th class="right">Pays</th><th class="right">Filled</th>
    <th class="right">Waiting</th><th class="right">In escrow</th><th>State</th></tr></thead>
  <tbody>${rows.map(j => `<tr>
    <td><a class="link" href="/jobs/${j.id}">${V.esc(j.title)}</a></td>
    <td><a class="link" href="/admin/users/${j.merchant_id}">${V.esc(j.buyer)}</a></td>
    <td class="num right">${V.money(j.rate)}</td>
    <td class="num right">${j.slots_filled} / ${j.slots}</td>
    <td class="num right ${j.waiting ? 'warn-t' : ''}">${j.waiting}</td>
    <td class="num right">${V.money(money.escrowRemaining(j.id))}</td>
    <td>${V.statusPill(j.status)}</td>
  </tr>`).join('')}</tbody></table></div>`
    : '<div class="pad muted">No jobs yet.</div>'}</div>`,
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

<div class="card"><div class="card-head"><h2>Withdrawals</h2>
  <span class="dim">every account detail, so it can be checked before sending</span></div>
${wds.length ? wds.map(w => `
<div class="wd ${w.status === 'pending' ? 'wd-open' : ''}">
  <div class="wd-top">
    <div>
      <b>${V.esc(w.name)}</b> <span class="dim">${V.esc(w.email)}</span>
      <div class="dim">asked ${V.ago(w.created_at)}</div>
    </div>
    <div class="wd-amt">${V.money(w.amount)}</div>
    <div>${V.statusPill(w.status)}</div>
  </div>

  <div class="wd-grid">
    <div><span>Send by</span><b>${V.esc(w.method === 'bank' ? 'Bank transfer' : w.method)}
      ${w.method !== 'bank' ? '<i class="dim">personal wallet</i>' : ''}</b></div>
    <div><span>Account name</span><b class="pick">${V.esc(w.account_name || '-')}</b></div>
    <div><span>${w.method === 'bank' ? 'Account number' : 'Number'}</span>
      <b class="pick mono">${V.esc(w.account_number || w.detail || '-')}</b></div>
    ${w.method === 'bank' ? `
      <div><span>Bank</span><b class="pick">${V.esc(w.bank_name || '-')}</b></div>
      <div><span>Branch</span><b class="pick">${V.esc(w.branch || '-')}</b></div>` : ''}
  </div>

  ${w.note ? `<p class="fine">Note: ${V.esc(w.note)}</p>` : ''}
  ${w.proof_file ? `<p class="fine">
    <a class="link" href="/payout-proof/${V.esc(w.proof_file)}" target="_blank" rel="noopener">
      See the payment screenshot</a> sent to them.</p>` : ''}

  ${w.status === 'pending' ? `
  <div class="wd-actions">
    <form method="post" action="/admin/withdrawals/${w.id}/pay" enctype="multipart/form-data">
      ${csrfField(req)}
      <label class="file-pick">
        <input type="file" name="proof" accept="image/jpeg,image/png,image/webp">
        <span>Attach the payment screenshot</span>
      </label>
      <button class="btn btn-sm" type="submit">Mark paid and send it</button>
      <span class="fine">The screenshot is optional, but it is what stops "I never got it"
        turning into an argument nobody can settle.</span>
    </form>
    <form method="post" action="/admin/withdrawals/${w.id}/reject" class="wd-reject">
      ${csrfField(req)}
      <input type="text" name="note" placeholder="Why you are refusing it" required maxlength="120">
      <button class="btn btn-ghost btn-sm" type="submit">Reject and refund</button>
    </form>
  </div>` : ''}
</div>`).join('') : '<div class="pad muted">No withdrawals.</div>'}
</div>`,
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

/* Mark a withdrawal paid, with the screenshot of the transfer attached.

   Multipart, so the CSRF check has to run again after multer - the global one
   skips multipart because the fields are not parsed yet when it runs.
*/
app.post('/admin/withdrawals/:id/pay', need('admin'), upload.single('proof'), checkCsrf, (req, res) => {
  const id = Number(req.params.id);
  try {
    // Attached before settling: if the file cannot be recorded, nothing has
    // been marked paid yet and the admin can try again.
    if (req.file) {
      db.prepare("UPDATE withdrawals SET proof_file = ? WHERE id = ? AND status = 'pending'")
        .run(req.file.filename, id);
    }
    money.settleWithdrawal(id, true, 'Paid');
    audit(req.user.id, 'withdrawal_paid', `withdrawal:${id}`,
      { proof: req.file ? req.file.filename : null }, req.ip);
    back(res, '/admin/money',
      req.file ? 'Marked as paid, with the screenshot attached.' : 'Marked as paid.', 'ok');
  } catch (err) { fail(res, err.message); }
});

/* The payment screenshot.

   Only the person it was sent to, and an admin. It shows an account number
   and a name, which is nobody else's business.
*/
app.get('/payout-proof/:name', need(), (req, res) => {
  const name = path.basename(String(req.params.name));
  const file = path.join(DATA_DIR, 'proofs', name);
  if (!file.startsWith(path.join(DATA_DIR, 'proofs')) || !fs.existsSync(file)) return res.status(404).end();

  const w = db.prepare('SELECT user_id FROM withdrawals WHERE proof_file = ?').get(name);
  if (!w) return res.status(404).end();
  if (req.user.role !== 'admin' && req.user.id !== w.user_id) return res.status(404).end();

  res.setHeader('Cache-Control', 'private, max-age=300');
  res.sendFile(file);
});

app.post('/admin/withdrawals/:id/reject', need('admin'), (req, res) => {
  try {
    money.settleWithdrawal(Number(req.params.id), false, String(req.body.note || '').slice(0, 120));
    back(res, '/admin/money', 'Rejected and the balance returned.', 'info');
  } catch (err) { fail(res, err.message); }
});

/* The people list, split by what kind of account they hold.

   Workers and buyers are judged on different things - a worker on the quality
   of what they send, a buyer on whether they pay for what they receive - so
   mixing them in one table means half the columns are meaningless for half the
   rows. The tabs are the fix, and the counts sit on them so an admin can see
   the shape of the site without clicking.
*/
app.get('/admin/users', need('admin'), (req, res) => {
  const q = String(req.query.q || '').trim();
  const role = ['worker', 'merchant', 'admin'].includes(req.query.role) ? req.query.role : null;
  const status = ['active', 'suspended', 'banned'].includes(req.query.status) ? req.query.status : null;

  const where = [];
  const args = [];
  if (role) { where.push('u.role = ?'); args.push(role); }
  if (status) { where.push('u.status = ?'); args.push(status); }
  if (q) {
    where.push('(u.name LIKE ? OR u.email LIKE ? OR u.username LIKE ?)');
    args.push('%' + q + '%', '%' + q + '%', '%' + q + '%');
  }

  const rows = db.prepare(`
    SELECT u.*,
      (SELECT COALESCE(SUM(amount), 0) FROM ledger WHERE user_id = u.id) AS balance,
      (SELECT COUNT(*) FROM submissions WHERE worker_id = u.id AND status = 'approved') AS approved,
      (SELECT COUNT(*) FROM submissions WHERE worker_id = u.id AND status = 'rejected') AS rejected,
      (SELECT COUNT(*) FROM submissions WHERE worker_id = u.id AND status IN ('started','submitted')) AS busy,
      (SELECT COUNT(*) FROM jobs WHERE merchant_id = u.id) AS jobs,
      (SELECT COUNT(*) FROM jobs WHERE merchant_id = u.id AND status = 'active') AS jobsLive,
      (SELECT COUNT(*) FROM submissions WHERE merchant_id = u.id AND status = 'submitted') AS toReview
    FROM users u
    ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
    ORDER BY u.id DESC LIMIT 300
  `).all(...args);

  const counts = db.prepare(
    'SELECT role, COUNT(*) AS n FROM users GROUP BY role'
  ).all().reduce((a, r) => (a[r.role] = r.n, a), {});
  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  const keep = (extra) => {
    const parts = [];
    if (q) parts.push('q=' + encodeURIComponent(q));
    if (extra) parts.push(extra);
    return parts.length ? '?' + parts.join('&') : '';
  };

  const buyers = role === 'merchant';

  send(req, res, {
    title: 'People', active: 'users', wide: true,
    body: `
<div class="page-head">
  <div><h1>${buyers ? 'Buyers' : role === 'worker' ? 'Workers' : role === 'admin' ? 'Admins' : 'People'}</h1>
    <p class="muted">${buyers
      ? 'Accounts that post and fund work. For how they treat workers, use the buyer view.'
      : role === 'worker'
        ? 'Accounts that do tasks and get paid.'
        : 'Everyone with an account, whatever they use it for.'}</p></div>
  <form class="filters" method="get">
    ${role ? `<input type="hidden" name="role" value="${V.esc(role)}">` : ''}
    <input type="search" name="q" value="${V.esc(q)}" placeholder="Name, email or username">
    <button class="btn btn-ghost" type="submit">Search</button>
  </form>
</div>

<div class="range wide-range">
  <a class="${!role ? 'on' : ''}" href="/admin/users${keep()}">Everyone <i>${total}</i></a>
  <a class="${role === 'worker' ? 'on' : ''}" href="/admin/users${keep('role=worker')}">Workers <i>${counts.worker || 0}</i></a>
  <a class="${role === 'merchant' ? 'on' : ''}" href="/admin/users${keep('role=merchant')}">Buyers <i>${counts.merchant || 0}</i></a>
  <a class="${role === 'admin' ? 'on' : ''}" href="/admin/users${keep('role=admin')}">Admins <i>${counts.admin || 0}</i></a>
  ${buyers ? '<a class="alt" href="/admin/buyers">How they treat workers &rarr;</a>' : ''}
</div>

<div class="card"><div class="table-wrap"><table>
  <thead><tr>
    <th>Person</th><th>Type</th><th class="right">Balance</th>
    ${buyers
      ? '<th class="right">Jobs</th><th class="right">To review</th>'
      : '<th class="right">Approved</th><th class="right">Rejected</th><th class="right">Busy</th>'}
    <th>Email</th><th>State</th><th></th>
  </tr></thead>
  <tbody>${rows.length ? rows.map(u => `<tr>
    <td><a class="link" href="/admin/users/${u.id}">${V.esc(u.name)}</a>
      <div class="dim">${V.esc(u.email)}${u.username ? ` &middot; ${V.esc(u.username)}` : ''}</div></td>
    <td><span class="pill ${u.role === 'merchant' ? 'lvl' : ''}">${u.role === 'merchant' ? 'buyer' : V.esc(u.role)}</span></td>
    <td class="num right">${V.money(u.balance)}</td>
    ${buyers
      ? `<td class="num right">${u.jobs}<div class="dim">${u.jobsLive} live</div></td>
         <td class="num right ${u.toReview ? 'warn-t' : ''}">${u.toReview}</td>`
      : `<td class="num right">${u.approved}</td>
         <td class="num right ${u.rejected ? 'bad' : ''}">${u.rejected}</td>
         <td class="num right">${u.busy}</td>`}
    <td>${u.email_verified
      ? '<span class="pill s-approved">confirmed</span>'
      : '<span class="pill s-submitted">unconfirmed</span>'}</td>
    <td>${V.statusPill(u.status)}${u.suspend_reason ? `<div class="dim clip">${V.esc(u.suspend_reason)}</div>` : ''}</td>
    <td class="right nowrap">
      ${u.role === 'admin' ? '' : `<a class="link" href="/admin/users/${u.id}#balance">Add funds</a>`}
      <a class="link" href="/admin/users/${u.id}">Open</a></td>
  </tr>`).join('') : '<tr><td colspan="8" class="pad muted">Nobody matches that.</td></tr>'}</tbody>
</table></div></div>`,
  });
});

/* One person, everything about them, on one page.

   Built because the alternative is an admin trying to judge a report by
   flicking between four screens. A decision to suspend somebody should be made
   with their whole record in view: what they earned, what was rejected, how
   fast they work, who else shares their connection.
*/
app.get('/admin/users/:id', need('admin'), (req, res) => {
  const id = Number(req.params.id);
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!u) return fail(res, 'No such user.');

  const asWorker = db.prepare(`
    SELECT
      COUNT(*) AS taken,
      SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved,
      SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected,
      SUM(CASE WHEN status IN ('started','submitted') THEN 1 ELSE 0 END) AS open,
      SUM(CASE WHEN flagged = 1 THEN 1 ELSE 0 END) AS flagged,
      AVG(CASE WHEN seconds_spent IS NOT NULL THEN seconds_spent END) AS avg_seconds
    FROM submissions WHERE worker_id = ?
  `).get(id);

  const asMerchant = db.prepare(`
    SELECT COUNT(*) AS jobs,
      COALESCE(SUM(slots), 0) AS slots,
      COALESCE(SUM(slots_filled), 0) AS filled
    FROM jobs WHERE merchant_id = ?
  `).get(id);

  const earned = db.prepare(
    "SELECT COALESCE(SUM(amount), 0) AS n FROM ledger WHERE user_id = ? AND kind = 'task_earning'"
  ).get(id).n;
  const deposited = db.prepare(
    "SELECT COALESCE(SUM(amount), 0) AS n FROM ledger WHERE user_id = ? AND kind = 'deposit'"
  ).get(id).n;
  const withdrawn = db.prepare(
    "SELECT COALESCE(SUM(amount), 0) AS n FROM withdrawals WHERE user_id = ? AND status = 'paid'"
  ).get(id).n;

  const ledger = money.history(id, 25);
  const tasks = db.prepare(`
    SELECT s.*, j.title, j.rate, j.min_seconds FROM submissions s JOIN jobs j ON j.id = s.job_id
    WHERE s.worker_id = ? ORDER BY s.id DESC LIMIT 25
  `).all(id);
  const jobs = db.prepare(
    'SELECT * FROM jobs WHERE merchant_id = ? ORDER BY id DESC LIMIT 15'
  ).all(id);
  const reportsAgainst = db.prepare(
    'SELECT * FROM reports WHERE against_id = ? ORDER BY id DESC LIMIT 10'
  ).all(id);
  const peers = u.last_ip ? auth.accountsOnIp(u.last_ip).filter(a => a.id !== id) : [];
  const logins = db.prepare(
    'SELECT ip, user_agent, created_at FROM logins WHERE user_id = ? ORDER BY id DESC LIMIT 10'
  ).all(id);

  const rate = asWorker.taken
    ? Math.round((asWorker.approved / Math.max(1, asWorker.approved + asWorker.rejected)) * 100)
    : null;

  send(req, res, {
    title: u.name, active: 'users', wide: true,
    body: `
<a class="back" href="/admin/users">&larr; All users</a>
<div class="page-head">
  <div>
    <h1>${V.esc(u.name)}</h1>
    <p class="muted">${V.esc(u.email)} · ${V.esc(u.role)} · joined ${V.ago(u.created_at)}
      ${u.country ? '· ' + V.esc(u.country) : ''}</p>
  </div>
  <div class="btn-row">
    ${V.statusPill(u.status)}
    ${u.role === 'admin' ? '' : (u.status === 'active' ? `
      <form method="post" action="/admin/users/${u.id}/suspend" class="inline">${csrfField(req)}
        <input type="text" name="reason" placeholder="Reason" required maxlength="120">
        <button class="btn btn-danger btn-sm" type="submit">Suspend</button></form>` : `
      <form method="post" action="/admin/users/${u.id}/restore" class="inline">${csrfField(req)}
        <button class="btn btn-sm" type="submit">Restore</button></form>`)}
  </div>
</div>

${u.suspend_reason ? `<div class="alert alert-stop"><b>Suspended:</b> ${V.esc(u.suspend_reason)}
  ${u.suspended_until ? `· lifts ${V.esc(u.suspended_until.slice(0, 10))}` : ''}</div>` : ''}

<div class="stat-row">
  <div class="stat"><b>${V.money(money.balance(u.id))}</b><span>balance now</span></div>
  <div class="stat ok"><b>${V.money(earned)}</b><span>earned from tasks</span></div>
  <div class="stat"><b>${V.money(deposited)}</b><span>deposited</span></div>
  <div class="stat"><b>${V.money(withdrawn)}</b><span>withdrawn</span></div>
  <div class="stat"><b>${asWorker.approved || 0}</b><span>tasks approved</span></div>
  <div class="stat ${asWorker.rejected ? 'bad' : ''}"><b>${asWorker.rejected || 0}</b><span>rejected</span></div>
  ${rate !== null ? `<div class="stat ${rate < 70 ? 'bad' : ''}"><b>${rate}%</b><span>approval rate</span></div>` : ''}
  <div class="stat ${asWorker.flagged ? 'warn' : ''}"><b>${asWorker.flagged || 0}</b><span>flagged</span></div>
  <div class="stat"><b>${asWorker.avg_seconds ? V.mmss(Math.round(asWorker.avg_seconds)) : '--'}</b><span>average time</span></div>
  <div class="stat"><b>${u.strikes}</b><span>strikes</span></div>
</div>

${asMerchant.jobs ? `<div class="stat-row">
  <div class="stat"><b>${asMerchant.jobs}</b><span>jobs posted</span></div>
  <div class="stat"><b>${asMerchant.filled} / ${asMerchant.slots}</b><span>slots taken</span></div>
</div>` : ''}

<div class="card">
  ${u.role !== 'merchant' && !asMerchant.jobs ? '' : (() => {
    const b = stats.buyerBehaviour(id);
    return `
<div class="card">
  <div class="card-head">
    <h2>As a buyer</h2>
    <a class="link" href="/admin/buyers">Compare with other buyers</a>
  </div>

  ${b.concerns.length ? `<div class="pad"><div class="alert alert-warn">
    <b>Worth a closer look:</b>
    <ul class="tight-list">${b.concerns.map(c => `<li>${V.esc(c)}</li>`).join('')}</ul>
    <span class="fine">None of this is proof on its own. A high rejection rate can simply mean
      unclear instructions. Read the submissions before acting.</span>
  </div></div>` : `<div class="pad"><p class="muted">Nothing unusual. They are reviewing work
    and paying for it at ordinary rates.</p></div>`}

  <div class="pad">
    <div class="stat-row">
      <div class="stat"><b>${b.jobsActive}</b><span>jobs running</span></div>
      <div class="stat"><b>${b.jobs}</b><span>jobs posted</span></div>
      <div class="stat ${b.waiting ? 'warn' : ''}"><b>${b.waiting}</b><span>waiting on them</span></div>
      <div class="stat ok"><b>${V.money(b.paidOut)}</b><span>paid to workers</span></div>
      <div class="stat"><b>${V.money(b.held)}</b><span>still in escrow</span></div>
    </div>
    <div class="stat-row">
      <div class="stat"><b>${b.approved}</b><span>approved</span></div>
      <div class="stat ${b.rejectRate !== null && b.rejectRate >= 40 ? 'bad' : ''}">
        <b>${b.rejected}</b><span>rejected${b.rejectRate !== null ? ` (${b.rejectRate}%)` : ''}</span></div>
      <div class="stat ${b.lapsed ? 'warn' : ''}"><b>${b.lapsed}</b><span>deadline lapsed</span></div>
      <div class="stat"><b>${b.reviewDays === null ? '--' : b.reviewDays + 'd'}</b><span>average to review</span></div>
      <div class="stat ${b.upheld ? 'bad' : ''}"><b>${b.upheld} / ${b.reports}</b><span>reports upheld</span></div>
      <div class="stat"><b>${b.stars === null ? '--' : b.stars + '/5'}</b><span>worker rating${b.ratings ? ` (${b.ratings})` : ''}</span></div>
    </div>
    <p class="fine">Money in escrow is theirs until work is approved, and returns to them if a
       job is cancelled. It is not ours and it is not the workers' yet, which is why it is
       counted separately from a balance.</p>
  </div>

  ${jobs.length ? `<div class="table-wrap"><table>
    <thead><tr><th>Job</th><th class="right">Pays</th><th class="right">Filled</th>
      <th class="right">Waiting</th><th class="right">Escrow</th><th>State</th></tr></thead>
    <tbody>${jobs.map(j => {
      const waiting = db.prepare("SELECT COUNT(*) AS n FROM submissions WHERE job_id = ? AND status = 'submitted'").get(j.id).n;
      return `<tr>
        <td><a class="link" href="/jobs/${j.id}">${V.esc(j.title)}</a></td>
        <td class="num right">${V.money(j.rate)}</td>
        <td class="num right">${j.slots_filled} / ${j.slots}</td>
        <td class="num right ${waiting ? 'warn-t' : ''}">${waiting}</td>
        <td class="num right">${V.money(money.escrowRemaining(j.id))}</td>
        <td>${V.statusPill(j.status)}</td></tr>`;
    }).join('')}</tbody></table></div>` : ''}
</div>`;
  })()}

  <div class="card-head" id="balance"><h2>Adjust balance</h2></div>
  <div class="pad">
    <p class="muted">Adds or removes money by hand. It appears in their wallet history
       like anything else, they are told the reason, and it is written to the audit log
       against your name. A deduction cannot take anyone below zero.</p>
    <form method="post" action="/admin/users/${u.id}/balance" class="adjust-form">
      ${csrfField(req)}
      <div class="field">
        <label for="f-direction">Do what</label>
        <select id="f-direction" name="direction">
          <option value="add">Add to balance</option>
          <option value="remove">Take from balance</option>
        </select>
      </div>
      <div class="field">
        <label for="f-currency">Currency</label>
        <select id="f-currency" name="currency">
          <option value="local">${V.esc(getSetting('currency'))}</option>
          <option value="usd">USD (converted at ${V.money(numSetting('usd_rate'))} per $1)</option>
        </select>
      </div>
      <div class="field">
        <label for="f-amount">Amount</label>
        <input id="f-amount" type="text" name="amount" placeholder="500.00" required>
      </div>
      <div class="field wide">
        <label for="f-reason">Reason (they will read this)</label>
        <input id="f-reason" type="text" name="reason" required maxlength="200"
               placeholder="bKash payment received outside the gateway, trx ABC123">
      </div>
      <button class="btn" type="submit">Apply</button>
    </form>
  </div>
</div>

<div class="two">
  <div class="card">
    <div class="card-head"><h2>Tasks</h2></div>
    ${tasks.length ? `<div class="table-wrap"><table>
      <thead><tr><th>Job</th><th>Time</th><th>State</th><th>When</th></tr></thead>
      <tbody>${tasks.map(t => `<tr${t.flagged ? ' class="flagged"' : ''}>
        <td>${V.esc(t.title)}${t.flagged ? ` <span class="flag">flagged</span>` : ''}
          ${t.flag_reason ? `<div class="dim clip">${V.esc(t.flag_reason)}</div>` : ''}</td>
        <td class="num ${t.seconds_spent != null && t.seconds_spent < t.min_seconds ? 'bad' : ''}">${V.mmss(t.seconds_spent)}</td>
        <td>${V.statusPill(t.status)}</td>
        <td class="dim">${V.ago(t.started_at)}</td>
      </tr>`).join('')}</tbody></table></div>`
      : '<div class="pad muted">No tasks.</div>'}
  </div>

  <div class="card">
    <div class="card-head"><h2>Wallet</h2></div>
    ${ledger.length ? `<div class="table-wrap"><table>
      <thead><tr><th>When</th><th>What</th><th class="right">Amount</th></tr></thead>
      <tbody>${ledger.map(l => `<tr>
        <td class="dim">${V.ago(l.created_at)}</td>
        <td class="clip">${V.esc(l.note || l.kind)}</td>
        <td class="num right ${l.amount >= 0 ? 'pos' : 'neg'}">${l.amount >= 0 ? '+' : '-'}${V.money(Math.abs(l.amount))}</td>
      </tr>`).join('')}</tbody></table></div>`
      : '<div class="pad muted">No money has moved.</div>'}
  </div>
</div>

${jobs.length ? `<div class="card">
  <div class="card-head"><h2>Jobs posted</h2></div>
  <div class="table-wrap"><table>
    <thead><tr><th>Title</th><th>Rate</th><th>Filled</th><th>Held</th><th>State</th></tr></thead>
    <tbody>${jobs.map(j => `<tr>
      <td><a class="link" href="/jobs/${j.id}">${V.esc(j.title)}</a></td>
      <td class="num">${V.money(j.rate)}</td>
      <td class="num">${j.slots_filled} / ${j.slots}</td>
      <td class="num">${V.money(money.escrowRemaining(j.id))}</td>
      <td>${V.statusPill(j.status)}</td>
    </tr>`).join('')}</tbody></table></div>
</div>` : ''}

${reportsAgainst.length ? `<div class="card">
  <div class="card-head"><h2>Reported ${reportsAgainst.length} time${reportsAgainst.length === 1 ? '' : 's'}</h2></div>
  <div class="table-wrap"><table>
    <thead><tr><th>When</th><th>Reason</th><th>Detail</th><th>Result</th></tr></thead>
    <tbody>${reportsAgainst.map(r => `<tr>
      <td class="dim">${V.ago(r.created_at)}</td><td>${V.esc(r.reason)}</td>
      <td class="clip">${V.esc(r.detail || '')}</td><td>${V.statusPill(r.status)}</td>
    </tr>`).join('')}</tbody></table></div>
</div>` : ''}

<div class="two">
  <div class="card">
    <div class="card-head"><h2>Sign-ins</h2></div>
    <div class="table-wrap"><table>
      <thead><tr><th>When</th><th>Address</th></tr></thead>
      <tbody>${logins.map(l => `<tr>
        <td class="dim">${V.ago(l.created_at)}</td>
        <td class="mono">${V.esc(l.ip || '')}</td>
      </tr>`).join('') || '<tr><td colspan="2" class="muted pad">None.</td></tr>'}</tbody>
    </table></div>
  </div>

  <div class="card">
    <div class="card-head"><h2>Others on their connection</h2></div>
    ${peers.length ? `<div class="table-wrap"><table>
      <thead><tr><th>User</th><th>Role</th><th>Last seen</th></tr></thead>
      <tbody>${peers.map(p => `<tr>
        <td><a class="link" href="/admin/users/${p.id}">${V.esc(p.name)}</a>
          <div class="dim">${V.esc(p.email)}</div></td>
        <td>${V.esc(p.role)}</td><td class="dim">${V.ago(p.last_login)}</td>
      </tr>`).join('')}</tbody></table></div>
      <div class="pad"><p class="fine">Shared addresses are normal here &mdash; mobile
        networks, offices and families all produce this. Weigh it with everything else
        on this page, never on its own.</p></div>`
      : '<div class="pad muted">Nobody else has signed in from their address.</div>'}
  </div>
</div>`,
  });
});

/* Add or take money from one account by hand.

   Accepts either the site currency or USD; USD is converted at the rate in
   settings and the exact amount that will land is shown on the confirmation
   before anything moves.
*/
app.post('/admin/users/:id/balance', need('admin'), (req, res) => {
  const id = Number(req.params.id);
  const currency = req.body.currency === 'usd' ? 'usd' : 'local';
  const direction = req.body.direction === 'remove' ? -1 : 1;
  const reason = String(req.body.reason || '').trim().slice(0, 200);

  let units;
  if (currency === 'usd') {
    const usd = Number(String(req.body.amount || '').trim());
    if (!Number.isFinite(usd) || usd <= 0) return fail(res, 'Enter a USD amount like 25 or 12.50');
    units = Math.round(usd * numSetting('usd_rate'));
  } else {
    units = money.parseAmount(req.body.amount);
    if (!units || units <= 0) return fail(res, 'Enter an amount like 500 or 500.00');
  }

  try {
    const result = money.adjustBalance({
      userId: id, amount: units * direction, reason, adminId: req.user.id,
    });
    db.prepare(`INSERT INTO notices (user_id, kind, title, body) VALUES (?, 'balance', ?, ?)`)
      .run(id,
        direction > 0 ? `${money.fmt(units)} was added to your balance`
                      : `${money.fmt(units)} was taken from your balance`,
        `Reason given: ${reason}` + String.fromCharCode(10, 10) +
        `Your balance is now ${money.fmt(result.after)}. It is in your wallet history as well. If this looks wrong, message support.`);

    audit(req.user.id, direction > 0 ? 'balance_credit' : 'balance_debit', `user:${id}`,
      { units, currency, reason, before: result.before, after: result.after }, req.ip);

    back(res, '/admin/users/' + id,
      `${direction > 0 ? 'Added' : 'Deducted'} ${money.fmt(units)}. New balance ${money.fmt(result.after)}.`, 'ok');
  } catch (err) {
    fail(res, err.message);
  }
});

/* Settings an admin can change without a deploy. Deliberately a short list -
   anything that changes how money is calculated belongs here where it can be
   seen, not spread through the code. */
const EDITABLE = [
  { key: 'usd_rate', label: 'Rate for 1 USD', money: true,
    hint: 'Used for crypto deposits and USD adjustments. Set by hand on purpose - a wrong automatic rate mispays everyone quietly.' },
  { key: 'commission_bps', label: 'Platform fee', bps: true,
    hint: 'Taken from each approved task. 1000 = 10%.' },
  { key: 'min_withdrawal', label: 'Smallest withdrawal', money: true },
  { key: 'min_deposit', label: 'Smallest deposit', money: true,
    hint: 'A floor in local currency. The one people actually see is the dollar figure below.' },
  { key: 'min_deposit_usd', label: 'Smallest deposit in USD', money: true,
    hint: 'In dollars. Deposits are chosen in dollars whichever way somebody pays. 1.00 = one dollar.' },
  { key: 'max_tasks_per_day', label: 'Tasks per worker per day' },
  { key: 'max_tasks_per_merchant_per_day', label: 'Tasks from one buyer per day' },
  { key: 'min_seconds_floor', label: 'Minimum seconds on any task' },
  { key: 'auto_suspend_rejects', label: 'Rejections that suspend' },
  { key: 'auto_suspend_window_days', label: 'Counted over how many days' },
  { key: 'strikes_before_suspend', label: 'Strikes before suspension' },
  { key: 'suspend_days', label: 'Suspension length in days' },
  { key: 'ip_accounts_warn', label: 'Accounts on one connection before a notice' },
  // Every contact field is optional and is hidden across the whole site while
  // it is blank, so a half-filled install never shows a dead link or an empty
  // "call us on".
  { key: 'business_email', label: 'Contact email', text: true, group: 'Business details' },
  { key: 'business_phone', label: 'Contact phone', text: true, group: 'Business details' },
  { key: 'business_address', label: 'Registered address', text: true, group: 'Business details' },
  { key: 'business_reg', label: 'Business registration / trade licence', text: true, group: 'Business details' },

  { key: 'verify_meta', label: 'Domain ownership tags', text: true, group: 'Business details',
    hint: 'One per line, as name=value. What Cryptomus, Google Search Console and Facebook hand you to prove the domain is yours. Example: cryptomus=613393ab-...' },

  { key: 'telegram_channel', label: 'Telegram channel', text: true, group: 'Support channels',
    hint: 'Announcements, one way. Full link: https://t.me/yourchannel' },
  { key: 'telegram_support', label: 'Telegram support chat', text: true, group: 'Support channels',
    hint: 'Where people message you directly: https://t.me/yourusername' },
  { key: 'telegram_group', label: 'Telegram group', text: true, group: 'Support channels',
    hint: 'The community group, if you run one.' },
  { key: 'whatsapp_number', label: 'WhatsApp number', text: true, group: 'Support channels',
    hint: 'International format, digits only: 8801XXXXXXXXX. The link is built for you.' },
  { key: 'whatsapp_text', label: 'WhatsApp opening message', text: true, group: 'Support channels',
    hint: 'Pre-filled in their chat box so you know what they are writing about.' },
  { key: 'facebook_page', label: 'Facebook page', text: true, group: 'Support channels' },
  { key: 'facebook_group', label: 'Facebook group', text: true, group: 'Support channels' },
  { key: 'live_chat_url', label: 'Live chat embed URL', text: true, group: 'Support channels',
    hint: 'Tawk.to, Crisp or similar. Leave blank to use the built-in ticket system only.' },
  { key: 'support_hours', label: 'When support answers', text: true, group: 'Support channels' },

  { key: 'mail_enabled', label: 'Send email', bool: true, group: 'Email',
    hint: 'Nothing is sent until the host and from-address below are filled in. Set to No to hold mail deliberately - it is queued, not lost.' },
  { key: 'mail_from', label: 'Send from address', text: true, group: 'Email',
    hint: 'Must be an address your mail server is allowed to send as.' },
  { key: 'mail_from_name', label: 'Send from name', text: true, group: 'Email' },
  { key: 'smtp_host', label: 'SMTP host', text: true, group: 'Email',
    hint: 'For example smtp.gmail.com, or smtp-relay.brevo.com.' },
  { key: 'smtp_port', label: 'SMTP port', group: 'Email',
    hint: '587 for STARTTLS, 465 for TLS. Both are encrypted; plain sending is refused.' },
  { key: 'smtp_user', label: 'SMTP username', text: true, group: 'Email' },
  { key: 'smtp_pass', label: 'SMTP password', text: true, secret: true, group: 'Email',
    hint: 'Leave blank to keep the one already saved. For Gmail this is an app password, not your account password.' },
  { key: 'mail_on_signup', label: 'Email on sign-up', bool: true, group: 'Which emails go out' },
  { key: 'mail_on_task_submitted', label: 'Email the buyer when work arrives', bool: true, group: 'Which emails go out' },
  { key: 'mail_on_task_decided', label: 'Email the worker on approve or reject', bool: true, group: 'Which emails go out' },
  { key: 'mail_on_deposit', label: 'Email on deposit', bool: true, group: 'Which emails go out' },
  { key: 'mail_on_withdrawal', label: 'Email on withdrawal', bool: true, group: 'Which emails go out' },
];

app.get('/admin/settings', need('admin'), (req, res) => {
  send(req, res, {
    title: 'Settings', active: 'settings',
    body: `
<h1>Settings</h1>
<p class="muted">Changed here rather than in the code, so nothing needs a deploy.
   Amounts are in ${V.esc(getSetting('currency'))} unless the label says otherwise.</p>

<form method="post" action="/admin/settings" class="card pad">
  ${csrfField(req)}
  ${[...new Set(EDITABLE.map(f => f.group || 'Money and limits'))].map(group => `
    <h2 class="set-group">${V.esc(group)}</h2>
    <div class="form-grid">
      ${EDITABLE.filter(f => (f.group || 'Money and limits') === group).map(f => {
        const raw = getSetting(f.key, '');
        const shown = f.secret ? '' : (f.money ? (Number(raw) / 100).toFixed(2) : raw);
        const hint = f.hint || (f.money ? 'In ' + getSetting('currency') : (f.bps ? 'Basis points: 1000 = 10%' : ''));
        if (f.bool) {
          return V.field({
            label: f.label, name: f.key, type: 'select', value: raw === '1' ? '1' : '0', hint,
            options: [{ value: '1', label: 'Yes' }, { value: '0', label: 'No' }],
          });
        }
        return V.field({
          label: f.label, name: f.key, value: shown, hint,
          type: f.secret ? 'password' : 'text',
          placeholder: f.secret && raw ? 'unchanged' : '',
        });
      }).join('')}
    </div>`).join('')}
  <button class="btn" type="submit">Save settings</button>
</form>

<div class="card pad">
  <h2>Test your email settings</h2>
  <p class="muted">Not sure what to put in the fields above?
     <a class="link" href="/admin/mail/setup">Use the guided setup</a> instead &mdash; it asks
     for two things and fills in the rest.</p>
  <p class="muted">Sends one message to your own address, through the settings above.
     It tells you whether the connection and the password work before anybody
     else finds out the hard way.</p>
  ${(() => {
    const c = mail.config();
    if (c.enabled) {
      return `<p class="muted">Mail is <b>on</b>, sending through
        ${V.esc(c.host)}:${c.port} as ${V.esc(c.from)}.</p>`;
    }
    const missing = [];
    if (getSetting('mail_enabled', '1') !== '1') missing.push('"Send email" is set to No');
    if (!c.host) missing.push('no SMTP host');
    if (!c.from) missing.push('no from-address');
    return `<p class="muted">Mail is <b>off</b>: ${V.esc(missing.join(', '))}.
      Messages are still being written down and will go out once this is fixed.</p>`;
  })()}
  <form method="post" action="/admin/mail/test">
    ${csrfField(req)}
    ${V.field({ label: 'Send a test to', name: 'to', value: req.user.email, required: true })}
    <button class="btn" type="submit">Send test email</button>
  </form>
</div>`,
  });
});

app.post('/admin/settings', need('admin'), (req, res) => {
  const changed = [];
  for (const f of EDITABLE) {
    const given = String(req.body[f.key] == null ? '' : req.body[f.key]).trim();
    let value;

    if (f.bool) {
      /* A select always submits, so an absent key means the form did not carry
         this field at all - a partial post, or an older page. Leaving it alone
         is the safe reading. Treating absent as "no" once silently switched
         mail off for a save that never mentioned mail. */
      if (req.body[f.key] === undefined) continue;
      value = given === '1' ? '1' : '0';
    } else if (f.secret) {
      // A blank secret means "leave it alone", not "erase it". Otherwise
      // opening the settings page and saving anything wipes the mail password,
      // and mail stops working for a reason nobody connects to the visit.
      if (given === '') continue;
      value = given;
    } else if (f.text) {
      value = given;
    } else if (f.money) {
      const units = money.parseAmount(given);
      if (units === null) return fail(res, `"${f.label}" should be an amount like 120.00`);
      value = String(units);
    } else {
      if (!/^\d+$/.test(given)) return fail(res, `"${f.label}" should be a whole number`);
      value = given;
    }

    if (String(getSetting(f.key, '')) !== value) {
      setSetting(f.key, value);
      changed.push(f.key);
    }
  }

  if (changed.length) audit(req.user.id, 'settings_changed', null, { changed }, req.ip);
  back(res, '/admin/settings',
    changed.length ? `Saved ${changed.length} change${changed.length === 1 ? '' : 's'}.` : 'Nothing changed.',
    'ok');
});

// ====================================================================
//  Mail: a test send, the outbox, and announcements to everybody
// ====================================================================

/* ====================================================================
   Guided email setup.

   The settings page has eight mail fields, and getting them right means
   knowing which host goes with which provider, which port implies which kind
   of encryption, and that Gmail wants an App Password rather than the one you
   sign in with. That is a lot to know before anything works, and the failure
   mode is silence - which reads as "the site is broken".

   So this page asks for the two things only the owner can know, fills in the
   rest from the provider they picked, and refuses to save anything until it
   has actually opened a connection and signed in with it. Settings that were
   never proven to work are how a site ends up quietly sending nothing.
   ==================================================================== */

const MAIL_PROVIDERS = {
  gmail: {
    name: 'Gmail',
    note: 'A personal @gmail.com address, or Google Workspace.',
    host: 'smtp.gmail.com', port: 587,
    userLabel: 'Your full Gmail address',
    userPlaceholder: 'you@gmail.com',
    passLabel: 'App Password',
    passHint: 'Sixteen letters from Google, not your normal password. Steps are below.',
    free: 'Around 500 messages a day.',
    steps: [
      'Open myaccount.google.com and sign in with the address you want to send from.',
      'Go to Security, and switch on 2-Step Verification if it is not already on. Google will not offer App Passwords without it.',
      'Still under Security, open App passwords. If you cannot find it, go straight to myaccount.google.com/apppasswords.',
      'Type any name you like, such as Remote Work BD, and press Create.',
      'Google shows sixteen letters in four groups. Copy them, spaces and all, and paste them below. You will not be shown them again.',
    ],
  },
  brevo: {
    name: 'Brevo',
    note: 'Built for sending to a list. Better deliverability than Gmail at volume.',
    host: 'smtp-relay.brevo.com', port: 587,
    userLabel: 'Your Brevo SMTP login',
    userPlaceholder: 'you@example.com',
    passLabel: 'SMTP key',
    passHint: 'From the SMTP & API page in Brevo. Not your account password.',
    free: '300 messages a day, free.',
    steps: [
      'Create an account at brevo.com and confirm your address.',
      'Open the account menu, then SMTP & API.',
      'On the SMTP tab, press Generate a new SMTP key and give it any name.',
      'Copy the login and the key it shows you, and paste them below.',
      'Under Senders, add and verify the address you want mail to come from.',
    ],
  },
  zoho: {
    name: 'Zoho Mail',
    note: 'Free mail on your own domain.',
    host: 'smtp.zoho.com', port: 587,
    userLabel: 'Your Zoho address',
    userPlaceholder: 'you@yourdomain.com',
    passLabel: 'App password',
    passHint: 'Zoho also wants an app-specific password, not your sign-in one.',
    free: 'Fine for a small site.',
    steps: [
      'Sign in at zoho.com and open My Account, then Security.',
      'Find App Passwords and press Generate New Password.',
      'Name it Remote Work BD and copy what it gives you.',
      'Paste it below with your full Zoho address.',
    ],
  },
  outlook: {
    name: 'Outlook or Hotmail',
    note: 'A personal Microsoft address.',
    host: 'smtp-mail.outlook.com', port: 587,
    userLabel: 'Your Outlook address',
    userPlaceholder: 'you@outlook.com',
    passLabel: 'App password',
    passHint: 'Microsoft needs two-step verification switched on first.',
    free: 'Low limits. Fine for testing, not for announcements.',
    steps: [
      'Open account.microsoft.com/security and switch on two-step verification.',
      'Open Advanced security options, then Create a new app password.',
      'Copy it and paste it below.',
    ],
  },
  other: {
    name: 'Something else',
    note: 'Any SMTP server - your host, your own mail server, Mailgun, Postmark.',
    host: '', port: 587,
    userLabel: 'SMTP username',
    userPlaceholder: 'usually the full email address',
    passLabel: 'SMTP password',
    passHint: '',
    free: '',
    steps: [
      'Find the SMTP details from whoever provides the mailbox.',
      'You need a host, a port, a username and a password.',
      'Use port 587 unless they tell you 465. Both are encrypted; anything else is refused.',
    ],
  },
};

app.get('/admin/mail/setup', need('admin'), (req, res) => {
  const pick = MAIL_PROVIDERS[req.query.p] ? req.query.p : null;
  const cfg = mail.config();

  send(req, res, {
    title: 'Set up email', active: 'mail',
    body: `
<a class="back" href="/admin/mail">&larr; Email</a>
<h1>Set up email</h1>
<p class="muted">Two things only you can know, and the rest is filled in for you.
   Nothing is saved until it has actually connected and signed in.</p>

${cfg.enabled ? `<div class="alert alert-ok">
  <b>Email already works.</b> Sending through ${V.esc(cfg.host)} as ${V.esc(cfg.from)}.
  Filling this in again will replace those settings.</div>` : ''}

<div class="card pad">
  <h2>1. Where will the mail be sent from?</h2>
  <p class="muted">Whichever you already have. Gmail is the quickest if you are only
     sending receipts and confirmations.</p>
  <div class="prov-grid">
    ${Object.entries(MAIL_PROVIDERS).map(([key, v]) => `
      <a class="prov ${key === pick ? 'on' : ''}" href="/admin/mail/setup?p=${key}">
        <b>${V.esc(v.name)}</b>
        <span>${V.esc(v.note)}</span>
        ${v.free ? `<em>${V.esc(v.free)}</em>` : ''}
      </a>`).join('')}
  </div>
</div>

${!pick ? '' : (() => {
  const v = MAIL_PROVIDERS[pick];
  return `
<div class="card pad">
  <h2>2. Get the password</h2>
  <p class="muted">${pick === 'other'
    ? 'From whoever runs the mailbox.'
    : `${v.name} will not accept the password you sign in with. It needs a separate one, made just for this site, which you can revoke later without changing anything else.`}</p>
  <ol class="steps">
    ${v.steps.map(x => `<li>${V.esc(x)}</li>`).join('')}
  </ol>
</div>

<form method="post" action="/admin/mail/setup" class="card pad">
  ${csrfField(req)}
  <input type="hidden" name="provider" value="${V.esc(pick)}">
  <h2>3. Fill these in</h2>

  ${V.field({ label: v.userLabel, name: 'user', required: true,
    placeholder: v.userPlaceholder, value: getSetting('smtp_user', '') })}
  ${V.field({ label: v.passLabel, name: 'pass', type: 'password', required: true,
    hint: v.passHint, placeholder: 'paste it here' })}
  ${V.field({ label: 'Name people will see it from', name: 'fromName',
    value: getSetting('mail_from_name', 'Remote Work BD'),
    hint: 'What appears as the sender in their inbox.' })}

  ${pick === 'other' ? `
    <div class="row-2">
      ${V.field({ label: 'SMTP host', name: 'host', required: true,
        value: getSetting('smtp_host', ''), placeholder: 'smtp.yourhost.com' })}
      ${V.field({ label: 'Port', name: 'port', type: 'number', value: getSetting('smtp_port', '587'),
        hint: '587 for STARTTLS, 465 for TLS.' })}
    </div>
    ${V.field({ label: 'Send from address', name: 'from', required: true,
      value: getSetting('mail_from', ''), placeholder: 'noreply@yourdomain.com' })}`
    : `<p class="fine">Host and port are set for you:
        <b>${V.esc(v.host)}</b> on port <b>${v.port}</b>, encrypted with STARTTLS.
        Mail will be sent from the address above.</p>`}

  <div class="btn-row">
    <button class="btn btn-lg" type="submit">Test it and save</button>
  </div>
  <p class="fine">This opens a connection and signs in before saving anything. If the
     password is wrong you will be told now rather than finding out when somebody
     does not get their confirmation link.</p>
</form>`;
})()}`,
  });
});

/* Turn an SMTP failure into something a person can act on.

   The raw text is kept, because it is what a search engine or a provider's
   support will recognise. But "535-5.7.8 Username and Password not accepted"
   tells somebody nothing about what to do, and by far the most common cause
   is the one thing the page already warned about: a normal Gmail password
   pasted where an App Password belongs.
*/
function mailAdvice(message, provider) {
  const m = String(message || '');

  if (/535|5\.7\.8|Username and Password not accepted|Authentication failed|AUTH/i.test(m)) {
    if (provider === 'gmail') {
      return 'Gmail refused the sign-in. Almost always one of two things: this is your '
        + 'ordinary Google password rather than a 16-letter App Password, or 2-Step '
        + 'Verification is not switched on yet - Google will not issue an App Password '
        + 'without it. / জিমেইল লগইন নেয়নি। সাধারণ পাসওয়ার্ড নয়, ১৬ অক্ষরের App Password দিন, '
        + 'আর আগে 2-Step Verification চালু থাকতে হবে।';
    }
    if (provider === 'brevo') {
      return 'Brevo refused the sign-in. Use the SMTP key from SMTP & API, not your '
        + 'account password, and the login shown on that same page.';
    }
    return 'The mail server refused the username or password. Check both, and whether '
      + 'this provider needs an app-specific password rather than your normal one.';
  }

  if (/534|Application-specific password required/i.test(m)) {
    return 'Google is asking for an App Password specifically. Make one at '
      + 'myaccount.google.com/apppasswords and paste that instead.';
  }
  if (/ENOTFOUND|getaddrinfo/i.test(m)) {
    return 'That host name does not resolve. Check the spelling of the SMTP host.';
  }
  if (/ECONNREFUSED/i.test(m)) {
    return 'Nothing is listening on that port. Try 587, or 465 if your provider asks for it.';
  }
  if (/ETIMEDOUT|Could not reach|stopped responding/i.test(m)) {
    return 'The server did not answer. The port may be blocked where this site is hosted - '
      + 'try 465 if you used 587, or the other way round.';
  }
  if (/STARTTLS/i.test(m)) {
    return 'That port offers no encryption, so sending was refused. Use 587 or 465.';
  }
  if (/self-signed|certificate/i.test(m)) {
    return 'The server presented a certificate that could not be verified. Check the host name '
      + 'is the one the provider gave you.';
  }
  return '';
}

app.post('/admin/mail/setup', need('admin'), async (req, res) => {
  const b = req.body || {};
  const v = MAIL_PROVIDERS[b.provider];
  if (!v) return back(res, '/admin/mail/setup', 'Pick where the mail is sent from first.', 'fail');

  const user = String(b.user || '').trim();
  // Gmail shows the App Password in four groups of four. People paste it as
  // shown, and Google does not want the spaces.
  const pass = String(b.pass || '').replace(/\s+/g, '');
  const host = (b.provider === 'other' ? String(b.host || '').trim() : v.host);
  const port = Number(b.provider === 'other' ? b.port : v.port) || 587;
  const from = (b.provider === 'other' ? String(b.from || '').trim() : user);
  const fromName = String(b.fromName || '').trim() || 'Remote Work BD';

  if (!user || !pass) return back(res, `/admin/mail/setup?p=${b.provider}`, 'Fill in both the address and the password.', 'fail');
  if (!host) return back(res, `/admin/mail/setup?p=${b.provider}`, 'Give the SMTP host.', 'fail');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(from)) {
    return back(res, `/admin/mail/setup?p=${b.provider}`, 'That send-from address does not look like an email address.', 'fail');
  }

  const trial = { host, port, user, pass, secure: port === 465 };

  // Prove it works before writing anything down.
  try {
    await smtp.check(trial);
  } catch (err) {
    const advice = mailAdvice(err.message, b.provider);
    return back(res, `/admin/mail/setup?p=${b.provider}`,
      advice ? `${advice}  (${err.message})` : `Could not sign in: ${err.message}`, 'fail');
  }

  // Then prove a message actually leaves.
  try {
    const { html, text } = mail.render({
      heading: 'Email is working',
      intro: 'Sent from the setup page, through the settings you just entered.',
      lines: [`Through ${host} on port ${port}, as ${from}.`,
        'Confirmations, receipts and announcements will now reach people.'],
    });
    await smtp.send(trial, {
      from, fromName, to: req.user.email,
      subject: 'Remote Work BD - email is working', text, html,
    });
  } catch (err) {
    const advice = mailAdvice(err.message, b.provider);
    return back(res, `/admin/mail/setup?p=${b.provider}`,
      `Signed in, but the message was refused. ${advice || ''} (${err.message})`.trim(), 'fail');
  }

  setSetting('smtp_host', host);
  setSetting('smtp_port', String(port));
  setSetting('smtp_user', user);
  setSetting('smtp_pass', pass);
  setSetting('mail_from', from);
  setSetting('mail_from_name', fromName);
  setSetting('mail_enabled', '1');

  // Anything queued while mail was off can go now.
  mail.flush(50).catch(e => console.error('first flush:', e.message));

  audit(req.user.id, 'mail_configured', null, { host, port, from, provider: b.provider }, req.ip);
  back(res, '/admin/mail',
    `Email is on. A test was sent to ${req.user.email} - check it arrived, and look in spam if it did not.`,
    'ok');
});

app.post('/admin/mail/test', need('admin'), async (req, res) => {
  const to = String((req.body || {}).to || '').trim();
  if (!to) return back(res, '/admin/settings', 'Give an address to send to.', 'fail');

  const cfg = mail.config();
  if (!cfg.host) return back(res, '/admin/settings', 'Set an SMTP host first.', 'fail');
  if (!cfg.from) return back(res, '/admin/settings', 'Set the address to send from first.', 'fail');

  // Sent directly rather than queued: the whole point is to find out now
  // whether it works, and a queued message would only tell you a minute later.
  try {
    const { html, text } = mail.render({
      heading: 'Your email settings work',
      intro: 'This is a test from the admin settings page.',
      lines: [`Sent through ${cfg.host} on port ${cfg.port} as ${cfg.from}.`,
        'If you are reading this, receipts and notices will reach people too.'],
    });
    await smtp.send(cfg, {
      from: cfg.from, fromName: cfg.fromName, to,
      subject: 'Remote Work BD - test email', text, html,
    });
    audit(req.user.id, 'mail_test', null, { to, host: cfg.host }, req.ip);
    back(res, '/admin/settings', `Sent to ${to}. If it does not arrive, check the spam folder.`, 'ok');
  } catch (err) {
    const advice = mailAdvice(err.message, /gmail/i.test(cfg.host) ? 'gmail' : '');
    back(res, '/admin/settings',
      advice ? `${advice}  (${err.message})` : `It did not send: ${err.message}`, 'fail');
  }
});

app.get('/admin/mail', need('admin'), (req, res) => {
  const status = ['queued', 'sent', 'failed', 'held'].includes(req.query.status) ? req.query.status : null;
  const rows = db.prepare(`
    SELECT m.*, u.name AS person FROM mail_outbox m
    LEFT JOIN users u ON u.id = m.user_id
    ${status ? 'WHERE m.status = ?' : ''}
    ORDER BY m.id DESC LIMIT 200
  `).all(...(status ? [status] : []));

  const counts = db.prepare(
    'SELECT status, COUNT(*) AS n FROM mail_outbox GROUP BY status'
  ).all().reduce((acc, r) => (acc[r.status] = r.n, acc), {});

  const cfg = mail.config();

  send(req, res, {
    title: 'Email', active: 'mail', wide: true,
    body: `
<div class="page-head">
  <div><h1>Email</h1>
    <p class="muted">Everything the site has tried to send. Mail is
      <b>${cfg.enabled ? 'on' : 'off'}</b>${cfg.enabled ? ` via ${V.esc(cfg.host)}` : ''}.</p></div>
  <div class="btn-row">
    <a class="btn btn-ghost" href="/admin/mail/setup">${cfg.enabled ? 'Change email settings' : 'Set up email'}</a>
    <a class="btn" href="/admin/announce">Write an announcement</a>
  </div>
</div>

${cfg.enabled ? '' : `<div class="alert alert-warn">
  <b>Mail is switched off, so nothing is being sent.</b>
  Messages are still being written down, and nothing is lost in the meantime.
  <a href="/admin/mail/setup">Set it up in three steps</a>.</div>`}

<div class="stat-row">
  <a class="stat" href="/admin/mail"><b>${Object.values(counts).reduce((a, b) => a + b, 0)}</b><span>all</span></a>
  <a class="stat ok" href="/admin/mail?status=sent"><b>${counts.sent || 0}</b><span>sent</span></a>
  <a class="stat" href="/admin/mail?status=queued"><b>${counts.queued || 0}</b><span>waiting</span></a>
  <a class="stat" href="/admin/mail?status=held"><b>${counts.held || 0}</b><span>held</span></a>
  <a class="stat ${counts.failed ? 'bad' : ''}" href="/admin/mail?status=failed"><b>${counts.failed || 0}</b><span>failed</span></a>
</div>

<div class="card">
  ${rows.length ? `<div class="table-wrap"><table>
    <thead><tr><th>To</th><th>Subject</th><th>Kind</th><th>State</th><th>Tries</th><th>When</th></tr></thead>
    <tbody>${rows.map(m => `<tr>
      <td>${V.esc(m.to_email)}${m.person ? `<div class="dim">${V.esc(m.person)}</div>` : ''}</td>
      <td>${V.esc(m.subject)}${m.last_error ? `<div class="dim">${V.esc(m.last_error)}</div>` : ''}</td>
      <td class="dim">${V.esc(m.kind)}</td>
      <td>${V.statusPill(m.status)}</td>
      <td class="num">${m.attempts}</td>
      <td class="dim">${V.ago(m.sent_at || m.created_at)}</td>
    </tr>`).join('')}</tbody></table></div>`
    : '<div class="pad muted">Nothing has been sent yet.</div>'}
</div>

${counts.failed ? `
<form method="post" action="/admin/mail/retry" class="card pad">
  ${csrfField(req)}
  <h2>Try the failed ones again</h2>
  <p class="muted">Puts everything that gave up back in the queue. Worth doing once
     you have fixed whatever the error above was complaining about.</p>
  <button class="btn" type="submit">Retry ${counts.failed} failed</button>
</form>` : ''}`,
  });
});

app.post('/admin/mail/retry', need('admin'), (req, res) => {
  const r = db.prepare("UPDATE mail_outbox SET status = 'queued', attempts = 0 WHERE status = 'failed'").run();
  audit(req.user.id, 'mail_retry', null, { requeued: r.changes }, req.ip);
  back(res, '/admin/mail', `${r.changes} message(s) back in the queue.`, 'ok');
});

app.get('/admin/announce', need('admin'), (req, res) => {
  const reach = db.prepare(`
    SELECT
      COUNT(*) AS all_users,
      SUM(CASE WHEN role = 'worker' THEN 1 ELSE 0 END) AS workers,
      SUM(CASE WHEN role = 'merchant' THEN 1 ELSE 0 END) AS merchants
    FROM users
    WHERE role != 'admin' AND email_opt_out = 0 AND status != 'banned'
      AND email IS NOT NULL AND email != ''
  `).get();

  send(req, res, {
    title: 'Announcement', active: 'mail',
    body: `
<a class="back" href="/admin/mail">&larr; Email</a>
<h1>Write an announcement</h1>
<p class="muted">Goes to everyone who has not turned announcements off. It is queued
   one message per person, so nobody sees anybody else's address.</p>

<form method="post" action="/admin/announce" class="card pad">
  ${csrfField(req)}
  ${V.field({ label: 'Subject', name: 'subject', required: true,
    placeholder: 'Payouts will be slower this weekend' })}
  ${V.field({ label: 'Heading inside the email', name: 'heading',
    hint: 'Leave blank to reuse the subject.' })}
  ${V.field({ label: 'What you want to say', name: 'body', type: 'textarea', rows: 10, required: true,
    hint: 'A blank line starts a new paragraph. Write it as you would say it - no HTML.' })}
  <div class="field">
    <label for="f-aud">Who gets it</label>
    <select id="f-aud" name="audience">
      <option value="all">Everyone (${reach.all_users || 0} people)</option>
      <option value="workers">Workers only (${reach.workers || 0})</option>
      <option value="merchants">Buyers only (${reach.merchants || 0})</option>
    </select>
  </div>
  <label class="check">
    <input type="checkbox" name="sure" value="1" required>
    <span>I have read it back and it is ready to send.</span>
  </label>
  <button class="btn btn-lg" type="submit">Queue the announcement</button>
  <p class="fine">Queued, not sent instantly: they go out steadily over the next few
     minutes so the mail server does not treat a burst as spam.</p>
</form>`,
  });
});

app.post('/admin/announce', need('admin'), (req, res) => {
  const b = req.body || {};
  const subject = String(b.subject || '').trim();
  const body = String(b.body || '').trim();
  if (!subject || !body) return back(res, '/admin/announce', 'Give it a subject and something to say.', 'fail');
  if (!b.sure) return back(res, '/admin/announce', 'Tick the box once you have read it back.', 'fail');

  const queued = mail.broadcast({
    subject, body,
    heading: String(b.heading || '').trim() || subject,
    audience: ['all', 'workers', 'merchants'].includes(b.audience) ? b.audience : 'all',
    adminId: req.user.id,
  });

  // Also put it in the on-site notices, so it reaches people whose mail
  // bounces, who never open email, or who turned announcements off.
  const audience = b.audience === 'workers' ? "AND role = 'worker'"
    : b.audience === 'merchants' ? "AND role = 'merchant'" : '';
  const people = db.prepare(
    `SELECT id FROM users WHERE role != 'admin' AND status != 'banned' ${audience}`
  ).all();
  const notice = db.prepare(
    "INSERT INTO notices (user_id, kind, title, body) VALUES (?, 'announcement', ?, ?)"
  );
  for (const person of people) notice.run(person.id, subject, body);

  back(res, '/admin/mail',
    `Queued for ${queued} inbox${queued === 1 ? '' : 'es'}, and shown on site to ${people.length}.`,
    'ok');
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
  /* Only link to a deposit that exists.

     deposit_id is a foreign key, so an order id we do not recognise used to
     fail the insert and take the whole webhook down with it - a 500, which
     every gateway answers by retrying, so one stray callback became a storm.
     The claimed id is still in the stored payload, so nothing is lost by
     recording the row unlinked. */
  const linked = depositId
    && db.prepare('SELECT 1 FROM deposits WHERE id = ?').get(depositId) ? depositId : null;

  db.prepare(`INSERT INTO gateway_events (provider, deposit_id, ref, verified, status, payload, ip)
              VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(provider, linked, ref || null, verified ? 1 : 0, status || null,
         typeof payload === 'string' ? payload.slice(0, 20000) : JSON.stringify(payload).slice(0, 20000),
         ip || null);
}

/* Start an EPS payment: bKash, Nagad, Rocket, card, internet banking. */
app.post('/wallet/deposit/eps', need('merchant'), active, async (req, res) => {
  if (!eps.configured()) return fail(res, 'Card and mobile banking payments are not switched on yet.');

  /* Chosen in dollars, like the crypto side, and converted here.

     EPS charges in whole taka, so the converted figure is rounded up to the
     next whole unit and that same rounded figure is what gets credited. The
     alternative - charging one number and crediting another - puts a few
     paisa into the books from nowhere on every single deposit. */
  const usd = Number(String(req.body.usd || '').trim());
  const minUsd = numSetting('min_deposit_usd');
  if (!Number.isFinite(usd) || usd <= 0) return fail(res, 'Enter an amount in USD.');
  if (Math.round(usd * 100) < minUsd) {
    return fail(res, `The smallest deposit is $${(minUsd / 100).toFixed(2)}`);
  }

  const rate = numSetting('usd_rate');
  const amount = Math.ceil((usd * rate) / 100) * 100;

  const mtid = eps.newTransactionId();
  const info = db.prepare(`INSERT INTO deposits (user_id, amount, method, provider, provider_ref, reference)
                           VALUES (?, ?, ?, 'eps', ?, ?)`)
    // The asked-for figure, not a rounded one: this is the line an admin reads
    // when matching a payment, and $1.005 charged as 121 should not be filed
    // as $1.00.
    .run(req.user.id, amount, 'eps', mtid, `$${usd} @ ${rate / 100}`);
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
  const minUsd = numSetting('min_deposit_usd');
  if (!Number.isFinite(usd) || usd <= 0) return fail(res, 'Enter an amount in USD.');
  if (Math.round(usd * 100) < minUsd) {
    return fail(res, `The smallest deposit is $${(minUsd / 100).toFixed(2)}`);
  }

  const rate = numSetting('usd_rate');                 // local units per 1 USD
  const credit = Math.round(usd * rate);

  const info = db.prepare(`INSERT INTO deposits (user_id, amount, method, provider, reference)
                           VALUES (?, ?, 'crypto', 'cryptomus', ?)`)
    .run(req.user.id, credit, `$${usd} @ ${rate / 100}`);
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

  /* The invoice this callback is about must be the invoice we opened for this
     deposit.

     order_id is our own row number, which is only unique within one database.
     Point a staging deploy and the live site at the same Cryptomus merchant -
     an easy thing to do while testing - and a callback for staging deposit 41
     arrives quoting order_id 41, matching a completely different person's
     deposit here. The signature would be valid, because it is the same
     merchant key. The invoice id is what actually ties the two together. */
  if (dep.provider_ref && payload.uuid && dep.provider_ref !== payload.uuid) {
    audit(null, 'webhook_wrong_invoice', `deposit:${dep.id}`,
      { expected: dep.provider_ref, got: payload.uuid }, req.ip);
    return res.status(200).json({ ok: true });
  }

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

  const site = String(process.env.PUBLIC_URL || '').replace(/\/$/, '');
  const localhost = !site || /localhost|127\.0\.0\.1/.test(site);

  send(req, res, {
    title: 'Gateway', active: 'gateway', wide: true,
    body: `<h1>Gateway activity</h1>

${cryptomus.configured() && eps.configured() ? '' : `
<div class="card pad">
  <h2>Turn a gateway on</h2>
  <p class="muted">Both read their keys from the environment rather than from settings,
     because a payment key is a deployment secret. On Railway that is
     <b>Variables</b>; the service restarts on its own once you save.</p>

  ${cryptomus.configured() ? '' : `
  <div class="setup-block">
    <h3>Cryptomus <span class="pill s-submitted">off</span></h3>
    <p class="muted">Crypto deposits. Sign up at cryptomus.com and pass their KYC,
       then create a merchant &mdash; the keys only exist once a merchant does.
       Both values are on that merchant's own API or integration page.</p>
    <table class="mini"><tbody>
      <tr><td class="mono">CRYPTOMUS_MERCHANT_ID</td><td class="dim">the merchant UUID</td></tr>
      <tr><td class="mono">CRYPTOMUS_PAYMENT_KEY</td><td class="dim">the payment API key, not the payout one</td></tr>
    </tbody></table>
    <p class="muted">Nothing else to configure there. The callback address is sent
       with every payment we create, so there is no webhook field to fill in:</p>
    <p class="mono copyline">${V.esc(site || 'https://your-domain')}/hooks/cryptomus</p>
    <p class="fine">Shown only so you can recognise it in their logs, and so you can
       see at a glance whether it is pointing somewhere real.</p>
    ${localhost ? `<div class="alert alert-warn">
      <b>PUBLIC_URL is not a public address.</b> That address is sent to Cryptomus
      with every payment, and they call it from the internet - so a deposit will
      never be credited while it points at localhost. Set PUBLIC_URL to your real
      domain first.</div>` : ''}
    <p class="fine">Deposits are priced in USD and credited at the
      <a class="link" href="/admin/settings">rate you set by hand</a>
      &mdash; currently ${V.money(numSetting('usd_rate'))} to the dollar. Check that before
      taking a real payment: everything is credited at whatever it says.</p>
  </div>`}

  ${eps.configured() ? '' : `
  <div class="setup-block">
    <h3>EPS <span class="pill s-submitted">off</span></h3>
    <p class="muted">bKash, Nagad, Rocket and cards. Needs a merchant account from
       Easy Payment System, so it takes longer to arrange than Cryptomus.</p>
    <table class="mini"><tbody>
      <tr><td class="mono">EPS_USERNAME</td><td class="dim"></td></tr>
      <tr><td class="mono">EPS_PASSWORD</td><td class="dim"></td></tr>
      <tr><td class="mono">EPS_HASH_KEY</td><td class="dim">signs every request</td></tr>
      <tr><td class="mono">EPS_MERCHANT_ID</td><td class="dim"></td></tr>
      <tr><td class="mono">EPS_STORE_ID</td><td class="dim"></td></tr>
      <tr><td class="mono">EPS_SANDBOX</td><td class="dim">1 to test, 0 for real money</td></tr>
    </tbody></table>
  </div>`}

  <p class="fine">Every callback that arrives is listed below with whether its signature
     checked out. A deposit is only ever credited from a signed callback or a
     server-to-server verify &mdash; never from somebody landing on a success page.</p>
</div>`}

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
// ACCOUNT
// ======================================================================
/* Why switching sides is allowed at all, and what stops it being abused.

   Somebody who came here to work often later wants to hire, and telling them
   to make a second Google account would be telling them to break the one
   account per person rule we enforce everywhere else.

   What it must never do is let anyone walk away from work in flight. A
   merchant with submissions waiting owes those workers a decision; a worker
   holding open tasks owes that buyer either proof or the slot back. So the
   switch is blocked while either is true, and the reason says exactly what to
   finish first.

   It cannot be used to approve your own work: a worker may never take a job
   whose merchant_id is their own user id, and that check reads the job, not
   the current role.
*/
function switchBlockers(user) {
  const reasons = [];

  if (user.role === 'merchant') {
    const waiting = db.prepare(
      "SELECT COUNT(*) AS n FROM submissions WHERE merchant_id = ? AND status = 'submitted'"
    ).get(user.id).n;
    if (waiting) {
      reasons.push(`${waiting} submission${waiting === 1 ? '' : 's'} still need${waiting === 1 ? 's' : ''} your decision`);
    }
    const live = db.prepare(
      "SELECT COUNT(*) AS n FROM jobs WHERE merchant_id = ? AND status IN ('active','paused')"
    ).get(user.id).n;
    if (live) {
      reasons.push(`${live} job${live === 1 ? ' is' : 's are'} still open - cancel or finish ${live === 1 ? 'it' : 'them'} first`);
    }
  }

  if (user.role === 'worker') {
    const open = db.prepare(
      "SELECT COUNT(*) AS n FROM submissions WHERE worker_id = ? AND status IN ('started','submitted')"
    ).get(user.id).n;
    if (open) {
      reasons.push(`${open} task${open === 1 ? '' : 's'} of yours ${open === 1 ? 'is' : 'are'} still open or waiting review`);
    }
  }

  return reasons;
}

app.get('/account', need(), (req, res) => {
  const u = req.user;
  const other = u.role === 'merchant' ? 'worker' : 'merchant';
  const blockers = u.role === 'admin' ? ['Admin accounts do not switch.'] : switchBlockers(u);

  const logins = db.prepare(
    'SELECT ip, created_at FROM logins WHERE user_id = ? ORDER BY id DESC LIMIT 8'
  ).all(u.id);

  const pending = db.prepare(
    "SELECT * FROM role_requests WHERE user_id = ? AND status = 'pending'"
  ).get(u.id);

  const past = db.prepare(
    "SELECT * FROM role_requests WHERE user_id = ? AND status != 'pending' ORDER BY id DESC LIMIT 3"
  ).all(u.id);

  send(req, res, {
    title: 'Account', active: 'account',
    body: `
<h1>Account</h1>

<div class="two">
  <div class="card pad">
    <h2>You</h2>
    <dl class="kv">
      <dt>Name</dt><dd>${V.esc(u.name)}</dd>
      <dt>Email</dt><dd>${V.esc(u.email)}
        ${u.email_verified
          ? '<span class="pill s-approved">confirmed</span>'
          : '<span class="pill s-submitted">not confirmed</span>'}</dd>
      ${u.username ? `<dt>Username</dt><dd>${V.esc(u.username)}</dd>` : ''}
      <dt>Signs in with</dt><dd>${[
        u.google_sub ? 'Google' : null,
        u.password_hash ? 'a password' : null,
      ].filter(Boolean).join(' and ') || 'Google'}</dd>
      <dt>Account type</dt><dd><b>${u.role === 'merchant' ? 'Buyer - you hire' : u.role === 'admin' ? 'Admin' : 'Worker - you do tasks'}</b></dd>
      <dt>Joined</dt><dd>${V.ago(u.created_at)}</dd>
      <dt>Balance</dt><dd>${V.money(money.balance(u.id))}</dd>
    </dl>
  </div>

  ${u.role !== 'worker' ? '' : (() => {
    const st = quality.workerStanding(u.id);
    const mine = stats.myPlace(u.id);
    return `
  <div class="card pad">
    <h2>Your level <span class="bn">আপনার লেভেল</span></h2>
    <div class="level-now">
      <span class="lvl-badge l${st.level}">${V.esc(st.name)}</span>
      <div>
        <b>${V.money(st.earned)} earned</b>
        <span class="dim">from ${st.approved} approved task${st.approved === 1 ? '' : 's'}</span>
      </div>
    </div>

    ${st.next ? `
      <div class="lvl-bar"><span style="width:${st.next.percent}%"></span></div>
      <p class="muted">${V.money(st.next.remaining)} more of approved work reaches
        <b>${V.esc(st.next.name)}</b>.
        <span class="bn">আর ${V.money(st.next.remaining)} টাকার কাজ করলেই ${V.esc(st.next.name)} হয়ে যাবেন।</span></p>`
      : `<p class="muted">You are at the top level. <span class="bn">আপনি সর্বোচ্চ লেভেলে আছেন।</span></p>`}

    ${st.heldBack ? `<div class="alert alert-warn">
      <b>Your earnings would carry a higher level, but too much of your work is being rejected.</b>
      A level needs ${st.next ? st.next.minRate : numSetting('level_min_rate')}% of decided work
      approved; yours is ${st.rate}%. Take more care on each task and it will come back.</div>` : ''}

    <div class="lvl-steps">
      ${quality.LEVELS.map((l, i) => `<div class="${i <= st.level ? 'done' : ''}">
        <b>${V.esc(l.name)}</b>
        <span>${i === 0 ? 'from the start' : V.money(quality.thresholds()[i])}</span>
      </div>`).join('')}
    </div>

    <div class="lvl-prize">
      <b>Monthly prize <span class="bn">মাসিক পুরস্কার</span></b>
      <p class="muted">You have earned ${V.money(mine.earned)} this month
        ${mine.qualifies
          ? `and you are in the running${mine.place ? `, currently ${mine.place}${mine.place === 1 ? 'st' : mine.place === 2 ? 'nd' : mine.place === 3 ? 'rd' : 'th'}` : ''}.`
          : `. Earn ${V.money(Math.max(0, mine.minEarned - mine.earned))} more this month to enter.`}</p>
      <a class="btn btn-ghost btn-sm" href="/leaderboard">See the board</a>
    </div>
  </div>`;
  })()}

  <div class="card pad">
    <h2>Sign-in and security</h2>

    ${u.email_verified ? '' : `
      <div class="alert alert-warn">
        <b>Your email address is not confirmed yet.</b>
        You can look around, but taking work and withdrawing are closed until it is.
        That is what keeps one person from running a row of accounts.
        <form method="post" action="/resend-verification" class="inline-form">
          ${csrfField(req)}
          <button class="btn btn-sm" type="submit">Send the link again</button>
        </form>
      </div>`}

    <form method="post" action="/account/password" class="stack">
      ${csrfField(req)}
      <h3>${u.password_hash ? 'Change your password' : 'Add a password'}</h3>
      <p class="muted">${u.password_hash
        ? 'Changing it signs out everything else that is signed in as you.'
        : 'Your account signs in with Google. Adding a password gives you a second way in - Google keeps working either way.'}</p>
      ${u.password_hash ? V.field({ label: 'Current password', name: 'current', type: 'password', required: true }) : ''}
      ${V.field({ label: 'New password', name: 'password', type: 'password', required: true,
        hint: 'At least 8 characters. Length matters more than punctuation.' })}
      ${V.field({ label: 'Confirm it', name: 'password2', type: 'password', required: true })}
      ${u.password_hash ? '' : V.field({ label: 'Pick a username', name: 'username',
        hint: 'Optional. Letters, numbers, dot or underscore - you can sign in with it instead of your email.' })}
      <button class="btn" type="submit">${u.password_hash ? 'Change password' : 'Set password'}</button>
    </form>

    <form method="post" action="/account/email-prefs" class="stack border-top">
      ${csrfField(req)}
      <h3>Email</h3>
      <label class="check">
        <input type="checkbox" name="updates" value="1"${u.email_opt_out ? '' : ' checked'}>
        <span>Send me announcements and news from Remote Work BD</span>
      </label>
      <p class="fine">Messages about your own money and your account security are sent
         whatever you choose here. A receipt for a payment is not something we can decide
         to withhold.</p>
      <button class="btn btn-ghost btn-sm" type="submit">Save</button>
    </form>
  </div>

  ${u.role === 'admin' ? '' : `
  <div class="card pad">
    <h2>Switch to ${other === 'merchant' ? 'hiring' : 'working'}</h2>
    ${other === 'merchant'
      ? '<p class="muted">Post tasks, fund them up front, and review the proof that comes back. Your balance and history stay exactly as they are.</p>'
      : '<p class="muted">Do tasks yourself and get paid when a buyer approves them. Your balance and history stay exactly as they are.</p>'}

    ${pending ? `
      <div class="alert alert-warn">
        <b>Your request is with an admin.</b>
        Asked ${V.ago(pending.created_at)} to become a ${V.esc(pending.to_role)}.
        You will get a notice here when it is decided.
      </div>
      <form method="post" action="/account/role/withdraw">${csrfField(req)}
        <button class="btn btn-ghost btn-sm" type="submit">Withdraw the request</button></form>`
    : blockers.length ? `
      <div class="alert alert-warn">
        <b>Finish this first:</b>
        <ul class="tight">${blockers.map(b => `<li>${V.esc(b)}</li>`).join('')}</ul>
        Switching now would leave other people waiting on you.
      </div>`
    : `<form method="post" action="/account/role">
         ${csrfField(req)}
         <input type="hidden" name="role" value="${other}">
         ${V.field({ label: 'Why do you want to switch?', name: 'reason', type: 'textarea', rows: 3,
           required: true, hint: 'An admin reads this. A sentence or two is enough.' })}
         <button class="btn" type="submit">Ask to become ${other === 'merchant' ? 'a buyer' : 'a worker'}</button>
       </form>
       <p class="fine">This is not automatic &mdash; an admin checks it first. Usually within a day.</p>`}
  </div>`}
</div>

${past.length ? `<div class="card">
  <div class="card-head"><h2>Past requests</h2></div>
  <div class="table-wrap"><table>
    <thead><tr><th>Asked</th><th>Change</th><th>Result</th><th>Admin said</th></tr></thead>
    <tbody>${past.map(r => `<tr>
      <td class="dim">${V.ago(r.created_at)}</td>
      <td>${V.esc(r.from_role)} &rarr; ${V.esc(r.to_role)}</td>
      <td>${V.statusPill(r.status)}</td>
      <td class="dim">${V.esc(r.admin_note || '')}</td>
    </tr>`).join('')}</tbody></table></div>
</div>` : ''}

<div class="card">
  <div class="card-head"><h2>Recent sign-ins</h2></div>
  <div class="table-wrap"><table>
    <thead><tr><th>When</th><th>Connection</th></tr></thead>
    <tbody>${logins.map(l => `<tr>
      <td class="dim">${V.ago(l.created_at)}</td>
      <td class="mono">${V.esc(l.ip || 'unknown')}</td>
    </tr>`).join('') || '<tr><td colspan="2" class="muted pad">Nothing recorded yet.</td></tr>'}</tbody>
  </table></div>
  <div class="pad"><p class="fine">Shown so you can see what we see. If an address here is
    not yours, <a href="/support">tell support</a>.</p></div>
</div>`,
  });
});

/* Set or change the password on an account.

   Two different situations behind one form: a Google account adding a
   password for the first time, and a password account changing one. The
   difference that matters is that changing an existing password has to prove
   you know the old one - otherwise a borrowed, still-signed-in browser is
   enough to take the account for good.
*/
app.post('/account/password', need(), (req, res) => {
  const b = req.body || {};
  const u = req.user;

  if (String(b.password || '') !== String(b.password2 || '')) {
    return back(res, '/account', 'The two passwords are not the same.', 'fail');
  }

  if (u.password_hash) {
    if (!passwords.verify(String(b.current || ''), u.password_hash)) {
      return back(res, '/account', 'That is not your current password.', 'fail');
    }
  } else if (b.username) {
    // Only offered while the account has no username yet.
    const problem = passwords.problemWithUsername(b.username);
    if (problem) return back(res, '/account', problem, 'fail');
    const taken = db.prepare('SELECT id FROM users WHERE lower(username) = ? AND id != ?')
      .get(String(b.username).toLowerCase(), u.id);
    if (taken) return back(res, '/account', 'That username is taken. Please pick another.', 'fail');
    db.prepare('UPDATE users SET username = ? WHERE id = ?').run(String(b.username).trim(), u.id);
  }

  try {
    auth.setPassword(u.id, b.password, u);
  } catch (err) {
    return back(res, '/account', err.message, 'fail');
  }

  mail.passwordChanged(u);

  // setPassword ends every session, including this one, so sign them straight
  // back in rather than dumping them at the login page for doing the right thing.
  const session = auth.startSession(u.id);
  res.setHeader('Set-Cookie',
    `wrj_session=${session.token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${session.maxAge}`);
  back(res, '/account',
    u.password_hash
      ? 'Password changed. Anything else signed in as you has been signed out.'
      : 'Password set. You can now sign in with it as well as with Google.',
    'ok');
});

app.post('/account/email-prefs', need(), (req, res) => {
  const wants = !!(req.body || {}).updates;
  db.prepare('UPDATE users SET email_opt_out = ? WHERE id = ?').run(wants ? 0 : 1, req.user.id);
  back(res, '/account',
    wants ? 'You will get announcements from us.' : 'You will not get announcements any more.',
    'ok');
});

app.post('/account/role', need(), (req, res) => {
  const u = req.user;
  if (u.role === 'admin') return fail(res, 'Admin accounts do not switch.');

  const want = req.body.role === 'merchant' ? 'merchant' : 'worker';
  if (want === u.role) return back(res, '/account', 'That is already your account type.', 'info');

  const blockers = switchBlockers(u);
  if (blockers.length) return fail(res, 'Finish this first: ' + blockers.join('; '));

  const reason = String(req.body.reason || '').trim().slice(0, 500);
  if (reason.length < 10) {
    return fail(res, 'Tell us in a sentence or two why you want to switch. An admin reads it.');
  }

  try {
    db.prepare('INSERT INTO role_requests (user_id, from_role, to_role, reason) VALUES (?, ?, ?, ?)')
      .run(u.id, u.role, want, reason);
  } catch (err) {
    if (String(err.message).includes('UNIQUE')) {
      return back(res, '/account', 'You already have a request waiting.', 'info');
    }
    throw err;
  }

  audit(u.id, 'role_requested', `user:${u.id}`, { from: u.role, to: want }, req.ip);
  back(res, '/account', 'Sent. An admin will look at it, usually within a day.', 'ok');
});

app.post('/account/role/withdraw', need(), (req, res) => {
  db.prepare("UPDATE role_requests SET status = 'withdrawn', reviewed_at = datetime('now') WHERE user_id = ? AND status = 'pending'")
    .run(req.user.id);
  back(res, '/account', 'Request withdrawn.', 'info');
});

// ---------------------------------------------------------- admin: requests
app.get('/admin/roles', need('admin'), (req, res) => {
  const rows = db.prepare(`
    SELECT r.*, u.name, u.email, u.status AS user_status, u.strikes, u.created_at AS joined,
      (SELECT COUNT(*) FROM submissions WHERE worker_id = u.id AND status = 'approved') AS approved,
      (SELECT COUNT(*) FROM submissions WHERE worker_id = u.id AND status = 'rejected') AS rejected,
      (SELECT COALESCE(SUM(amount), 0) FROM ledger WHERE user_id = u.id) AS balance
    FROM role_requests r JOIN users u ON u.id = r.user_id
    ORDER BY (r.status = 'pending') DESC, r.id DESC LIMIT 100
  `).all();

  send(req, res, {
    title: 'Role requests', active: 'roles', wide: true,
    body: `<h1>Role requests</h1>
<p class="muted">Somebody asking to change which side of the marketplace they are on.
   Worth a look at their history before approving a move to buyer &mdash; a buyer can
   fund jobs, and a worker with a bad record moving across is the pattern to watch for.</p>

${rows.length ? rows.map(r => `
<div class="card">
  <div class="card-head">
    <div><b>${V.esc(r.name)}</b> <span class="dim">${V.esc(r.email)}</span>
      <div class="dim">${V.esc(r.from_role)} &rarr; <b>${V.esc(r.to_role)}</b> · asked ${V.ago(r.created_at)}</div></div>
    ${V.statusPill(r.status)}
  </div>
  <div class="pad">
    <div class="mini-stats">
      <span><b>${r.approved}</b> approved</span>
      <span class="${r.rejected ? 'bad' : ''}"><b>${r.rejected}</b> rejected</span>
      <span><b>${r.strikes}</b> strikes</span>
      <span><b>${V.money(r.balance)}</b> balance</span>
      <span>joined ${V.ago(r.joined)}</span>
      <span>${V.statusPill(r.user_status)}</span>
    </div>
    <h3>Why they asked</h3>
    <div class="prose">${V.br(r.reason || '')}</div>
    ${r.admin_note ? `<h3>Decision</h3><div class="prose muted">${V.br(r.admin_note)}</div>` : ''}
    <p><a class="link" href="/admin/users/${r.user_id}">Open their full record &rarr;</a></p>

    ${r.status === 'pending' ? `<div class="review-actions">
      <form method="post" action="/admin/roles/${r.id}/approve">${csrfField(req)}
        <button class="btn" type="submit">Approve the switch</button></form>
      <form method="post" action="/admin/roles/${r.id}/reject">${csrfField(req)}
        <input type="text" name="note" placeholder="Why not?" required maxlength="200">
        <button class="btn btn-danger" type="submit">Reject</button></form>
    </div>` : ''}
  </div>
</div>`).join('') : '<div class="empty">No requests.</div>'}`,
  });
});

app.post('/admin/roles/:id/approve', need('admin'), (req, res) => {
  const id = Number(req.params.id);
  db.exec('BEGIN IMMEDIATE');
  try {
    const r = db.prepare("SELECT * FROM role_requests WHERE id = ? AND status = 'pending'").get(id);
    if (!r) throw new Error('That request is already decided.');

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(r.user_id);
    if (!user) throw new Error('That account no longer exists.');
    if (user.role === 'admin') throw new Error('Admin accounts do not switch.');

    // Their situation may have changed while the request sat in the queue.
    const blockers = switchBlockers(user);
    if (blockers.length) throw new Error('They now have work in flight: ' + blockers.join('; '));

    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(r.to_role, r.user_id);
    db.prepare(`UPDATE role_requests SET status = 'approved', reviewed_by = ?,
                reviewed_at = datetime('now') WHERE id = ?`).run(req.user.id, id);
    db.prepare(`INSERT INTO notices (user_id, kind, title, body) VALUES (?, 'role', ?, ?)`)
      .run(r.user_id, 'Your account type was changed',
        `You are now ${r.to_role === 'merchant' ? 'a buyer and can post jobs' : 'a worker and can take tasks'}. Your balance and history are unchanged.`);
    db.exec('COMMIT');
    audit(req.user.id, 'role_approved', `user:${r.user_id}`, { to: r.to_role }, req.ip);
    back(res, '/admin/roles', 'Approved.', 'ok');
  } catch (err) {
    db.exec('ROLLBACK');
    fail(res, err.message);
  }
});

app.post('/admin/roles/:id/reject', need('admin'), (req, res) => {
  const note = String(req.body.note || '').trim().slice(0, 200);
  if (!note) return fail(res, 'Give a reason - they will read it.');

  const r = db.prepare("SELECT * FROM role_requests WHERE id = ? AND status = 'pending'").get(Number(req.params.id));
  if (!r) return fail(res, 'That request is already decided.');

  db.prepare(`UPDATE role_requests SET status = 'rejected', admin_note = ?, reviewed_by = ?,
              reviewed_at = datetime('now') WHERE id = ?`).run(note, req.user.id, r.id);
  db.prepare(`INSERT INTO notices (user_id, kind, title, body) VALUES (?, 'role', ?, ?)`)
    .run(r.user_id, 'Your request to switch was not approved',
      note + String.fromCharCode(10,10) + 'If you think this is wrong, message support.');
  audit(req.user.id, 'role_rejected', `user:${r.user_id}`, { note }, req.ip);
  back(res, '/admin/roles', 'Rejected, and they have been told why.', 'info');
});

// ======================================================================
// REFERRALS
// ======================================================================
app.get('/r/:code', (req, res) => {
  // The cookie is set and the destination is the same whether or not the code
  // is real. Redirecting somewhere different for an unknown code would let
  // anyone probe codes to find out which exist - the code is only checked when
  // an account is actually created, where an invalid one simply attaches
  // nobody.
  res.setHeader('Set-Cookie',
    `wrj_ref=${encodeURIComponent(String(req.params.code).slice(0, 12))}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`);
  res.redirect('/login?want=worker');
});

app.get('/referrals', need(), (req, res) => {
  const u = req.user;
  const code = referrals.codeFor(u.id);
  const link = `${(process.env.PUBLIC_URL || '').replace(/\/$/, '') || ''}/r/${code}`;
  const s = referrals.summary(u.id);
  const list = referrals.people(u.id);
  const recent = referrals.recentEarnings(u.id);

  const depositShare = (numSetting('referral_deposit_bps') / 100).toFixed(0);

  send(req, res, {
    title: 'Refer a friend', active: 'referrals',
    body: `
<div class="page-head"><div><h1>Refer a friend ${V.bn('বন্ধুকে আনুন')}</h1>
  <p class="muted">Share your link and earn ${V.money(numSetting('referral_flat'))} once your friend's
     first task is approved.<br>
     ${V.bn(`আপনার লিংকে কেউ জয়েন করে প্রথম কাজ শেষ করলেই আপনি ${V.money(numSetting('referral_flat'))} টাকা পাবেন।`)}</p></div></div>

<div class="stat-row">
  <div class="stat"><b>${s.joined}</b><span>joined with your link ${V.bn('জয়েন করেছে')}</span></div>
  <div class="stat"><b>${s.active}</b><span>have earned you something</span></div>
  <div class="stat ok"><b>${V.money(s.earned)}</b><span>earned from referrals ${V.bn('আয় হয়েছে')}</span></div>
</div>

<div class="card pad ref-card">
  <h2>Your link</h2>
  <div class="ref-link">
    <input type="text" id="ref-link" value="${V.esc(link)}" readonly onclick="this.select()">
    <button class="btn" type="button" id="ref-copy">Copy</button>
  </div>
  <p class="muted">Your code is <b class="mono">${V.esc(code)}</b>. Anyone who signs in
     through your link is linked to you permanently, on their first account only.</p>
</div>

<div class="two">
  <div class="card pad">
    <h2>What you earn</h2>
    <ul class="tick-list">
      <li><b>${V.money(numSetting('referral_flat'))}</b> the first time somebody you
        invited has a task approved. Once per person, on a day you can point at.</li>
      <li><b>${depositShare}% of every deposit</b> a referral you brought in adds to
        their balance as a buyer.</li>
    </ul>
    <p class="fine">Both come out of what the platform earns &mdash; never out of your
      friend's earnings or the price they pay. Nobody is worse off because you referred
      them, which is the only version of this worth running.
      <span class="bn">এই টাকা আমাদের কমিশন থেকে যায় &mdash; আপনার বন্ধুর আয় থেকে এক টাকাও কাটা হয় না।</span></p>
  </div>

  <div class="card pad">
    <h2>The rules</h2>
    <ul class="tick-list">
      <li>One account per person still applies. Signing up again with your own link is
        the fastest way to lose both accounts.</li>
      <li>Rewards are paid when the task is <b>approved</b> or the deposit clears &mdash;
        not when someone signs up.</li>
      <li>Nothing is paid on an account that gets closed for fraud.</li>
    </ul>
  </div>
</div>

${list.length ? `<div class="card">
  <div class="card-head"><h2>People you referred</h2></div>
  <div class="table-wrap"><table>
    <thead><tr><th>Name</th><th>Type</th><th>Joined</th><th>Tasks done</th><th class="right">Earned you</th></tr></thead>
    <tbody>${list.map(p => `<tr>
      <td>${V.esc(p.name)}</td><td>${V.esc(p.role)}</td>
      <td class="dim">${V.ago(p.created_at)}</td><td class="num">${p.tasks}</td>
      <td class="num right ${p.earned ? 'pos' : ''}">${V.money(p.earned)}</td>
    </tr>`).join('')}</tbody></table></div>
</div>` : `<div class="empty">Nobody has used your link yet. Share it and it will show here.</div>`}

${recent.length ? `<div class="card">
  <div class="card-head"><h2>Recent referral earnings</h2></div>
  <div class="table-wrap"><table>
    <thead><tr><th>When</th><th>From</th><th>For</th><th class="right">Amount</th></tr></thead>
    <tbody>${recent.map(r => `<tr>
      <td class="dim">${V.ago(r.created_at)}</td>
      <td>${V.esc(r.from_name)}</td>
      <td>${r.kind === 'task' ? 'a task they completed' : 'a deposit they made'}</td>
      <td class="num right pos">+${V.money(r.amount)}</td>
    </tr>`).join('')}</tbody></table></div>
</div>` : ''}`,
  });
});

// ======================================================================
// PUBLIC ACTIVITY AND PAYMENT PROOF
// ======================================================================
/* Both pages show real rows straight from the database. Nothing is generated,
   padded or back-dated. A site that invents its own activity feed is telling
   its first honest users a lie on the page that asks them to trust it.

   Names are shortened - first name and an initial - because somebody doing
   tasks for money has not agreed to have their full name and payout history on
   a public page. Amounts and timings are real; identities are not the point.
*/
function shortName(name) {
  const parts = String(name || '').trim().split(/\s+/);
  if (!parts[0]) return 'Someone';
  return parts.length > 1 ? `${parts[0]} ${parts[1].charAt(0)}.` : parts[0];
}

app.get('/activity', (req, res) => {
  const jobs = db.prepare(`
    SELECT j.id, j.title, j.rate, j.slots, j.slots_filled, j.created_at,
           c.name AS category, u.name AS buyer
    FROM jobs j LEFT JOIN categories c ON c.id = j.category_id
    JOIN users u ON u.id = j.merchant_id
    WHERE j.status IN ('active','completed')
    ORDER BY j.id DESC LIMIT 40
  `).all();

  const approvals = db.prepare(`
    SELECT s.reviewed_at, j.title, j.rate, w.name AS worker
    FROM submissions s JOIN jobs j ON j.id = s.job_id JOIN users w ON w.id = s.worker_id
    WHERE s.status = 'approved' ORDER BY s.id DESC LIMIT 25
  `).all();

  send(req, res, {
    title: 'Live activity', active: 'activity', wide: true,
    body: `${pageHead('Live activity')}
<p class="lede">Every row here is real and comes straight from the database. Nothing on
   this page is generated to make the site look busier than it is.</p>

<div class="two">
  <div class="card">
    <div class="card-head"><h2>Jobs</h2><a class="link" href="/jobs">Browse open jobs</a></div>
    ${jobs.length ? `<div class="feed-list">${jobs.map(j => {
      const pct = Math.round((j.slots_filled / Math.max(1, j.slots)) * 100);
      return `<a class="feed-row" href="/jobs/${j.id}">
        <div class="feed-main">
          <b>${V.esc(j.title)}</b>
          <span class="dim">${V.esc(j.category || 'Task')} · by ${V.esc(shortName(j.buyer))} · ${V.ago(j.created_at)}</span>
          <span class="bar"><i style="width:${pct}%"></i></span>
        </div>
        <div class="feed-side">
          <b>${V.money(j.rate)}</b>
          <span class="dim">${j.slots_filled} of ${j.slots}</span>
        </div>
      </a>`;
    }).join('')}</div>` : '<div class="pad muted">No jobs yet.</div>'}
  </div>

  <div class="card">
    <div class="card-head"><h2>Approved work</h2></div>
    ${approvals.length ? `<div class="feed-list">${approvals.map(a => `
      <div class="feed-row">
        <div class="feed-main">
          <b>${V.esc(shortName(a.worker))}</b>
          <span class="dim">${V.esc(a.title)} · ${V.ago(a.reviewed_at)}</span>
        </div>
        <div class="feed-side"><b class="pos">+${V.money(a.rate)}</b></div>
      </div>`).join('')}</div>`
      : '<div class="pad muted">No work has been approved yet. When it is, it appears here.</div>'}
  </div>
</div>`,
  });
});

app.get('/payments', (req, res) => {
  const paid = db.prepare(`
    SELECT w.amount, w.method, w.reviewed_at, u.name
    FROM withdrawals w JOIN users u ON u.id = w.user_id
    WHERE w.status = 'paid' ORDER BY w.id DESC LIMIT 50
  `).all();

  const total = db.prepare(
    "SELECT COALESCE(SUM(amount), 0) AS n FROM withdrawals WHERE status = 'paid'"
  ).get().n;
  const people = db.prepare(
    "SELECT COUNT(DISTINCT user_id) AS n FROM withdrawals WHERE status = 'paid'"
  ).get().n;

  send(req, res, {
    title: 'Payment proof',
    body: `${pageHead('Payment proof')}
<p class="lede">Withdrawals we have actually paid. Straight from our records, nothing
   added.</p>

${paid.length ? `
<div class="stat-row">
  <div class="stat ok"><b>${V.money(total)}</b><span>paid out</span></div>
  <div class="stat"><b>${people}</b><span>people paid</span></div>
  <div class="stat"><b>${paid.length}</b><span>most recent shown</span></div>
</div>

<div class="card"><div class="table-wrap"><table>
  <thead><tr><th>When</th><th>Who</th><th>Method</th><th class="right">Amount</th></tr></thead>
  <tbody>${paid.map(p => `<tr>
    <td class="dim">${V.ago(p.reviewed_at)}</td>
    <td>${V.esc(shortName(p.name))}</td>
    <td>${V.esc(p.method)}</td>
    <td class="num right pos">${V.money(p.amount)}</td>
  </tr>`).join('')}</tbody>
</table></div></div>
<p class="fine">Names are shortened. Somebody doing tasks for a living has not agreed to
   have their full name and payout history on a public page.</p>`
: `<div class="empty">
    <p><b>No withdrawals have been paid yet.</b></p>
    <p class="muted">This page fills itself as real payouts happen. We would rather show
      an empty page than invented screenshots &mdash; you can check back.</p>
   </div>`}`,
  });
});

// ======================================================================
// SUPPORT
// ======================================================================
/* Every way of reaching us that has actually been filled in.

   Each one is hidden while its setting is blank. A support page listing a
   WhatsApp number nobody answers, or a Telegram link that 404s, is worse than
   a page that simply does not mention it - people try it, get nothing back,
   and conclude the whole site is abandoned.
*/
function supportChannels() {
  const wa = String(getSetting('whatsapp_number', '')).replace(/[^0-9]/g, '');
  const waText = encodeURIComponent(getSetting('whatsapp_text', ''));

  const channels = [
    { href: getSetting('telegram_channel', ''), name: 'Telegram channel',
      note: 'Announcements and new jobs', icon: 'send' },
    { href: getSetting('telegram_support', ''), name: 'Telegram support',
      note: 'Message us directly', icon: 'send' },
    { href: getSetting('telegram_group', ''), name: 'Telegram group',
      note: 'Ask other members', icon: 'users' },
    { href: wa ? `https://wa.me/${wa}${waText ? '?text=' + waText : ''}` : '',
      name: 'WhatsApp', note: 'Chat with support', icon: 'phone' },
    { href: getSetting('facebook_page', ''), name: 'Facebook page',
      note: 'News and updates', icon: 'globe' },
    { href: getSetting('facebook_group', ''), name: 'Facebook group',
      note: 'The community', icon: 'users' },
  ].filter(c => c.href);

  if (!channels.length) return '';

  const hours = getSetting('support_hours', '');
  return `<div class="chan-wrap">
    <div class="chan-row">
      ${channels.map(c => `<a class="chan" href="${V.esc(c.href)}" target="_blank" rel="noopener">
        <b>${V.esc(c.name)}</b><span>${V.esc(c.note)}</span></a>`).join('')}
    </div>
    ${hours ? `<p class="fine">Support answers ${V.esc(hours)}. A ticket here is always
       read, whatever the hour.</p>` : ''}
  </div>`;
}

/* An external live-chat widget, if one is configured.

   Loaded only where it is wanted and only when a URL is set, so the site has
   no third-party script on it by default - which is what the privacy page
   promises.
*/
function liveChat() {
  const url = String(getSetting('live_chat_url', '')).trim();
  if (!/^https:\/\//.test(url)) return '';
  return `<script async src="${V.esc(url)}" crossorigin="anonymous"></script>`;
}

/* ====================================================================
   The monthly prize.

   Three prizes each month for the workers who earned the most, with a floor
   to enter so it is a reward for real work rather than a lottery. Everything
   is counted from the ledger, so anybody can check their own figure against
   their wallet - a leaderboard nobody can verify is just a poster.
   ==================================================================== */

function prizeTable(board, meId) {
  if (!board.rows.length) {
    return '<div class="pad muted">Nobody has earned anything this month yet. '
      + 'The first task approved starts the board.</div>';
  }
  return `<div class="table-wrap"><table>
    <thead><tr><th>#</th><th>Worker</th><th class="right">Earned</th>
      <th class="right">Tasks</th><th>Prize</th></tr></thead>
    <tbody>${board.rows.map(r => `<tr class="${r.id === meId ? 'row-me' : ''}">
      <td class="num">${r.place <= 3 && r.qualifies ? `<span class="medal m${r.place}">${r.place}</span>` : r.place}</td>
      <td>${V.esc(r.name)}${r.id === meId ? ' <span class="pill s-active">you</span>' : ''}</td>
      <td class="num right">${V.money(r.earned)}</td>
      <td class="num right">${r.tasks}</td>
      <td>${r.prize ? `<b class="pos">${V.money(r.prize)}</b>`
        : r.qualifies ? '<span class="dim">&mdash;</span>'
        : `<span class="dim">needs ${V.money(board.minEarned - r.earned)} more to enter</span>`}</td>
    </tr>`).join('')}</tbody></table></div>`;
}

app.get('/leaderboard', (req, res) => {
  const month = /^\d{4}-\d{2}$/.test(String(req.query.m || '')) ? req.query.m : null;
  const board = stats.leaderboard(month, 25);
  const months = stats.prizeMonths(6);
  const mine = req.user && req.user.role === 'worker' ? stats.myPlace(req.user.id, board.month) : null;

  send(req, res, {
    title: 'Monthly prize',
    body: `
<div class="page-head">
  <div><h1>Monthly prize <span class="bn">মাসিক পুরস্কার</span></h1>
    <p class="muted">Every month the three workers who earn the most share
       ${V.money(board.prizes[0] + board.prizes[1] + board.prizes[2])} between them.</p></div>
  ${months.length > 1 ? `<div class="range">
    ${months.map(m => `<a class="${m.month === board.month ? 'on' : ''}" href="/leaderboard?m=${m.month}">${m.month}</a>`).join('')}
  </div>` : ''}
</div>

<div class="prize-row">
  ${[0, 1, 2].map(i => `<div class="prize p${i + 1}">
    <span class="medal m${i + 1}">${i + 1}</span>
    <b>${V.money(board.prizes[i])}</b>
    <span>${['First', 'Second', 'Third'][i]} place</span>
  </div>`).join('')}
</div>

<div class="alert alert-info">
  <b>To enter, earn ${V.money(board.minEarned)} from approved work in the month.</b>
  <span class="bn">অংশ নিতে হলে মাসে কমপক্ষে ${V.money(board.minEarned)} টাকার কাজ শেষ করতে হবে।</span>
  Only approved work counts, and it is counted from your wallet, so the figure on this
  page is one you can check yourself.
</div>

${mine ? `
<div class="card pad me-standing">
  <h2>Where you stand</h2>
  <div class="stat-row">
    <div class="stat"><b>${mine.place || '--'}</b><span>your place</span></div>
    <div class="stat ok"><b>${V.money(mine.earned)}</b><span>earned this month</span></div>
    <div class="stat ${mine.qualifies ? 'ok' : 'warn'}">
      <b>${mine.qualifies ? 'In' : V.money(Math.max(0, mine.minEarned - mine.earned))}</b>
      <span>${mine.qualifies ? 'you have qualified' : 'more to qualify'}</span></div>
    <div class="stat"><b>${mine.entrants}</b><span>workers qualified</span></div>
  </div>
</div>` : ''}

<div class="card">
  <div class="card-head"><h2>${V.esc(board.month)}</h2>
    ${board.done ? '<span class="pill s-approved">paid out</span>' : '<span class="dim">still running</span>'}</div>
  ${prizeTable(board, req.user ? req.user.id : null)}
</div>`,
  });
});

/* Awarding a month.

   By hand, and only once per month per place - the unique index sees to that
   even if the button is pressed twice. Done by hand on purpose: a month can
   contain a suspended account or somebody an admin is already looking at, and
   a prize paid automatically to a cheat is very hard to take back.
*/
app.get('/admin/prizes', need('admin'), (req, res) => {
  const month = /^\d{4}-\d{2}$/.test(String(req.query.m || '')) ? req.query.m : null;
  const board = stats.leaderboard(month, 25);
  const months = stats.prizeMonths(12);
  const winners = board.rows.filter(r => r.prize > 0);
  const paid = db.prepare(`
    SELECT p.*, u.name FROM prizes p JOIN users u ON u.id = p.user_id
    ORDER BY p.month DESC, p.place ASC LIMIT 30
  `).all();

  send(req, res, {
    title: 'Monthly prize', active: 'prizes', wide: true,
    body: `
<div class="page-head">
  <div><h1>Monthly prize</h1>
    <p class="muted">The three highest earners each month, from approved work only.</p></div>
  <div class="range">
    ${months.map(m => `<a class="${m.month === board.month ? 'on' : ''}" href="/admin/prizes?m=${m.month}">${m.month}</a>`).join('')}
  </div>
</div>

<div class="card">
  <div class="card-head"><h2>${V.esc(board.month)}</h2>
    <a class="link" href="/leaderboard?m=${board.month}">What everyone else sees</a></div>
  ${prizeTable(board, null)}
</div>

${board.done ? `<div class="alert alert-ok">
  <b>This month has been paid.</b>
  ${Object.values(board.awarded).map(a => `${a.place}. ${V.money(a.amount)}`).join(' &middot; ')}
</div>` : winners.length ? `
<form method="post" action="/admin/prizes/award" class="card pad">
  ${csrfField(req)}
  <input type="hidden" name="month" value="${V.esc(board.month)}">
  <h2>Pay this month</h2>
  <p class="muted">Adds the prize to each winner's balance and tells them. Once done it
     cannot be repeated for this month, so check the names first &mdash; a prize paid to
     somebody who was cheating is hard to take back.</p>
  <ul class="tight-list">
    ${winners.map(w => `<li><b>${V.esc(w.name)}</b> &mdash; ${V.money(w.prize)}
      <span class="dim">(earned ${V.money(w.earned)})</span></li>`).join('')}
  </ul>
  <label class="check">
    <input type="checkbox" name="sure" value="1" required>
    <span>I have looked at these accounts and they are genuine.</span>
  </label>
  <button class="btn btn-lg" type="submit">Pay ${V.money(winners.reduce((t, w) => t + w.prize, 0))}</button>
</form>` : `<div class="alert alert-warn">
  <b>Nobody qualifies yet.</b> A worker needs ${V.money(board.minEarned)} of approved work
  in the month to enter.</div>`}

${paid.length ? `<div class="card">
  <div class="card-head"><h2>Already paid</h2></div>
  <div class="table-wrap"><table>
    <thead><tr><th>Month</th><th>Place</th><th>Worker</th><th class="right">Prize</th>
      <th class="right">They earned</th><th>When</th></tr></thead>
    <tbody>${paid.map(x => `<tr>
      <td>${V.esc(x.month)}</td><td class="num">${x.place}</td>
      <td><a class="link" href="/admin/users/${x.user_id}">${V.esc(x.name)}</a></td>
      <td class="num right">${V.money(x.amount)}</td>
      <td class="num right">${V.money(x.earned)}</td>
      <td class="dim">${V.ago(x.created_at)}</td>
    </tr>`).join('')}</tbody></table></div>
</div>` : ''}`,
  });
});

app.post('/admin/prizes/award', need('admin'), (req, res) => {
  const month = /^\d{4}-\d{2}$/.test(String((req.body || {}).month || '')) ? req.body.month : null;
  if (!month) return back(res, '/admin/prizes', 'Which month?', 'fail');
  if (!(req.body || {}).sure) {
    return back(res, `/admin/prizes?m=${month}`, 'Tick the box once you have looked at the accounts.', 'fail');
  }

  const board = stats.leaderboard(month, 25);
  const winners = board.rows.filter(r => r.prize > 0);
  if (!winners.length) return back(res, `/admin/prizes?m=${month}`, 'Nobody qualifies for that month.', 'fail');

  let paid = 0;
  const already = [];
  for (const w of winners) {
    try {
      /* The row goes in first. Its unique index on (month, place) is what
         actually stops a month being paid twice, so it has to be claimed
         before any money moves - the other way round, a double press pays
         twice and only then discovers it should not have. */
      db.prepare(`INSERT INTO prizes (month, place, user_id, amount, earned, awarded_by)
                  VALUES (?, ?, ?, ?, ?, ?)`)
        .run(month, w.place, w.id, w.prize, w.earned, req.user.id);
    } catch (err) {
      if (/UNIQUE/i.test(err.message)) { already.push(w.name); continue; }
      throw err;
    }

    money.adjustBalance({
      userId: w.id, amount: w.prize, adminId: req.user.id,
      reason: `Monthly prize for ${month}, ${['first', 'second', 'third'][w.place - 1]} place`,
    });

    db.prepare("INSERT INTO notices (user_id, kind, title, body) VALUES (?, 'prize', ?, ?)")
      .run(w.id, `You won ${money.fmt(w.prize)} in the ${month} monthly prize`,
        `You came ${w.place === 1 ? 'first' : w.place === 2 ? 'second' : 'third'} for ${month}, `
        + `with ${money.fmt(w.earned)} of approved work. The prize is in your balance now.`);

    mail.queue({
      userId: w.id, kind: 'prize',
      subject: `You won ${money.fmt(w.prize)} in the monthly prize`,
      heading: `${w.place === 1 ? 'First' : w.place === 2 ? 'Second' : 'Third'} place for ${month}`,
      rows: [['Prize', money.fmt(w.prize)], ['You earned', money.fmt(w.earned)], ['Month', month]],
      lines: ['It is in your balance now. The board resets at the start of each month.'],
      button: { label: 'See the board', href: mail.siteUrl() + '/leaderboard' },
    });
    paid++;
  }

  audit(req.user.id, 'prizes_awarded', `month:${month}`, { paid, already }, req.ip);
  back(res, `/admin/prizes?m=${month}`,
    already.length
      ? `Paid ${paid}. ${already.length} had already been paid for that month.`
      : `Paid ${paid} winner${paid === 1 ? '' : 's'}.`,
    'ok');
});

app.get('/support', need(), (req, res) => {
  const tickets = db.prepare(
    'SELECT * FROM tickets WHERE user_id = ? ORDER BY updated_at DESC LIMIT 50'
  ).all(req.user.id);

  send(req, res, {
    title: 'Support', active: 'support',
    body: `
<div class="page-head"><div><h1>Support</h1>
  <p class="muted">Replies land right here, and we usually answer within a day.
     Or reach us wherever suits you better.<br>
     ${V.bn('উত্তর এখানেই পাবেন, সাধারণত একদিনের মধ্যে। অথবা নিচের যেকোনো মাধ্যমে যোগাযোগ করুন।')}</p></div></div>

${supportChannels()}
${liveChat()}

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

/* Shut down cleanly when the platform says to.

   Every deploy stops the old container with SIGTERM. Without this the process
   is killed, npm reports the signal as a failure, and the platform writes
   "Deployment crashed" for what was a completely normal replacement. Two
   problems with that: it is alarming, and it means a real crash one day is
   indistinguishable from the noise.

   Existing requests are given a moment to finish - somebody halfway through
   approving a payment should not have it cut off - and then we exit 0, which
   is the truth: we were asked to stop and we stopped.
*/
let stopping = false;
function shutdown(signal) {
  if (stopping) return;
  stopping = true;
  console.log(`
  ${signal} received, finishing open requests...`);

  const done = () => {
    console.log('  stopped cleanly');
    process.exit(0);
  };

  server.close(done);
  // Do not hang forever on a slow client holding a connection open.
  setTimeout(() => {
    console.log('  some connections were still open, exiting anyway');
    process.exit(0);
  }, 8000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Housekeeping: abandoned slots go back in the pool, dead sessions get swept.
setInterval(() => {
  try {
    spam.releaseExpiredHolds();
    auth.sweepSessions();
    auth.sweepTokens();
    // The review deadline. Also run on boot below, because a server that was
    // down for a day must not swallow the deadlines it was meant to enforce.
    const paid = quality.releaseOverdue();
    if (paid) console.log(`  auto-approved ${paid} submission(s) past their review deadline`);
  } catch (e) { console.error(e.message); }

  // Mail is swept separately and never awaited by a request. A slow or
  // rate-limiting mail server should make mail late, not make the site slow.
  mail.flush().then(r => {
    if (r.sent) console.log(`  sent ${r.sent} email(s)`);
    if (r.failed) console.log(`  ${r.failed} email(s) could not be sent - see /admin/mail`);
  }).catch(e => console.error('mail sweep:', e.message));
}, 60000).unref();

const server = app.listen(PORT, HOST, () => {
  spam.releaseExpiredHolds();
  try {
    const caught = quality.releaseOverdue();
    if (caught) console.log(`  auto-approved ${caught} submission(s) whose deadline passed while down`);
  } catch (e) { console.error('  deadline sweep failed:', e.message); }
  const on = x => (x ? 'on' : 'off');
  console.log('');
  console.log('  Remote Work BD');
  console.log(`  http://localhost:${PORT}`);
  console.log('');
  console.log(`  data      ${DATA_DIR}`);
  console.log(`  sign-in   ${google.configured() ? 'Google + password' : 'password only (Google not configured)'}`);
  const mailCfg = mail.config();
  console.log(`  mail      ${mailCfg.enabled ? `on, via ${mailCfg.host}:${mailCfg.port} as ${mailCfg.from}` : 'off - nothing will be sent'}`);
  console.log(`  admins    ${auth.adminEmails().join(', ') || 'none - set ADMIN_EMAILS'}`);
  console.log(`  payments  EPS ${on(eps.configured())}, Cryptomus ${on(cryptomus.configured())}`);
  if (process.env.ALLOW_DEV_LOGIN === '1') {
    console.log('  dev login ENABLED - /dev-login?email=... (this machine only)');
  }
  console.log('');
});
