/* Server-rendered HTML.

   Pages come back as complete documents. No build step, no client framework,
   and every screen works with JavaScript switched off - which for a site where
   people are counting their earnings is worth more than any animation.
*/

const { getSetting } = require('./db');
const money = require('./money');

const esc = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

// The header mark. Uses assets/logo.png when it is there, and otherwise draws
// the same idea inline - a ring, a node and a rising arrow - so the site never
// shows a broken image while artwork is being prepared.
const fs = require('fs');
const path = require('path');
const LOGO = path.join(__dirname, '..', 'web', 'assets', 'logo.png');

function logoMark() {
  if (fs.existsSync(LOGO)) {
    return '<img class="brand-mark-img" src="/assets/logo.png" alt="" width="32" height="32">';
  }
  return `<span class="brand-mark" aria-hidden="true">
    <svg viewBox="0 0 32 32" width="20" height="20" fill="none">
      <circle cx="16" cy="16" r="12" stroke="currentColor" stroke-width="2"/>
      <path d="M9 20l5-5 3 3 6-7" stroke="currentColor" stroke-width="2.6"
            stroke-linecap="round" stroke-linejoin="round"/>
      <path d="M19 11h5v5" stroke="currentColor" stroke-width="2.6"
            stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
  </span>`;
}

const SITE = 'Remote Work BD';

// Newlines to <br>, after escaping. Written once here so no template has to
// carry an escaped regex around.
const NL = new RegExp('\n', 'g');
function br(text) {
  return esc(text).replace(NL, '<br>');
}

function nav(user, active) {
  if (!user) {
    return `
      <a href="/jobs"${active === 'jobs' ? ' class="on"' : ''}>Browse jobs</a>
      <a href="/activity"${active === 'activity' ? ' class="on"' : ''}>Live activity</a>
      <a href="/payments"${active === 'payments' ? ' class="on"' : ''}>Payment proof</a>
      <a href="/how-it-works"${active === 'how' ? ' class="on"' : ''}>How it works</a>
      <span class="nav-gap"></span>
      <a href="/login" class="btn btn-sm">Continue with Google</a>`;
  }

  if (user.role === 'admin') {
    return `
      <a href="/admin"${active === 'admin' ? ' class="on"' : ''}>Overview</a>
      <a href="/admin/reports"${active === 'reports' ? ' class="on"' : ''}>Reports</a>
      <a href="/admin/money"${active === 'money' ? ' class="on"' : ''}>Money</a>
      <a href="/admin/users"${active === 'users' ? ' class="on"' : ''}>Users</a>
      <a href="/admin/connections"${active === 'connections' ? ' class="on"' : ''}>Connections</a>
      <a href="/admin/roles"${active === 'roles' ? ' class="on"' : ''}>Roles</a>
      <a href="/admin/gateway"${active === 'gateway' ? ' class="on"' : ''}>Gateway</a>
      <a href="/admin/settings"${active === 'settings' ? ' class="on"' : ''}>Settings</a>
      <a href="/admin/support"${active === 'support' ? ' class="on"' : ''}>Support</a>
      <span class="nav-gap"></span>
      <span class="who">${esc(user.name)} · admin</span>
      <a href="/logout" class="btn btn-ghost btn-sm">Sign out</a>`;
  }

  if (user.role === 'merchant') {
    return `
      <a href="/merchant"${active === 'dash' ? ' class="on"' : ''}>Dashboard</a>
      <a href="/merchant/jobs"${active === 'myjobs' ? ' class="on"' : ''}>My jobs</a>
      <a href="/merchant/review"${active === 'review' ? ' class="on"' : ''}>Review work</a>
      <a href="/wallet"${active === 'wallet' ? ' class="on"' : ''}>Wallet</a>
      <a href="/referrals"${active === 'referrals' ? ' class="on"' : ''}>Refer</a>
      <a href="/support"${active === 'support' ? ' class="on"' : ''}>Support</a>
      <span class="nav-gap"></span>
      <a href="/account"${active === 'account' ? ' class="on"' : ''} class="who-link">${esc(user.name)}</a>
      <a href="/merchant/jobs/new" class="btn btn-sm">Post a job</a>
      <a href="/logout" class="btn btn-ghost btn-sm">Sign out</a>`;
  }

  return `
    <a href="/worker"${active === 'dash' ? ' class="on"' : ''}>Dashboard</a>
    <a href="/jobs"${active === 'jobs' ? ' class="on"' : ''}>Find work</a>
    <a href="/worker/tasks"${active === 'tasks' ? ' class="on"' : ''}>My tasks</a>
    <a href="/wallet"${active === 'wallet' ? ' class="on"' : ''}>Wallet</a>
    <a href="/referrals"${active === 'referrals' ? ' class="on"' : ''}>Refer</a>
    <a href="/support"${active === 'support' ? ' class="on"' : ''}>Support</a>
    <span class="nav-gap"></span>
    <a href="/account" class="who-link">${esc(user.name)}</a>
    <a href="/logout" class="btn btn-ghost btn-sm">Sign out</a>`;
}

function layout({ title, user, active, body, flash, wide, notices, csrf }) {
  const bal = user ? money.balance(user.id) : 0;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} | ${SITE}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@500;600;700&family=Figtree:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap">
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>

<header class="top">
  <div class="wrap top-inner">
    <a href="/" class="brand">
      ${logoMark()}
      <span class="brand-name">Remote Work <b>BD</b></span>
    </a>
    <nav class="nav">${nav(user, active)}</nav>
  </div>
</header>

${user && user.status === 'suspended' ? `
<div class="wrap"><div class="alert alert-stop">
  <b>Your account is suspended.</b>
  ${esc(user.suspend_reason || '')}${user.suspended_until
    ? ` It lifts on ${esc(user.suspended_until.slice(0, 10))} (UTC).` : ''}
  You can sign in and see your history, but you cannot take or post work.
</div></div>` : ''}

${flash ? `<div class="wrap"><div class="alert alert-${flash.kind || 'info'}">${esc(flash.text)}</div></div>` : ''}

${(notices || []).map(n => `<div class="wrap"><div class="alert alert-warn notice">
  <div><b>${esc(n.title)}</b><div class="notice-body">${br(n.body)}</div>
    <a class="link" href="/support">Message support</a></div>
  <form method="post" action="/notices/${n.id}/seen">
    ${csrf ? `<input type="hidden" name="_csrf" value="${esc(csrf)}">` : ''}
    <button class="btn btn-ghost btn-sm" type="submit">Got it</button>
  </form>
</div></div>`).join('')}

<main class="wrap${wide ? ' wrap-wide' : ''}">
${body}
</main>

<footer class="foot">
  <div class="wrap foot-inner">
    <span>&copy; ${new Date().getFullYear()} ${SITE}</span>
    <span class="foot-links">
      <a href="/about">About</a>
      <a href="/how-it-works">How it works</a>
      <a href="/activity">Live activity</a>
      <a href="/payments">Payment proof</a>
      <a href="/rules">Rules</a>
      <a href="/faq">Questions</a>
      <a href="/security">Security</a>
      <a href="/terms">Terms</a>
      <a href="/privacy-policy">Privacy</a>
      <a href="/refunds">Refunds</a>
      <a href="/contact">Contact</a>
    </span>
  </div>
</footer>

${user ? `<div class="balance-chip"><span>Balance</span><b>${esc(money.fmt(bal))}</b></div>` : ''}
<script src="/assets/app.js" defer></script>
</body>
</html>`;
}

// ------------------------------------------------------------------ pieces
function statusPill(status) {
  const label = { started: 'in progress', submitted: 'waiting review' }[status] || status;
  return `<span class="pill s-${esc(status)}">${esc(label)}</span>`;
}

function card(inner, cls) {
  return `<div class="card${cls ? ' ' + cls : ''}">${inner}</div>`;
}

function field({ label, name, type = 'text', value = '', hint, required, placeholder, rows, options, min, step }) {
  const id = 'f-' + name;
  let control;
  if (type === 'textarea') {
    control = `<textarea id="${id}" name="${esc(name)}" rows="${rows || 4}"${required ? ' required' : ''}
       placeholder="${esc(placeholder || '')}">${esc(value)}</textarea>`;
  } else if (type === 'select') {
    control = `<select id="${id}" name="${esc(name)}"${required ? ' required' : ''}>` +
      options.map(o => `<option value="${esc(o.value)}"${String(o.value) === String(value) ? ' selected' : ''}>${esc(o.label)}</option>`).join('') +
      `</select>`;
  } else {
    control = `<input id="${id}" type="${esc(type)}" name="${esc(name)}" value="${esc(value)}"
       ${required ? 'required' : ''} ${placeholder ? `placeholder="${esc(placeholder)}"` : ''}
       ${min != null ? `min="${esc(min)}"` : ''} ${step ? `step="${esc(step)}"` : ''}>`;
  }
  return `<div class="field">
    <label for="${id}">${esc(label)}</label>
    ${control}
    ${hint ? `<span class="hint">${esc(hint)}</span>` : ''}
  </div>`;
}

function money_(units) { return esc(money.fmt(units)); }

function ago(iso) {
  if (!iso) return '';
  const then = new Date(iso.replace(' ', 'T') + 'Z').getTime();
  const d = Math.max(0, Date.now() - then) / 1000;
  if (d < 60) return Math.floor(d) + 's ago';
  if (d < 3600) return Math.floor(d / 60) + 'm ago';
  if (d < 86400) return Math.floor(d / 3600) + 'h ago';
  return Math.floor(d / 86400) + 'd ago';
}

function mmss(seconds) {
  if (seconds == null) return '--';
  const m = Math.floor(seconds / 60), s = seconds % 60;
  return `${m}m ${String(s).padStart(2, '0')}s`;
}

module.exports = { esc, br, layout, card, field, statusPill, money: money_, ago, mmss, SITE };
