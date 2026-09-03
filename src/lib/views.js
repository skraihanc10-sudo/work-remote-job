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

const SITE = 'Work Remote Job';

function nav(user, active) {
  if (!user) {
    return `
      <a href="/jobs"${active === 'jobs' ? ' class="on"' : ''}>Browse jobs</a>
      <a href="/how-it-works"${active === 'how' ? ' class="on"' : ''}>How it works</a>
      <span class="nav-gap"></span>
      <a href="/login" class="btn btn-ghost btn-sm">Sign in</a>
      <a href="/register" class="btn btn-sm">Create account</a>`;
  }

  if (user.role === 'admin') {
    return `
      <a href="/admin"${active === 'admin' ? ' class="on"' : ''}>Overview</a>
      <a href="/admin/reports"${active === 'reports' ? ' class="on"' : ''}>Reports</a>
      <a href="/admin/money"${active === 'money' ? ' class="on"' : ''}>Money</a>
      <a href="/admin/users"${active === 'users' ? ' class="on"' : ''}>Users</a>
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
      <span class="nav-gap"></span>
      <a href="/merchant/jobs/new" class="btn btn-sm">Post a job</a>
      <a href="/logout" class="btn btn-ghost btn-sm">Sign out</a>`;
  }

  return `
    <a href="/worker"${active === 'dash' ? ' class="on"' : ''}>Dashboard</a>
    <a href="/jobs"${active === 'jobs' ? ' class="on"' : ''}>Find work</a>
    <a href="/worker/tasks"${active === 'tasks' ? ' class="on"' : ''}>My tasks</a>
    <a href="/wallet"${active === 'wallet' ? ' class="on"' : ''}>Wallet</a>
    <span class="nav-gap"></span>
    <span class="who">${esc(user.name)}</span>
    <a href="/logout" class="btn btn-ghost btn-sm">Sign out</a>`;
}

function layout({ title, user, active, body, flash, wide }) {
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
      <span class="brand-mark">WR</span>
      <span class="brand-name">Work Remote <b>Job</b></span>
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

<main class="wrap${wide ? ' wrap-wide' : ''}">
${body}
</main>

<footer class="foot">
  <div class="wrap foot-inner">
    <span>&copy; ${new Date().getFullYear()} ${SITE}</span>
    <span class="foot-links">
      <a href="/how-it-works">How it works</a>
      <a href="/rules">Rules</a>
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

module.exports = { esc, layout, card, field, statusPill, money: money_, ago, mmss, SITE };
