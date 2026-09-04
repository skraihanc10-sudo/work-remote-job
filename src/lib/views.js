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

/* Stylesheet and script are cached for an hour, so without a version in the
   URL a deploy leaves people on the old CSS until it expires - which looks
   exactly like a broken site. The number is the file's own modification time,
   so it changes when the file does and not otherwise. */
function assetVersion(file) {
  try {
    return String(Math.floor(fs.statSync(path.join(__dirname, '..', 'web', 'assets', file)).mtimeMs));
  } catch (err) {
    return '0';
  }
}
const CSS_V = assetVersion('app.css');
const JS_V = assetVersion('app.js');

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

/* One list of destinations, rendered three ways: the desktop bar, the phone
   drawer, and the bottom tab bar. Keeping them from one source is the only way
   they stay in step - three hand-written copies drift the first time a link is
   added and then the phone quietly loses a page.

   `tab` marks the handful that earn a place in the bottom bar. On a phone most
   people are here to do one of four things, and those four should be one thumb
   away rather than behind a menu.
*/
function navItems(user) {
  if (!user) {
    return [
      { href: '/jobs', label: 'Browse jobs', key: 'jobs', tab: true, icon: 'search' },
      { href: '/activity', label: 'Live activity', key: 'activity', tab: true, icon: 'pulse' },
      { href: '/payments', label: 'Payment proof', key: 'payments', tab: true, icon: 'cash' },
      { href: '/how-it-works', label: 'How it works', key: 'how' },
      { href: '/faq', label: 'Questions', key: 'faq' },
      { href: '/login', label: 'Continue with Google', key: 'login', cta: true, tab: true, icon: 'user' },
    ];
  }

  if (user.role === 'admin') {
    return [
      { href: '/admin', label: 'Overview', key: 'admin', tab: true, icon: 'grid' },
      { href: '/admin/users', label: 'Users', key: 'users', tab: true, icon: 'user' },
      { href: '/admin/money', label: 'Money', key: 'money', tab: true, icon: 'cash' },
      { href: '/admin/support', label: 'Support', key: 'support', tab: true, icon: 'chat' },
      { href: '/admin/reports', label: 'Reports', key: 'reports' },
      { href: '/admin/roles', label: 'Roles', key: 'roles' },
      { href: '/admin/connections', label: 'Connections', key: 'connections' },
      { href: '/admin/gateway', label: 'Gateway', key: 'gateway' },
      { href: '/admin/mail', label: 'Email', key: 'mail' },
      { href: '/admin/settings', label: 'Settings', key: 'settings' },
    ];
  }

  if (user.role === 'merchant') {
    return [
      { href: '/merchant', label: 'Dashboard', key: 'dash', tab: true, icon: 'grid' },
      { href: '/merchant/jobs', label: 'My jobs', key: 'myjobs', tab: true, icon: 'list' },
      { href: '/merchant/review', label: 'Review work', key: 'review', tab: true, icon: 'check' },
      { href: '/wallet', label: 'Wallet', key: 'wallet', tab: true, icon: 'cash' },
      { href: '/merchant/jobs/new', label: 'Post a job', key: 'newjob', cta: true, tab: true, icon: 'plus' },
      { href: '/referrals', label: 'Refer a friend', key: 'referrals' },
      { href: '/support', label: 'Support', key: 'support' },
      { href: '/account', label: 'Account', key: 'account' },
    ];
  }

  return [
    { href: '/worker', label: 'Dashboard', key: 'dash', tab: true, icon: 'grid' },
    { href: '/jobs', label: 'Find work', key: 'jobs', tab: true, icon: 'search' },
    { href: '/worker/tasks', label: 'My tasks', key: 'tasks', tab: true, icon: 'list' },
    { href: '/wallet', label: 'Wallet', key: 'wallet', tab: true, icon: 'cash' },
    { href: '/referrals', label: 'Refer', key: 'referrals', tab: true, icon: 'gift' },
    { href: '/support', label: 'Support', key: 'support' },
    { href: '/account', label: 'Account', key: 'account' },
  ];
}

const NAV_ICONS = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13"/><path d="M3.5 6h.01M3.5 12h.01M3.5 18h.01"/>',
  cash: '<rect x="2.5" y="6" width="19" height="12" rx="2"/><circle cx="12" cy="12" r="2.5"/>',
  gift: '<rect x="3" y="8" width="18" height="13" rx="1.5"/><path d="M12 8v13M3 12h18"/><path d="M12 8S10.5 3 8 4.5 10 8 12 8zM12 8s1.5-5 4-3.5S14 8 12 8z"/>',
  chat: '<path d="M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12z"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.5 2.5L16 9.5"/>',
  plus: '<circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/>',
  user: '<circle cx="12" cy="8" r="3.5"/><path d="M4.5 20a7.5 7.5 0 0 1 15 0"/>',
  pulse: '<path d="M2 12h4l3-8 5 16 3-8h5"/>',
};

function navIcon(name) {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
    stroke-linecap="round" stroke-linejoin="round">${NAV_ICONS[name] || NAV_ICONS.grid}</svg>`;
}

function deskNav(user, active) {
  const items = navItems(user);
  const main = items.filter(i => !i.cta);
  const cta = items.filter(i => i.cta);
  return main.map(i =>
      `<a href="${i.href}"${i.key === active ? ' class="on"' : ''}>${esc(i.label)}</a>`).join(String.fromCharCode(10))
    + '<span class="nav-gap"></span>'
    + (user ? `<a href="/account"${active === 'account' ? ' class="on"' : ''} class="who-link">${esc(user.name)}</a>` : '')
    + cta.map(i => `<a href="${i.href}" class="btn btn-sm">${esc(i.label)}</a>`).join('')
    + (user ? '<a href="/logout" class="btn btn-ghost btn-sm">Sign out</a>' : '');
}

function drawer(user, active) {
  const items = navItems(user);
  return `<div class="drawer" id="drawer" hidden>
  <div class="drawer-panel">
    <div class="drawer-top">
      <span>${user ? esc(user.name) : 'Menu'}</span>
      <button type="button" class="drawer-close" id="drawer-close" aria-label="Close menu">&times;</button>
    </div>
    ${user ? `<div class="drawer-balance"><span>Balance</span><b>${esc(money.fmt(money.balance(user.id)))}</b></div>` : ''}
    <nav class="drawer-links">
      ${items.map(i => `<a href="${i.href}"${i.key === active ? ' class="on"' : ''}>${esc(i.label)}</a>`).join('')}
      ${user ? '<a href="/logout" class="danger">Sign out</a>' : ''}
    </nav>
    <div class="drawer-foot">
      <a href="/how-it-works">How it works</a>
      <a href="/faq">Questions</a>
      <a href="/support">Support</a>
    </div>
  </div>
</div>`;
}

function tabbar(user, active) {
  const tabs = navItems(user).filter(i => i.tab).slice(0, 5);
  return `<nav class="tabbar">
    ${tabs.map(i => `<a href="${i.href}"${i.key === active ? ' class="on"' : ''}>
      <span class="tab-ico">${navIcon(i.icon)}</span>
      <span class="tab-label">${esc(i.label)}</span>
    </a>`).join('')}
  </nav>`;
}

function layout({ title, user, active, body, flash, wide, notices, csrf, bare }) {
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
<link rel="stylesheet" href="/assets/app.css?v=${CSS_V}">
</head>
<body>

<header class="top${bare ? ' top-bare' : ''}">
  <div class="wrap top-inner">
    <a href="/" class="brand">
      ${logoMark()}
      <span class="brand-name">Remote Work <b>BD</b></span>
    </a>
    ${bare ? '' : `<nav class="nav">${deskNav(user, active)}</nav>`}
    ${bare ? '' : `<div class="head-mobile">
      ${user ? `<a class="head-bal" href="/wallet">${esc(money.fmt(bal))}</a>` : ''}
      <button type="button" class="burger" id="burger" aria-label="Open menu" aria-expanded="false">
        <span></span><span></span><span></span>
      </button>
    </div>`}
  </div>
</header>

${bare ? '' : drawer(user, active)}

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
  <div class="wrap foot-grid">
    <div class="foot-brand">
      <div class="foot-mark">${logoMark()}<span>Remote Work <b>BD</b></span></div>
      <p>Microjob and freelancing site to make money online. Every job is funded
         before it goes live.</p>
      ${getSetting('business_address', '') ? `<h5>Address</h5>
        <p class="foot-addr">${br(getSetting('business_address', ''))}</p>` : ''}
      ${getSetting('business_email', '') ? `<p class="foot-addr">${esc(getSetting('business_email', ''))}</p>` : ''}
    </div>

    <div class="foot-col">
      <h5>Company</h5>
      <ul>
        <li><a href="/about">About us</a></li>
        <li><a href="/privacy-policy">Privacy policy</a></li>
        <li><a href="/terms">Terms &amp; conditions</a></li>
        <li><a href="/security">Security</a></li>
      </ul>
    </div>

    <div class="foot-col">
      <h5>Services</h5>
      <ul>
        <li><a href="/jobs">Browse jobs</a></li>
        <li><a href="/how-it-works">How it works</a></li>
        <li><a href="/faq">FAQ</a></li>
        <li><a href="/refunds">Refund policy</a></li>
      </ul>
    </div>

    <div class="foot-col">
      <h5>Support</h5>
      <ul>
        <li><a href="/support">Live support</a></li>
        <li><a href="/activity">Live activity</a></li>
        <li><a href="/payments">Payment proof</a></li>
        <li><a href="/contact">Contact us</a></li>
      </ul>
      ${getSetting('telegram_channel', '') || getSetting('telegram_support', '') ? `
      <div class="foot-social">
        ${getSetting('telegram_channel', '') ? `<a href="${esc(getSetting('telegram_channel', ''))}"
          target="_blank" rel="noopener" aria-label="Telegram channel">
          <svg viewBox="0 0 24 24" width="17" height="17" fill="currentColor">
            <path d="M21.9 4.3 18.8 19c-.2 1-.9 1.3-1.7.8l-4.7-3.5-2.3 2.2c-.3.3-.5.5-.9.5l.3-4.7 8.6-7.8c.4-.3-.1-.5-.6-.2L6.9 13 2.3 11.5c-1-.3-1-1 .2-1.5l18-6.9c.8-.3 1.6.2 1.4 1.2z"/></svg></a>` : ''}
        ${getSetting('telegram_support', '') ? `<a href="${esc(getSetting('telegram_support', ''))}"
          target="_blank" rel="noopener" aria-label="Telegram support">
          <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor"
            stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 12a8 8 0 1 1-3.2-6.4"/><path d="M21 4v5h-5"/></svg></a>` : ''}
      </div>` : ''}
    </div>
  </div>

  <div class="foot-bottom">
    <div class="wrap">&copy; ${new Date().getFullYear()} ${SITE}. All rights reserved.</div>
  </div>
</footer>

${user ? `<div class="balance-chip"><span>Balance</span><b>${esc(money.fmt(bal))}</b></div>` : ''}
${tabbar(user, active)}
<script src="/assets/app.js?v=${JS_V}" defer></script>
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
