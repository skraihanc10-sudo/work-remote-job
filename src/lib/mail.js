/* ---------------------------------------------------------------------------
   Outgoing mail: what we send, and when.

   Two rules shape the whole file.

   The first is that mail is queued, never sent inline. A message is written
   into mail_outbox inside the same transaction as the thing it is about, and
   a sweep delivers it afterwards. A mail server that is slow, rate-limiting
   or simply down must never roll back a payment, and a payment that committed
   must never lose its receipt. Sending inside the request would trade one for
   the other, and both trades are bad.

   The second is that queueing never throws. Every call site is in the middle
   of something that matters more than the email - approving work, crediting a
   deposit, creating an account. If the mail cannot even be written down, that
   is logged and the important thing carries on.

   Mail is off until it is configured. A site that silently fails to send is
   worse than one that says plainly that it cannot.
   --------------------------------------------------------------------------- */

const crypto = require('crypto');
const { db, getSetting, audit } = require('./db');
const smtp = require('./smtp');

// Environment wins over the settings table: a deployment secret belongs in the
// environment, and it means the admin screen cannot lock anybody out of their
// own mail by saving a blank field.
function pick(envName, settingKey) {
  const fromEnv = process.env[envName];
  if (fromEnv !== undefined && String(fromEnv).trim() !== '') return String(fromEnv).trim();
  return String(getSetting(settingKey, '') || '').trim();
}

function config() {
  const host = pick('SMTP_HOST', 'smtp_host');
  const port = Number(pick('SMTP_PORT', 'smtp_port')) || 587;
  const from = pick('MAIL_FROM', 'mail_from');
  return {
    host, port,
    user: pick('SMTP_USER', 'smtp_user'),
    pass: pick('SMTP_PASS', 'smtp_pass'),
    from,
    fromName: pick('MAIL_FROM_NAME', 'mail_from_name') || 'Remote Work BD',
    secure: port === 465,
    // Configured means: somewhere to send it, and an address to send it from.
    // The switch alone is not enough, and neither is half the connection.
    enabled: getSetting('mail_enabled', '0') === '1' && !!host && !!from,
  };
}

function enabled() {
  return config().enabled;
}

function siteUrl() {
  return String(process.env.PUBLIC_URL || 'https://remoteworkbd.site').replace(/\/$/, '');
}

// --------------------------------------------------------------- unsubscribe
/* A token that proves the holder owns this address, without a database row.
   Signed with the same secret as everything else, so a guessed link does
   nothing. */
function unsubToken(userId) {
  const secret = process.env.CSRF_SECRET || 'dev-secret-change-me';
  const sig = crypto.createHmac('sha256', secret).update('unsub:' + userId).digest('base64url');
  return `${userId}.${sig}`;
}

function checkUnsubToken(token) {
  const [rawId, sig] = String(token || '').split('.');
  const id = Number(rawId);
  if (!id || !sig) return null;
  const expected = unsubToken(id).split('.')[1];
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return id;
}

// -------------------------------------------------------------------- layout
const esc = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');

/* One layout for every message.

   Tables and inline styles, because mail clients are twenty years behind
   browsers and a flexbox layout collapses into a heap in Outlook. Kept
   deliberately plain: a receipt that looks like an advert gets treated like
   one, both by the reader and by the spam filter.
*/
function render({ heading, intro, rows, lines, button, foot, unsub }) {
  const site = siteUrl();
  const navy = '#1B2A57';
  const green = '#1F9D4D';

  const rowsHtml = (rows || []).map(([k, v]) => `
    <tr>
      <td style="padding:6px 0;color:#6C757E;font-size:14px;">${esc(k)}</td>
      <td style="padding:6px 0;color:#14181C;font-size:14px;font-weight:600;text-align:right;">${esc(v)}</td>
    </tr>`).join('');

  const linesHtml = (lines || []).map(l =>
    `<p style="margin:0 0 12px;color:#3D454D;font-size:15px;line-height:1.6;">${esc(l)}</p>`
  ).join('');

  const html = `<!doctype html>
<html><body style="margin:0;padding:0;background:#F0F2F1;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F0F2F1;padding:24px 12px;">
<tr><td align="center">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#FFFFFF;border-radius:10px;overflow:hidden;font-family:Helvetica,Arial,sans-serif;">
    <tr><td style="background:${navy};padding:18px 24px;">
      <span style="color:#FFFFFF;font-size:17px;font-weight:700;">Remote Work BD</span>
    </td></tr>
    <tr><td style="padding:26px 24px 8px;">
      <h1 style="margin:0 0 14px;color:#14181C;font-size:21px;line-height:1.3;">${esc(heading)}</h1>
      ${intro ? `<p style="margin:0 0 16px;color:#3D454D;font-size:15px;line-height:1.6;">${esc(intro)}</p>` : ''}
      ${linesHtml}
      ${rowsHtml ? `<table role="presentation" width="100%" cellpadding="0" cellspacing="0"
         style="margin:18px 0;border-top:1px solid #E1E5E4;border-bottom:1px solid #E1E5E4;">${rowsHtml}</table>` : ''}
      ${button ? `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:20px 0 6px;">
        <tr><td style="background:${green};border-radius:8px;">
          <a href="${esc(button.href)}" style="display:inline-block;padding:12px 22px;color:#FFFFFF;
             font-size:15px;font-weight:600;text-decoration:none;">${esc(button.label)}</a>
        </td></tr></table>
        <p style="margin:10px 0 0;color:#6C757E;font-size:12.5px;line-height:1.5;word-break:break-all;">
          If the button does not work, copy this link:<br>${esc(button.href)}</p>` : ''}
      ${foot ? `<p style="margin:18px 0 0;color:#6C757E;font-size:13px;line-height:1.6;">${esc(foot)}</p>` : ''}
    </td></tr>
    <tr><td style="padding:18px 24px 24px;border-top:1px solid #E1E5E4;">
      <p style="margin:0;color:#6C757E;font-size:12px;line-height:1.6;">
        Remote Work BD &middot; <a href="${site}" style="color:${navy};">${esc(site.replace(/^https?:\/\//, ''))}</a><br>
        ${unsub ? `You are receiving this because you have an account with us.
          <a href="${esc(unsub)}" style="color:#6C757E;">Stop these updates</a>.`
        : 'This is a service message about your account, so it is sent whatever your settings.'}
      </p>
    </td></tr>
  </table>
</td></tr></table>
</body></html>`;

  const text = [
    heading, '',
    intro || '',
    ...(lines || []),
    '',
    ...(rows || []).map(([k, v]) => `${k}: ${v}`),
    button ? `\n${button.label}: ${button.href}` : '',
    foot ? `\n${foot}` : '',
    `\n---\nRemote Work BD - ${site}`,
    unsub ? `Stop these updates: ${unsub}` : '',
  ].filter(l => l !== '').join('\n');

  return { html, text };
}

// --------------------------------------------------------------------- queue
/* Messages that are part of the service - a receipt, a password reset, a
   security notice - go out whatever the person's preference. Only news and
   announcements are optional. Someone who turned off "updates" still has to
   be told their money moved. */
const ESSENTIAL = new Set([
  'verify', 'reset', 'password_changed', 'deposit', 'withdrawal', 'suspended', 'security',
]);

function queue({ userId, to, subject, kind, ...content }) {
  try {
    const cfg = config();
    let email = to;
    let unsubUrl = null;

    if (userId && !email) {
      const u = db.prepare('SELECT email, email_opt_out FROM users WHERE id = ?').get(userId);
      if (!u || !u.email) return null;
      if (u.email_opt_out && !ESSENTIAL.has(kind)) return null;
      email = u.email;
    }
    if (!email) return null;
    if (userId && !ESSENTIAL.has(kind)) {
      unsubUrl = `${siteUrl()}/unsubscribe?t=${unsubToken(userId)}`;
    }

    const { html, text } = render({ ...content, unsub: unsubUrl });
    const info = db.prepare(`
      INSERT INTO mail_outbox (user_id, to_email, subject, body, kind, status)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(userId || null, email, subject,
      JSON.stringify({ html, text, unsub: unsubUrl }), kind,
      // Written down even when mail is switched off, so that turning it on
      // does not silently lose the backlog - and so an admin can see what
      // would have gone out.
      cfg.enabled ? 'queued' : 'held');
    return Number(info.lastInsertRowid);
  } catch (err) {
    // Never let a mail problem break the thing the mail was about.
    console.error('could not queue mail:', err.message);
    return null;
  }
}

/* Send what is waiting.

   One at a time and capped per sweep: most SMTP providers rate limit, and a
   burst of a thousand on a broadcast gets an account suspended faster than
   any content ever would.
*/
const MAX_ATTEMPTS = 5;

async function flush(limit = 20) {
  const cfg = config();
  if (!cfg.enabled) return { sent: 0, failed: 0, skipped: 'mail is not configured' };

  // Anything held while mail was off becomes sendable once it is on.
  db.prepare("UPDATE mail_outbox SET status = 'queued' WHERE status = 'held'").run();

  const rows = db.prepare(
    "SELECT * FROM mail_outbox WHERE status = 'queued' AND attempts < ? ORDER BY id LIMIT ?"
  ).all(MAX_ATTEMPTS, limit);

  let sent = 0, failed = 0;
  for (const row of rows) {
    let content;
    try { content = JSON.parse(row.body); }
    catch {
      db.prepare("UPDATE mail_outbox SET status = 'failed', last_error = ? WHERE id = ?")
        .run('The stored message was unreadable.', row.id);
      failed++;
      continue;
    }

    try {
      await smtp.send(cfg, {
        from: cfg.from, fromName: cfg.fromName,
        to: row.to_email,
        subject: row.subject,
        text: content.text, html: content.html,
        replyTo: getSetting('business_email', '') || undefined,
        listUnsubscribe: content.unsub || undefined,
      });
      db.prepare("UPDATE mail_outbox SET status = 'sent', sent_at = datetime('now'), attempts = attempts + 1 WHERE id = ?")
        .run(row.id);
      sent++;
    } catch (err) {
      const attempts = row.attempts + 1;
      // Give up only after several tries: most failures are a moment of
      // rate limiting, not a wrong address.
      const status = attempts >= MAX_ATTEMPTS ? 'failed' : 'queued';
      db.prepare('UPDATE mail_outbox SET attempts = ?, last_error = ?, status = ? WHERE id = ?')
        .run(attempts, String(err.message).slice(0, 300), status, row.id);
      failed++;
      // A whole sweep failing the same way is one problem, not twenty. Stop
      // and let the next sweep try again.
      if (/Signing in|does not offer STARTTLS|Could not reach|ECONNREFUSED/.test(err.message)) break;
    }
  }
  return { sent, failed };
}

// ------------------------------------------------------------------ messages
const money = () => require('./money');

function welcome(user) {
  return queue({
    userId: user.id, kind: 'welcome',
    subject: 'Welcome to Remote Work BD',
    heading: `Welcome, ${user.name}`,
    intro: 'Your account is ready.',
    lines: [
      user.role === 'merchant'
        ? 'You can post a job, fund it, and workers will start on it straight away. The money sits in escrow until you approve the work, so nobody is asked to trust anybody.'
        : 'Find a task, read the instructions carefully, do it properly, and send your proof. Every job is funded before it goes live, so the money for your work is already set aside.',
      'One rule worth knowing now: each job can be done once per person. Doing the same job twice, or running several accounts, is what gets accounts suspended.',
    ],
    button: { label: user.role === 'merchant' ? 'Post your first job' : 'Find work', href: `${siteUrl()}/${user.role === 'merchant' ? 'merchant/jobs/new' : 'jobs'}` },
  });
}

function verifyEmail(user, token) {
  return queue({
    userId: user.id, kind: 'verify',
    subject: 'Confirm your email address',
    heading: 'Confirm your email address',
    intro: `Hello ${user.name}, please confirm this is your address.`,
    lines: ['Until you do, you can look around but you cannot take work or withdraw. It takes one click.'],
    button: { label: 'Confirm my email', href: `${siteUrl()}/verify?t=${token}` },
    foot: 'This link works once and expires in 24 hours. If you did not create this account, ignore this message and nothing will happen.',
  });
}

function resetPassword(user, token) {
  return queue({
    userId: user.id, kind: 'reset',
    subject: 'Reset your password',
    heading: 'Reset your password',
    intro: `Someone asked to reset the password for ${user.email}.`,
    button: { label: 'Choose a new password', href: `${siteUrl()}/reset?t=${token}` },
    foot: 'This link works once and expires in one hour. If it was not you, ignore this message - your password has not changed and nobody can use this link without your inbox.',
  });
}

function passwordChanged(user) {
  return queue({
    userId: user.id, kind: 'password_changed',
    subject: 'Your password was changed',
    heading: 'Your password was changed',
    intro: 'This is a security notice, sent whenever the password on an account changes.',
    lines: ['If this was you, there is nothing to do.',
      'If it was not, contact support immediately - somebody else may have access to your account.'],
    button: { label: 'Contact support', href: `${siteUrl()}/support` },
  });
}

function taskSubmitted(sub, job, worker) {
  if (getSetting('mail_on_task_submitted', '1') !== '1') return null;
  return queue({
    userId: job.merchant_id, kind: 'task_submitted',
    subject: `New work to review: ${job.title}`,
    heading: 'Someone finished your task',
    intro: `${worker.name} sent proof for "${job.title}".`,
    rows: [['Job', job.title], ['Worker', worker.name], ['Pays', money().fmt(job.rate)],
      ['You have', `${job.ttr_days || 7} days to review it`]],
    lines: ['If the deadline passes without a decision, it is approved and paid automatically. That is the deal you agreed when you set the review window.'],
    button: { label: 'Review it now', href: `${siteUrl()}/merchant/review` },
  });
}

function taskApproved(sub, job, net, auto) {
  if (getSetting('mail_on_task_decided', '1') !== '1') return null;
  return queue({
    userId: sub.worker_id, kind: 'task_approved',
    subject: auto ? 'Your task was approved automatically' : 'Your task was approved',
    heading: auto ? 'Approved automatically - and paid' : 'Your work was approved',
    intro: auto
      ? `The buyer had ${job.ttr_days || 7} days to review "${job.title}" and did not, so it was approved and paid.`
      : `The buyer approved your work on "${job.title}".`,
    rows: [['Job', job.title], ['Added to your balance', money().fmt(net)]],
    lines: auto
      ? ['This is how the review deadline works. You are never left waiting on a buyer indefinitely.']
      : [],
    button: { label: 'See your wallet', href: `${siteUrl()}/wallet` },
  });
}

function taskRejected(sub, job, reason) {
  if (getSetting('mail_on_task_decided', '1') !== '1') return null;
  return queue({
    userId: sub.worker_id, kind: 'task_rejected',
    subject: `Your work on "${job.title}" was not accepted`,
    heading: 'Your work was not accepted',
    intro: `The buyer rejected your submission for "${job.title}".`,
    rows: reason ? [['Their reason', reason]] : [],
    lines: [
      'If you believe this was unfair, you can report it and an admin will look at your proof themselves.',
      'Rejecting good work to avoid paying for it is against the rules, and buyers who do it are dealt with.',
    ],
    button: { label: 'Open the task', href: `${siteUrl()}/task/${sub.id}` },
  });
}

function depositCredited(userId, amount, method) {
  if (getSetting('mail_on_deposit', '1') !== '1') return null;
  return queue({
    userId, kind: 'deposit',
    subject: `${money().fmt(amount)} added to your balance`,
    heading: 'Your deposit arrived',
    rows: [['Amount', money().fmt(amount)], ['Method', method || 'Payment gateway']],
    lines: ['It is in your balance now and ready to fund a job.'],
    button: { label: 'See your wallet', href: `${siteUrl()}/wallet` },
  });
}

function withdrawalSettled(userId, amount, ok, note) {
  if (getSetting('mail_on_withdrawal', '1') !== '1') return null;
  return queue({
    userId, kind: 'withdrawal',
    subject: ok ? `${money().fmt(amount)} sent` : 'Your withdrawal could not be sent',
    heading: ok ? 'Your withdrawal has been sent' : 'Your withdrawal could not be sent',
    rows: [['Amount', money().fmt(amount)]].concat(note ? [['Note', note]] : []),
    lines: ok
      ? ['It is on its way by the payout method on your account.']
      : ['The money has been returned to your balance, so nothing is lost. Check your payout details and try again.'],
    button: { label: 'See your wallet', href: `${siteUrl()}/wallet` },
  });
}

function accountSuspended(userId, reason, until) {
  return queue({
    userId, kind: 'suspended',
    subject: 'Your account has been suspended',
    heading: 'Your account has been suspended',
    rows: [['Reason', reason || 'Rule violation']].concat(until ? [['Until', until]] : []),
    lines: ['If you think this is a mistake, reply to support and an admin will look at it properly.'],
    button: { label: 'Contact support', href: `${siteUrl()}/support` },
  });
}

/* An announcement to everybody.

   Queued for each person individually rather than one mail with everyone in
   the recipients: a shared To line would publish the whole user list to every
   reader, and a single failure would lose the lot.
*/
function broadcast({ subject, heading, body, adminId, audience = 'all' }) {
  const where = audience === 'workers' ? "AND role = 'worker'"
    : audience === 'merchants' ? "AND role = 'merchant'" : '';
  const users = db.prepare(`
    SELECT id, name, email FROM users
    WHERE email IS NOT NULL AND email != '' AND email_opt_out = 0
      AND status != 'banned' AND role != 'admin' ${where}
  `).all();

  let queued = 0;
  const lines = String(body || '').split(/\n{2,}/).map(s => s.trim()).filter(Boolean);
  for (const u of users) {
    const id = queue({
      userId: u.id, kind: 'announcement', subject,
      heading: heading || subject,
      lines,
      button: { label: 'Open Remote Work BD', href: siteUrl() },
    });
    if (id) queued++;
  }
  audit(adminId, 'broadcast', null, { subject, audience, queued });
  return queued;
}

module.exports = {
  config, enabled, flush, queue, render, siteUrl,
  unsubToken, checkUnsubToken,
  welcome, verifyEmail, resetPassword, passwordChanged,
  taskSubmitted, taskApproved, taskRejected,
  depositCredited, withdrawalSettled, accountSuspended,
  broadcast,
};
