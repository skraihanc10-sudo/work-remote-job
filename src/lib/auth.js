/* Accounts, sessions, and the device history behind them.

   There are no passwords. Sign-in is Google only, so identity is a Google
   account id and there is no credential here to steal, guess or reset.

   Sessions are random tokens in the database rather than signed cookies, so
   signing somebody out actually signs them out.
*/

const crypto = require('crypto');
const { db, getSetting, numSetting, audit } = require('./db');
const antispam = require('./antispam');

const SESSION_DAYS = 30;

// -------------------------------------------------------------------- roles
// Admins are named by email in ADMIN_EMAILS, so an admin is made by
// configuration rather than by anything a visitor can do.
function adminEmails() {
  return String(process.env.ADMIN_EMAILS || getSetting('admin_emails', ''))
    .split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
}

function isAdminEmail(email) {
  return adminEmails().includes(String(email || '').toLowerCase());
}

// ----------------------------------------------------------------- sign-in
/* Find or create the account behind a Google profile.
   Returns { user, created }. */
function signInWithGoogle(profile, ip) {
  let user = db.prepare('SELECT * FROM users WHERE google_sub = ?').get(profile.sub);

  // Someone whose account predates Google sign-in, matched by email once.
  if (!user) {
    const byEmail = db.prepare('SELECT * FROM users WHERE lower(email) = ?').get(profile.email);
    if (byEmail) {
      db.prepare('UPDATE users SET google_sub = ?, avatar = ?, email_verified = 1 WHERE id = ?')
        .run(profile.sub, profile.picture, byEmail.id);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(byEmail.id);
    }
  }

  let created = false;
  if (!user) {
    const role = isAdminEmail(profile.email) ? 'admin' : null;   // null = they choose next
    const info = db.prepare(`
      INSERT INTO users (role, name, email, password_hash, google_sub, avatar,
                         email_verified, signup_ip, last_ip)
      VALUES (?, ?, ?, '', ?, ?, 1, ?, ?)
    `).run(role || 'worker', profile.name, profile.email, profile.sub, profile.picture, ip, ip);
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(info.lastInsertRowid));
    created = true;
    audit(user.id, 'account_created', `user:${user.id}`, { via: 'google' }, ip);
  } else {
    // Keep the name and picture current, and promote if the email was added to
    // ADMIN_EMAILS after the account existed.
    const role = isAdminEmail(profile.email) && user.role !== 'admin' ? 'admin' : user.role;
    db.prepare('UPDATE users SET name = ?, avatar = ?, email_verified = 1, role = ? WHERE id = ?')
      .run(profile.name, profile.picture, role, user.id);
    user.role = role;
  }

  if (user.status === 'banned') throw new Error('This account has been closed.');
  return { user, created };
}

// --------------------------------------------------------------- sessions
function startSession(userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000)
    .toISOString().slice(0, 19).replace('T', ' ');
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .run(token, userId, expires);
  return { token, maxAge: SESSION_DAYS * 86400 };
}

function endSession(token) {
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

function userFor(token) {
  if (!token) return null;
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const row = db.prepare(`
    SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token = ? AND s.expires_at > ?
  `).get(token, now);
  if (!row) return null;
  return antispam.liftIfExpired(row);
}

function sweepSessions() {
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now);
}

// ------------------------------------------------------------ ip history
/* Record the sign-in and, if this connection now has several accounts on it,
   tell everybody on it once.

   Deliberately a notice and not a block. On mobile networks here thousands of
   people share one address, and a whole family shares one wifi. Treating that
   as fraud would punish the honest majority to catch a few. What it does do is
   make the pattern visible - to the people involved, so they can explain
   themselves before it becomes a problem, and to an admin looking at a report.
*/
function recordLogin(userId, ip, userAgent) {
  db.prepare('INSERT INTO logins (user_id, ip, user_agent) VALUES (?, ?, ?)')
    .run(userId, ip || null, String(userAgent || '').slice(0, 300));
  db.prepare("UPDATE users SET last_ip = ?, last_seen_at = datetime('now') WHERE id = ?")
    .run(ip || null, userId);

  if (!ip) return null;
  const limit = numSetting('ip_accounts_warn');

  const peers = db.prepare(`
    SELECT DISTINCT u.id, u.name, u.ip_notice_at
    FROM logins l JOIN users u ON u.id = l.user_id
    WHERE l.ip = ? AND u.role != 'admin'
  `).all(ip);

  if (peers.length < limit) return null;

  // Told once per account, not on every sign-in.
  const insert = db.prepare(`
    INSERT INTO notices (user_id, kind, title, body) VALUES (?, 'ip_shared', ?, ?)
  `);
  const title = `${peers.length} accounts have signed in from your connection`;
  const body = `Our security check has seen ${peers.length} different accounts signing in from the same internet connection as yours.

This is often completely innocent - a shared wifi, a family, an office, or a mobile network that gives thousands of people the same address. Nothing has been restricted and you do not need to do anything.

We are telling you because multiple accounts run by one person is against the rules, and if that ever comes up we would rather you had already explained the situation. If this is a shared connection, message support and it will be noted on your account.`;

  let notified = 0;
  for (const peer of peers) {
    if (peer.ip_notice_at) continue;
    insert.run(peer.id, title, body);
    db.prepare("UPDATE users SET ip_notice_at = datetime('now') WHERE id = ?").run(peer.id);
    notified++;
  }
  if (notified) {
    audit(null, 'ip_notice', `ip:${ip}`, { accounts: peers.length, notified }, ip);
  }
  return { ip, accounts: peers.length, notified };
}

function accountsOnIp(ip) {
  if (!ip) return [];
  return db.prepare(`
    SELECT u.id, u.name, u.email, u.role, u.status, u.created_at,
           COUNT(l.id) AS logins, MAX(l.created_at) AS last_login
    FROM logins l JOIN users u ON u.id = l.user_id
    WHERE l.ip = ? GROUP BY u.id ORDER BY last_login DESC
  `).all(ip);
}

/* Connections with more than one account on them, newest first. What an admin
   actually wants to look at. */
function sharedIps(minAccounts) {
  return db.prepare(`
    SELECT l.ip, COUNT(DISTINCT l.user_id) AS accounts,
           MAX(l.created_at) AS last_seen
    FROM logins l JOIN users u ON u.id = l.user_id
    WHERE l.ip IS NOT NULL AND u.role != 'admin'
    GROUP BY l.ip HAVING accounts >= ?
    ORDER BY accounts DESC, last_seen DESC LIMIT 100
  `).all(minAccounts || 2);
}

// ------------------------------------------------------------------ notices
function unseenNotices(userId) {
  return db.prepare('SELECT * FROM notices WHERE user_id = ? AND seen_at IS NULL ORDER BY id DESC')
    .all(userId);
}

function markNoticeSeen(id, userId) {
  db.prepare("UPDATE notices SET seen_at = datetime('now') WHERE id = ? AND user_id = ?")
    .run(id, userId);
}

module.exports = {
  isAdminEmail, adminEmails, signInWithGoogle,
  startSession, endSession, userFor, sweepSessions,
  recordLogin, accountsOnIp, sharedIps,
  unseenNotices, markNoticeSeen,
};
