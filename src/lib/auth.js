/* Accounts, sessions, and the device history behind them.

   There are two ways in: Google, and an email or username with a password.

   Google came first and is still the one we point people at, because it is
   the stronger of the two in exactly the way this site needs. Anybody can
   invent a name and an address; a crowd of Google accounts costs real effort,
   and that effort is what protects the people doing honest work from somebody
   farming a job with twenty identities.

   Passwords give that up, so they are fenced:

     - the address must be confirmed before the account can take work or
       take money out, which puts a real inbox behind every account;
     - failed sign-ins are counted and rate limited, per account and per
       connection, because a password is a secret that can be guessed and a
       Google token is not;
     - the password itself is never stored, only an scrypt hash (see
       passwords.js).

   Sessions are random tokens in the database rather than signed cookies, so
   signing somebody out actually signs them out.
*/

const crypto = require('crypto');
const { db, getSetting, numSetting, audit } = require('./db');
const antispam = require('./antispam');
const passwords = require('./passwords');

const SESSION_DAYS = 30;

// How many failures before a pause, and how long the window is.
const MAX_FAILURES = 8;
const WINDOW_MINUTES = 15;
const TOKEN_HOURS = { verify: 24, reset: 1 };

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

// ------------------------------------------------------- password sign-in
function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

/* Is this address or connection currently being guessed at?

   Counted two ways on purpose. Per identifier stops somebody hammering one
   account; per IP stops them spreading the same attempt thinly across many
   accounts, which is what a list of leaked passwords actually looks like.
*/
function tooManyFailures(identifier, ip) {
  const since = new Date(Date.now() - WINDOW_MINUTES * 60000)
    .toISOString().slice(0, 19).replace('T', ' ');

  const forId = db.prepare(
    'SELECT COUNT(*) AS n FROM login_attempts WHERE identifier = ? AND ok = 0 AND created_at >= ?'
  ).get(String(identifier || '').toLowerCase(), since).n;
  if (forId >= MAX_FAILURES) return true;

  if (ip) {
    const forIp = db.prepare(
      'SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND ok = 0 AND created_at >= ?'
    ).get(ip, since).n;
    // Looser than the per-account limit: a shared connection here can be a
    // whole office, and several people mistyping is not an attack.
    if (forIp >= MAX_FAILURES * 4) return true;
  }
  return false;
}

function recordAttempt(identifier, ip, ok) {
  db.prepare('INSERT INTO login_attempts (identifier, ip, ok) VALUES (?, ?, ?)')
    .run(String(identifier || '').toLowerCase(), ip || null, ok ? 1 : 0);
}

/* Create an account from the sign-up form.

   Throws with a message meant for the person filling in the form. The caller
   is expected to show it as-is.
*/
function signUpWithPassword({ name, email, username, password, country, role, ip }) {
  const cleanEmail = normalizeEmail(email);
  const cleanName = String(name || '').trim().slice(0, 80);
  const cleanUser = String(username || '').trim();

  if (cleanName.length < 2) throw new Error('Please give the name people should see.');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(cleanEmail)) {
    throw new Error('That does not look like an email address.');
  }

  const userProblem = passwords.problemWithUsername(cleanUser);
  if (userProblem) throw new Error(userProblem);

  const pwProblem = passwords.problemWith(password, { name: cleanName, email: cleanEmail, username: cleanUser });
  if (pwProblem) throw new Error(pwProblem);

  // Checked before inserting for a readable message, and again by the unique
  // indexes underneath, which is what actually settles a race between two
  // simultaneous sign-ups.
  if (db.prepare('SELECT id FROM users WHERE lower(email) = ?').get(cleanEmail)) {
    throw new Error('An account already uses that email address. Try signing in instead.');
  }
  if (db.prepare('SELECT id FROM users WHERE lower(username) = ?').get(cleanUser.toLowerCase())) {
    throw new Error('That username is taken. Please pick another.');
  }

  const hash = passwords.hash(password);
  const wanted = role === 'merchant' ? 'merchant' : 'worker';
  // An admin is made by configuration, never by anything a visitor can type.
  const finalRole = isAdminEmail(cleanEmail) ? 'admin' : wanted;

  let info;
  try {
    info = db.prepare(`
      INSERT INTO users (role, name, email, username, password_hash, country,
                         email_verified, signup_ip, last_ip)
      VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
    `).run(finalRole, cleanName, cleanEmail, cleanUser, hash,
      String(country || '').trim() || null, ip || null, ip || null);
  } catch (err) {
    if (/UNIQUE/i.test(err.message)) {
      throw new Error('That email address or username was just taken. Please try another.');
    }
    throw err;
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(info.lastInsertRowid));
  audit(user.id, 'account_created', `user:${user.id}`, { via: 'password' }, ip);
  return user;
}

/* Sign in with an email address or a username.

   The same message comes back whether the account does not exist or the
   password was wrong. Saying which one it was tells an attacker for free
   which addresses are worth attacking.
*/
function signInWithPassword({ identifier, password, ip }) {
  const id = String(identifier || '').trim();
  if (!id || !password) throw new Error('Please fill in both fields.');

  if (tooManyFailures(id, ip)) {
    throw new Error(
      `Too many failed attempts. Wait ${WINDOW_MINUTES} minutes and try again, ` +
      'or reset your password if you have forgotten it.');
  }

  const user = id.includes('@')
    ? db.prepare('SELECT * FROM users WHERE lower(email) = ?').get(normalizeEmail(id))
    : db.prepare('SELECT * FROM users WHERE lower(username) = ?').get(id.toLowerCase());

  const wrong = 'That email, username or password is not right.';

  if (!user || !user.password_hash) {
    // Spend roughly the same time as a real check would, so that a missing
    // account cannot be told apart from a wrong password by how fast the
    // answer comes back.
    passwords.verify(password, passwords.hash('timing equaliser'));
    recordAttempt(id, ip, false);
    if (user && !user.password_hash) {
      throw new Error('This account signs in with Google. Use the Google button above.');
    }
    throw new Error(wrong);
  }

  if (!passwords.verify(password, user.password_hash)) {
    recordAttempt(id, ip, false);
    throw new Error(wrong);
  }

  if (user.status === 'banned') throw new Error('This account has been closed.');

  // The only moment the plaintext exists, so it is the only moment the stored
  // hash can be brought up to the current cost.
  if (passwords.needsUpgrade(user.password_hash)) {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
      .run(passwords.hash(password), user.id);
  }

  recordAttempt(id, ip, true);
  return user;
}

function setPassword(userId, password, user) {
  const problem = passwords.problemWith(password, user || {});
  if (problem) throw new Error(problem);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
    .run(passwords.hash(password), userId);
  // Everything else signed in as them is now signed out. A password change is
  // most often a response to someone else having access.
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
  audit(userId, 'password_set', `user:${userId}`);
}

// -------------------------------------------------------- one-time links
/* Only the hash of the token is stored. A reset token is a password for as
   long as it lives, so the table must not hold anything usable. */
function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function issueToken(userId, kind) {
  const token = crypto.randomBytes(32).toString('base64url');
  const hours = TOKEN_HOURS[kind] || 1;
  const expires = new Date(Date.now() + hours * 3600000)
    .toISOString().slice(0, 19).replace('T', ' ');

  // Older links of the same kind stop working the moment a new one is asked
  // for, so a forwarded or intercepted email goes stale.
  db.prepare("UPDATE email_tokens SET used_at = datetime('now') WHERE user_id = ? AND kind = ? AND used_at IS NULL")
    .run(userId, kind);
  db.prepare('INSERT INTO email_tokens (user_id, kind, token_hash, expires_at) VALUES (?, ?, ?, ?)')
    .run(userId, kind, hashToken(token), expires);
  return token;
}

/* Spend a token, returning the user it belonged to or null.

   The update is what claims it, and it only matches a row that is still
   unused - so two clicks on the same link, or two tabs racing, can only
   succeed once.
*/
function useToken(token, kind) {
  if (!token) return null;
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const row = db.prepare(
    'SELECT * FROM email_tokens WHERE token_hash = ? AND kind = ? AND used_at IS NULL AND expires_at > ?'
  ).get(hashToken(token), kind, now);
  if (!row) return null;

  const claimed = db.prepare(
    "UPDATE email_tokens SET used_at = datetime('now') WHERE id = ? AND used_at IS NULL"
  ).run(row.id);
  if (claimed.changes !== 1) return null;

  return db.prepare('SELECT * FROM users WHERE id = ?').get(row.user_id) || null;
}

function markVerified(userId) {
  db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(userId);
  audit(userId, 'email_verified', `user:${userId}`);
}

function sweepTokens() {
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  db.prepare('DELETE FROM email_tokens WHERE expires_at <= ? OR used_at IS NOT NULL').run(now);
  const old = new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 19).replace('T', ' ');
  db.prepare('DELETE FROM login_attempts WHERE created_at < ?').run(old);
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
  signUpWithPassword, signInWithPassword, setPassword,
  tooManyFailures, recordAttempt, normalizeEmail,
  issueToken, useToken, markVerified, sweepTokens,
  startSession, endSession, userFor, sweepSessions,
  recordLogin, accountsOnIp, sharedIps,
  unseenNotices, markNoticeSeen,
};
