/* Accounts and sessions.

   Passwords are hashed with scrypt from Node's own crypto - no dependency, and
   deliberately slow, which is the point. Sessions are random tokens in the
   database rather than signed cookies, so signing somebody out actually signs
   them out.
*/

const crypto = require('crypto');
const { db, audit } = require('./db');
const antispam = require('./antispam');

const SESSION_DAYS = 30;

function hash(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(String(password), salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('hex')}$${derived.toString('hex')}`;
}

function verify(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const salt = Buffer.from(parts[1], 'hex');
  const want = Buffer.from(parts[2], 'hex');
  const got = crypto.scryptSync(String(password), salt, want.length, { N: 16384, r: 8, p: 1 });
  return crypto.timingSafeEqual(got, want);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(email || '').trim());
}

function register({ name, email, password, role, country }) {
  name = String(name || '').trim();
  email = String(email || '').trim().toLowerCase();

  if (name.length < 2) throw new Error('Enter your name');
  if (!validEmail(email)) throw new Error('That email address does not look right');
  if (String(password || '').length < 8) throw new Error('Use at least 8 characters for the password');
  if (role !== 'worker' && role !== 'merchant') throw new Error('Choose whether you are hiring or working');

  const taken = db.prepare('SELECT id FROM users WHERE lower(email) = ?').get(email);
  if (taken) throw new Error('An account already uses that email');

  const info = db.prepare(
    'INSERT INTO users (role, name, email, password_hash, country) VALUES (?, ?, ?, ?, ?)'
  ).run(role, name, email, hash(password), country || null);

  const id = Number(info.lastInsertRowid);
  audit(id, 'register', `user:${id}`, { role });
  return id;
}

function login(email, password) {
  const user = db.prepare('SELECT * FROM users WHERE lower(email) = ?')
    .get(String(email || '').trim().toLowerCase());
  // Same message either way: telling someone an email exists is a free gift to
  // anyone testing a list of addresses.
  if (!user || !verify(password, user.password_hash)) {
    throw new Error('Email or password is wrong');
  }
  if (user.status === 'banned') throw new Error('This account has been closed.');
  return user;
}

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

module.exports = { hash, verify, register, login, startSession, endSession, userFor, sweepSessions };
