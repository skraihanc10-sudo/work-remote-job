/* ---------------------------------------------------------------------------
   Passwords.

   The site was Google-only on purpose: there was no secret stored here, so
   there was nothing to steal, guess or reset. Adding passwords gives that up,
   so everything here exists to give back as much of it as possible.

     - scrypt, not a plain hash. A password is not a hash input, it is a
       low-entropy secret, and the only defence is making each guess cost
       something. scrypt costs memory as well as time, which is what stops
       somebody renting a GPU and testing billions of guesses a second.
     - A per-password random salt, so two people who picked the same password
       do not get the same stored value, and one cracked password is one
       cracked password.
     - Comparison in constant time. A comparison that returns early leaks how
       much of the value was right, one byte at a time.
     - The cost parameters are stored inside the string, so they can be raised
       later without invalidating everybody's existing password.

   scrypt is in Node itself. No dependency, nothing to compile - which is the
   same reason this project uses node:sqlite.
   --------------------------------------------------------------------------- */

const crypto = require('crypto');

// N=32768 costs about 32MB and 60ms per hash here. High enough that bulk
// guessing is expensive, low enough that a real sign-in feels instant and a
// burst of them will not knock over a cheap VPS. The value is recorded in
// every stored hash, so it can be raised later without invalidating anyone.
const N = 32768;
const R = 8;
const P = 1;
const KEYLEN = 64;
// scrypt needs maxmem above roughly 128 * N * r, or Node refuses.
const MAXMEM = 64 * 1024 * 1024;

function hash(plain) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(String(plain), salt, KEYLEN, { N, r: R, p: P, maxmem: MAXMEM });
  return ['scrypt', N, R, P, salt.toString('base64'), key.toString('base64')].join('$');
}

/* Returns true only for a genuine match.

   Never throws on a malformed or empty stored value - a Google-only account
   has an empty password_hash, and asking whether a password matches it must
   simply be false rather than an error somebody can provoke.
*/
function verify(plain, stored) {
  if (!stored || typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const n = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (!n || !r || !p) return false;

  let salt, expected;
  try {
    salt = Buffer.from(parts[4], 'base64');
    expected = Buffer.from(parts[5], 'base64');
  } catch { return false; }
  if (!salt.length || !expected.length) return false;

  let actual;
  try {
    actual = crypto.scryptSync(String(plain), salt, expected.length,
      { N: n, r, p, maxmem: MAXMEM });
  } catch { return false; }

  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

/* Whether a stored hash was made with weaker parameters than we use now, so
   it can be upgraded silently the next time the person signs in - the only
   moment the plaintext is available to rehash. */
function needsUpgrade(stored) {
  if (!stored || typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  return Number(parts[1]) < N;
}

// The twenty or so passwords that a guessing attempt tries first. Blocking
// them costs a legitimate person nothing and removes the easiest wins.
const OBVIOUS = new Set([
  'password', 'password1', 'password123', '12345678', '123456789', '1234567890',
  'qwerty123', 'qwertyui', 'abc12345', 'iloveyou', 'admin123', 'welcome1',
  'letmein1', 'football', 'baseball', 'sunshine', 'princess', 'dragon123',
  'monkey123', 'trustno1', 'bangladesh', 'dhaka1234', 'remotework',
]);

/* What is wrong with this password, or null if nothing is.

   Length carries most of the strength, so the rule is a real minimum rather
   than a pile of character-class requirements that mostly teach people to
   write Password1! and call it done.
*/
function problemWith(plain, { name, email, username } = {}) {
  const pw = String(plain || '');
  if (pw.length < 8) return 'Your password needs at least 8 characters.';
  if (pw.length > 200) return 'That password is too long - 200 characters at most.';
  if (!/\S/.test(pw)) return 'Your password cannot be only spaces.';
  if (OBVIOUS.has(pw.toLowerCase())) {
    return 'That is one of the first passwords an attacker tries. Please pick another.';
  }
  if (/^(.)\1+$/.test(pw)) return 'A single repeated character is not a password.';

  // A password that contains your own name or address is the first thing
  // guessed by anybody who knows who you are.
  const low = pw.toLowerCase();
  for (const own of [name, username, String(email || '').split('@')[0]]) {
    const v = String(own || '').toLowerCase().trim();
    if (v.length >= 4 && low.includes(v)) {
      return 'Your password should not contain your own name or email address.';
    }
  }
  return null;
}

/* Usernames are the handle people sign in with, so they have to be
   unambiguous: no spaces, no lookalike punctuation, and a reserved list so
   nobody registers "admin" or "support" and mails people as us. */
const RESERVED = new Set([
  'admin', 'administrator', 'root', 'support', 'help', 'helpdesk', 'staff',
  'moderator', 'mod', 'system', 'security', 'billing', 'payment', 'payments',
  'official', 'team', 'remoteworkbd', 'remotework', 'workremote', 'noreply',
  'no-reply', 'info', 'contact', 'about', 'login', 'logout', 'signup',
  'register', 'settings', 'wallet', 'jobs', 'task', 'tasks', 'me', 'null',
  'undefined', 'anonymous', 'guest', 'test',
]);

function problemWithUsername(raw) {
  const u = String(raw || '').trim();
  if (u.length < 3) return 'Your username needs at least 3 characters.';
  if (u.length > 24) return 'Your username can be at most 24 characters.';
  if (!/^[a-zA-Z0-9_.]+$/.test(u)) {
    return 'Usernames can use letters, numbers, underscore and full stop only.';
  }
  if (!/^[a-zA-Z]/.test(u)) return 'Your username must start with a letter.';
  if (/[._]{2,}/.test(u)) return 'Your username cannot contain two dots or underscores in a row.';
  if (/[._]$/.test(u)) return 'Your username cannot end with a dot or an underscore.';
  if (RESERVED.has(u.toLowerCase())) return 'That username is reserved. Please pick another.';
  return null;
}

module.exports = { hash, verify, needsUpgrade, problemWith, problemWithUsername };
