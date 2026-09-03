/* Creates the admin account, and optionally some demo data to click around in.

     npm run seed                    admin only
     npm run seed -- --demo          admin + sample merchant, workers and jobs

   Safe to run more than once: existing accounts are left alone.
*/

const { db, audit } = require('./lib/db');
const auth = require('./lib/auth');
const money = require('./lib/money');

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@workremotejob.local';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

function ensure(role, name, email, password, country) {
  const found = db.prepare('SELECT * FROM users WHERE lower(email) = ?').get(email.toLowerCase());
  if (found) return found.id;
  const info = db.prepare(
    'INSERT INTO users (role, name, email, password_hash, country) VALUES (?, ?, ?, ?, ?)'
  ).run(role, name, email, auth.hash(password), country || null);
  return Number(info.lastInsertRowid);
}

// ------------------------------------------------------------------- admin
if (!ADMIN_PASSWORD) {
  console.error('\n  Set an admin password first:\n');
  console.error('    ADMIN_PASSWORD=your-password npm run seed\n');
  process.exit(1);
}
if (ADMIN_PASSWORD.length < 8) {
  console.error('\n  Use at least 8 characters for the admin password.\n');
  process.exit(1);
}

const existing = db.prepare("SELECT id FROM users WHERE role = 'admin'").get();
if (existing) {
  console.log(`\n  An admin already exists (id ${existing.id}). Left alone.`);
} else {
  const id = ensure('admin', 'Administrator', ADMIN_EMAIL, ADMIN_PASSWORD);
  audit(id, 'seed_admin', `user:${id}`);
  console.log(`\n  Admin created\n    email: ${ADMIN_EMAIL}`);
}

// -------------------------------------------------------------------- demo
if (process.argv.includes('--demo')) {
  const merchant = ensure('merchant', 'Demo Buyer', 'buyer@example.com', 'demo12345', 'Bangladesh');
  const w1 = ensure('worker', 'Rakib Hasan', 'rakib@example.com', 'demo12345', 'Bangladesh');
  const w2 = ensure('worker', 'Nusrat Jahan', 'nusrat@example.com', 'demo12345', 'Bangladesh');

  if (money.balance(merchant) === 0) {
    money.entry(merchant, 'deposit', 500000, null, 'Demo funds');
  }

  if (!db.prepare('SELECT id FROM jobs WHERE merchant_id = ?').get(merchant)) {
    const jobs = [
      {
        title: 'Sign up and confirm your email',
        cat: 'sign-up', rate: 500, slots: 20, min: 90,
        instructions: '1. Open the link we send in the task.\n2. Create an account with a real email.\n3. Open the confirmation email and click the link.\n4. Send us the username you chose.',
        proof: 'The username you registered, and a screenshot of the page after confirming.',
      },
      {
        title: 'Install the app and open it once',
        cat: 'app-install', rate: 800, slots: 15, min: 180,
        instructions: '1. Install the app from the Play Store link.\n2. Open it and let the first screen finish loading.\n3. Keep it installed for at least 48 hours.',
        proof: 'A screenshot of the app open on your phone, showing your device.',
      },
      {
        title: 'Watch a video for 2 minutes and comment',
        cat: 'youtube', rate: 300, slots: 40, min: 150,
        instructions: '1. Open the video link.\n2. Watch at least 2 minutes.\n3. Leave a comment in your own words about what you saw.\n4. Do not copy another comment.',
        proof: 'Your channel name and the exact comment you left.',
      },
    ];

    for (const j of jobs) {
      const cat = db.prepare('SELECT id FROM categories WHERE slug = ?').get(j.cat);
      db.exec('BEGIN');
      try {
        const info = db.prepare(`
          INSERT INTO jobs (merchant_id, category_id, title, instructions, proof_required,
                            rate, slots, min_seconds, hold_minutes, country)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(merchant, cat ? cat.id : null, j.title, j.instructions, j.proof,
               j.rate, j.slots, j.min, 60, null);
        money.fundJob(Number(info.lastInsertRowid), merchant, j.rate * j.slots);
        db.exec('COMMIT');
      } catch (err) {
        db.exec('ROLLBACK');
        console.error('  demo job failed:', err.message);
      }
    }
  }

  console.log(`
  Demo data ready
    buyer@example.com   / demo12345   (merchant, funded)
    rakib@example.com   / demo12345   (worker)
    nusrat@example.com  / demo12345   (worker)`);
}

console.log('\n  Run:  npm start\n');
