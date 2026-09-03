/* Sets up categories and, optionally, demo data to click around in.

     npm run seed
     npm run seed -- --demo

   There is no admin password to set: sign-in is Google only. An account
   becomes an admin because its email is listed in ADMIN_EMAILS, checked on
   every sign-in, so admins are made by configuration rather than by anything
   a visitor can do.
*/

const { db, audit } = require('./lib/db');
const auth = require('./lib/auth');
const money = require('./lib/money');

const admins = auth.adminEmails();

console.log('');
if (!admins.length) {
  console.log('  No admin emails configured.');
  console.log('  Set ADMIN_EMAILS to the Google address that should run this site:\n');
  console.log('    ADMIN_EMAILS=you@gmail.com npm start\n');
} else {
  console.log('  Admin accounts (created on first Google sign-in):');
  admins.forEach(e => console.log('    ' + e));
  // Promote any that already exist.
  for (const email of admins) {
    const u = db.prepare('SELECT id, role FROM users WHERE lower(email) = ?').get(email);
    if (u && u.role !== 'admin') {
      db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(u.id);
      audit(null, 'promoted_admin', `user:${u.id}`);
      console.log(`    (existing account ${email} promoted)`);
    }
  }
}

// -------------------------------------------------------------------- demo
if (process.argv.includes('--demo')) {
  // Demo accounts have no google_sub, so they can never be signed into. They
  // exist to make the screens show something real.
  function demoUser(role, name, email, country) {
    const found = db.prepare('SELECT id FROM users WHERE lower(email) = ?').get(email);
    if (found) return found.id;
    const info = db.prepare(`
      INSERT INTO users (role, name, email, password_hash, country, email_verified)
      VALUES (?, ?, ?, '', ?, 1)
    `).run(role, name, email, country || null);
    return Number(info.lastInsertRowid);
  }

  const merchant = demoUser('merchant', 'Demo Buyer', 'buyer@example.com', 'Bangladesh');
  demoUser('worker', 'Rakib Hasan', 'rakib@example.com', 'Bangladesh');
  demoUser('worker', 'Nusrat Jahan', 'nusrat@example.com', 'Bangladesh');

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
  Demo data ready - three funded jobs and a buyer to review them.
  These accounts have no Google identity, so they cannot be signed into;
  they are there so the job list and dashboards are not empty.`);
}

console.log('\n  Run:  npm start\n');
