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
  console.log('  Admin accounts:');
  for (const email of admins) {
    const u = db.prepare('SELECT id, role FROM users WHERE lower(email) = ?').get(email);

    if (!u) {
      // Create the row now rather than waiting for a first Google sign-in.
      // It has no google_sub, so it cannot be signed into from the internet -
      // but /dev-login can reach it locally, and the moment that Google
      // address does sign in, signInWithGoogle matches it by email and
      // attaches the identity. Without this there is no way to see the admin
      // side before Google is configured.
      const info = db.prepare(`
        INSERT INTO users (role, name, email, password_hash, email_verified)
        VALUES ('admin', ?, ?, '', 1)
      `).run(email.split('@')[0], email);
      audit(null, 'seed_admin', `user:${Number(info.lastInsertRowid)}`);
      console.log(`    ${email}  (created)`);
    } else if (u.role !== 'admin') {
      db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(u.id);
      audit(null, 'promoted_admin', `user:${u.id}`);
      console.log(`    ${email}  (promoted)`);
    } else {
      console.log(`    ${email}`);
    }
  }
  console.log('  They become usable the moment that Google address signs in.');
}

// ------------------------------------------------------------ testimonials
// Marked is_demo, and the home page says so while any of them are. Swap them
// for real ones from the admin side as they arrive; showing invented praise as
// though it were real is the fastest way to lose the trust the site runs on.
if (!db.prepare('SELECT COUNT(*) AS n FROM testimonials').get().n) {
  const rows = [
    ['Shakib Al Amin', 'Worker, Dhaka',
     'I do three or four tasks in the evening after work. The money shows up the same day the buyer approves it, not next month.',
     '৳4,200 this month'],
    ['Farhana Akter', 'Worker, Chattogram',
     'What I like is that the buyer already paid before I start. On other sites I have done work and then been told the budget was finished.',
     '৳2,850 this month'],
    ['Tanvir Rahman', 'Buyer, app developer',
     'I needed 200 real installs with screenshots. Posted it, funded it, and reviewed the proof myself. The ones that came in too fast were flagged for me automatically.',
     '312 tasks bought'],
    ['Nusrat Jahan', 'Worker, Sylhet',
     'The rules are the same for everyone and they are actually enforced. One job once, and you cannot farm the same buyer all day.',
     '৳1,940 this month'],
    ['Imran Hossain', 'Buyer, marketing agency',
     'Being able to see how long somebody spent on a task changed how I review. Real work and clicking through do not look the same any more.',
     '1,100 tasks bought'],
    ['Rima Chowdhury', 'Worker, Rajshahi',
     'Withdrew twice through bKash with no problem. Support answered inside the site the same evening.',
     '৳3,100 this month'],
  ];
  const insert = db.prepare(
    'INSERT INTO testimonials (name, role, body, earned, is_demo, sort) VALUES (?, ?, ?, ?, 1, ?)'
  );
  rows.forEach((r, i) => insert.run(r[0], r[1], r[2], r[3], i));
  console.log('  Added ' + rows.length + ' example reviews for the home page (marked as examples).');
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
