/* ---------------------------------------------------------------------------
   The banner strip that sits under the header on every page.

   Two things live in two places on purpose:

     the rows      in the database, so order, captions and which are switched
                   on survive a restart and can be edited from the admin page

     the files     in DATA_DIR, on the mounted volume - never in the source
                   tree. Anything written into the app folder is gone at the
                   next deploy, so an admin who uploaded a banner would watch
                   it disappear a day later with nothing to explain it.

   The site ships with a set of banners in src/web/assets/banners. Those are
   seeds, not the live copy: on first run they are copied onto the volume and
   registered, and from then on the admin owns them - replacing or deleting one
   is not undone by the next deploy.
   --------------------------------------------------------------------------- */

const fs = require('fs');
const path = require('path');
const { db, DATA_DIR } = require('./db');

const DIR = path.join(DATA_DIR, 'banners');
const SEED_DIR = path.join(__dirname, '..', 'web', 'assets', 'banners');

function ensureDir() {
  fs.mkdirSync(DIR, { recursive: true });
}

/* The dimensions, straight out of the PNG or JPEG header.

   They go in the page as width and height attributes so the browser reserves
   the right space before the image arrives. Without them the strip is zero
   pixels tall and then suddenly is not, and everything below it jumps at the
   moment somebody was reaching for a link.
*/
function imageSize(file) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const head = Buffer.alloc(32);
    fs.readSync(fd, head, 0, 32, 0);

    // PNG: an IHDR that always starts at byte 16.
    if (head.readUInt32BE(0) === 0x89504E47) {
      return { width: head.readUInt32BE(16), height: head.readUInt32BE(20) };
    }

    // JPEG: walk the segments to the frame header that carries the size.
    if (head[0] === 0xFF && head[1] === 0xD8) {
      const size = fs.statSync(file).size;
      const buf = Buffer.alloc(Math.min(size, 512 * 1024));
      fs.readSync(fd, buf, 0, buf.length, 0);
      let i = 2;
      while (i < buf.length - 9) {
        if (buf[i] !== 0xFF) { i++; continue; }
        const marker = buf[i + 1];
        // SOF0..SOF15, minus the four that are not frame headers.
        if (marker >= 0xC0 && marker <= 0xCF &&
            marker !== 0xC4 && marker !== 0xC8 && marker !== 0xCC) {
          return { height: buf.readUInt16BE(i + 5), width: buf.readUInt16BE(i + 7) };
        }
        i += 2 + buf.readUInt16BE(i + 2);
      }
    }
  } catch { /* an unreadable file simply has no size to offer */ }
  finally { if (fd !== undefined) try { fs.closeSync(fd); } catch { /* nothing */ } }
  return { width: null, height: null };
}

/* Copy the shipped set onto the volume, once.

   Guarded on the table being empty rather than on the files being absent: an
   admin who deletes every banner has decided they want none, and a deploy
   that quietly put them all back would be the site arguing with them.
*/
function seedIfEmpty() {
  ensureDir();
  if (db.prepare('SELECT COUNT(*) AS n FROM banners').get().n > 0) return 0;
  if (!fs.existsSync(SEED_DIR)) return 0;

  let captions = {};
  try {
    captions = JSON.parse(fs.readFileSync(path.join(SEED_DIR, 'captions.json'), 'utf8'));
  } catch { /* captions are optional */ }

  const files = fs.readdirSync(SEED_DIR)
    .filter(f => /\.(png|jpe?g|webp)$/i.test(f))
    .sort((a, b) => a.localeCompare(b, 'en', { numeric: true }));

  let n = 0;
  for (const f of files) {
    const target = path.join(DIR, f);
    try {
      if (!fs.existsSync(target)) fs.copyFileSync(path.join(SEED_DIR, f), target);
      const size = imageSize(target);
      db.prepare(`INSERT INTO banners (file, caption, sort, active, width, height)
                  VALUES (?, ?, ?, 1, ?, ?)`)
        .run(f, captions[f] || '', n, size.width, size.height);
      n++;
    } catch (err) {
      if (!String(err.message).includes('UNIQUE')) throw err;
    }
  }
  return n;
}

// What the page shows: switched on, in the order an admin put them.
function live() {
  return db.prepare(
    'SELECT * FROM banners WHERE active = 1 ORDER BY sort, id'
  ).all().filter(b => fs.existsSync(path.join(DIR, b.file)));
}

// What the admin page shows: everything, including the ones switched off.
function all() {
  return db.prepare('SELECT * FROM banners ORDER BY sort, id').all();
}

function fileFor(name) {
  // basename, so a name from a URL can never climb out of the folder.
  const safe = path.basename(String(name || ''));
  const full = path.join(DIR, safe);
  if (!full.startsWith(DIR)) return null;
  return fs.existsSync(full) ? full : null;
}

function add({ file, caption }) {
  const size = imageSize(path.join(DIR, file));
  const next = db.prepare('SELECT COALESCE(MAX(sort), -1) + 1 AS n FROM banners').get().n;
  const info = db.prepare(`INSERT INTO banners (file, caption, sort, active, width, height)
                           VALUES (?, ?, ?, 1, ?, ?)`)
    .run(file, String(caption || '').slice(0, 300), next, size.width, size.height);
  return Number(info.lastInsertRowid);
}

function remove(id) {
  const row = db.prepare('SELECT * FROM banners WHERE id = ?').get(id);
  if (!row) return false;
  db.prepare('DELETE FROM banners WHERE id = ?').run(id);
  // The row goes first: a file with no row is invisible, a row with no file
  // is a broken image on every page of the site.
  try { fs.unlinkSync(path.join(DIR, row.file)); } catch { /* already gone */ }
  return true;
}

function setCaption(id, caption) {
  db.prepare('UPDATE banners SET caption = ? WHERE id = ?')
    .run(String(caption || '').slice(0, 300), id);
}

function setActive(id, on) {
  db.prepare('UPDATE banners SET active = ? WHERE id = ?').run(on ? 1 : 0, id);
}

/* Move one banner up or down by swapping its place with its neighbour.

   Normalised first, because rows that arrived with equal sort values have no
   defined neighbour and the buttons would appear to do nothing.
*/
function move(id, direction) {
  const rows = all();
  rows.forEach((r, i) => {
    if (r.sort !== i) db.prepare('UPDATE banners SET sort = ? WHERE id = ?').run(i, r.id);
    r.sort = i;
  });

  const at = rows.findIndex(r => r.id === Number(id));
  if (at < 0) return false;
  const to = direction === 'up' ? at - 1 : at + 1;
  if (to < 0 || to >= rows.length) return false;

  db.prepare('UPDATE banners SET sort = ? WHERE id = ?').run(to, rows[at].id);
  db.prepare('UPDATE banners SET sort = ? WHERE id = ?').run(at, rows[to].id);
  return true;
}

module.exports = { DIR, live, all, add, remove, setCaption, setActive, move, seedIfEmpty, fileFor, imageSize, ensureDir };
