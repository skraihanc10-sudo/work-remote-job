/* ---------------------------------------------------------------------------
   A small SMTP client.

   Written by hand for the same reason the Google sign-in and the payment
   signatures were: it is a well-specified protocol, the whole conversation
   fits on a page, and it means no dependency to audit or to compile on a
   Windows machine.

   It speaks the two shapes of SMTP that hosts actually offer:

     port 465  TLS from the first byte ("implicit TLS")
     port 587  plain connection, then STARTTLS upgrades it

   The one thing it will not do is send credentials or a message over an
   unencrypted socket. If the upgrade to TLS fails, the send fails - a mail
   that quietly went out in the clear, with the password that sent it, is
   worse than a mail that did not go.
   --------------------------------------------------------------------------- */

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');

const CONNECT_MS = 15000;
const REPLY_MS = 30000;

/* Wraps a socket in the two things an SMTP conversation needs: read one
   complete reply, and write a line.

   A reply is one or more lines. Continuation lines have a hyphen after the
   code ("250-STARTTLS"), the last has a space ("250 OK"). Reading until the
   first newline is the classic bug here: it works against a server that
   answers tersely and breaks against one that lists its capabilities.
*/
function conversation(socket) {
  let buffer = '';
  let waiting = null;
  let closed = null;

  const settle = () => {
    if (!waiting) return;
    // A complete reply ends with a line whose 4th character is a space.
    const lines = buffer.split('\r\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length >= 4 && line[3] === ' ') {
        const reply = lines.slice(0, i + 1).join('\r\n');
        buffer = lines.slice(i + 1).join('\r\n');
        const w = waiting; waiting = null;
        clearTimeout(w.timer);
        return w.resolve({ code: Number(line.slice(0, 3)), text: reply });
      }
    }
  };

  // Deliberately no setEncoding: a StringDecoder sitting on the socket cannot
  // be handed cleanly to TLS at STARTTLS time. Decode per chunk instead - SMTP
  // commands and replies are ASCII, so no character can straddle a chunk.
  const onData = chunk => { buffer += chunk.toString('latin1'); settle(); };
  const onError = err => {
    closed = err;
    if (waiting) { clearTimeout(waiting.timer); waiting.reject(err); waiting = null; }
  };
  const onClose = () => {
    closed = closed || new Error('The mail server closed the connection.');
    if (waiting) { clearTimeout(waiting.timer); waiting.reject(closed); waiting = null; }
  };
  socket.on('data', onData);
  socket.on('error', onError);
  socket.on('close', onClose);

  return {
    /* Stop listening, and hand back anything already buffered.

       This has to happen before STARTTLS wraps the socket. If it does not,
       this reader is still attached to the raw socket and swallows the first
       bytes of the TLS handshake, which then fails with a mystifying "bad
       record type" rather than anything that points here.
    */
    detach() {
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
      return buffer;
    },
    read() {
      if (closed) return Promise.reject(closed);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          waiting = null;
          reject(new Error('The mail server stopped responding.'));
        }, REPLY_MS);
        waiting = { resolve, reject, timer };
        settle();
      });
    },
    write(line) { socket.write(line + '\r\n'); },
    writeRaw(data) { socket.write(data); },
  };
}

/* Send a command and insist on the reply code we expected. SMTP reports
   failures as codes on an otherwise healthy connection, so a client that does
   not check them reports success for mail the server refused. */
const DEBUG = !!process.env.SMTP_DEBUG;

async function expect(chat, command, wanted, what) {
  // Set SMTP_DEBUG=1 to watch the conversation. Credentials are the one thing
  // never printed - a debug flag that leaks the mail password into the logs
  // is a worse bug than whatever is being debugged.
  if (command !== null) {
    if (DEBUG) console.error('smtp >', /^(AUTH|[A-Za-z0-9+/=]{16,}$)/.test(command) ? '<credentials>' : command);
    chat.write(command);
  }
  const reply = await chat.read();
  if (DEBUG) console.error('smtp <', reply.text.split(String.fromCharCode(13, 10))[0]);
  if (!wanted.includes(reply.code)) {
    throw new Error(`${what} failed: ${reply.text.split('\r\n')[0]}`);
  }
  return reply;
}

// ------------------------------------------------------------------ encoding
/* A header value that is pure ASCII goes as-is; anything else is base64 in an
   RFC 2047 encoded-word. Subjects here are routinely Bengali, and a raw UTF-8
   header is not legal and arrives as mojibake. */
function encodeHeader(value) {
  const v = String(value == null ? '' : value).replace(/[\r\n]/g, ' ');
  if (/^[\x20-\x7E]*$/.test(v)) return v;
  // Split on a generous boundary so no encoded-word exceeds the 75-char limit.
  const chunks = [];
  const bytes = Buffer.from(v, 'utf8');
  const MAX = 36;                       // bytes per chunk, base64 grows by 4/3
  for (let i = 0; i < bytes.length;) {
    let take = Math.min(MAX, bytes.length - i);
    // Never split a multi-byte character: back off to a lead byte.
    while (take > 1 && (bytes[i + take] & 0xC0) === 0x80) take--;
    chunks.push('=?UTF-8?B?' + bytes.slice(i, i + take).toString('base64') + '?=');
    i += take;
  }
  return chunks.join('\r\n ');
}

// An address for a header: the display name is encoded, the address is not.
function encodeAddress(email, name) {
  if (!name) return email;
  return `${encodeHeader(name)} <${email}>`;
}

function base64Body(text) {
  return Buffer.from(String(text), 'utf8').toString('base64').replace(/(.{76})/g, '$1\r\n');
}

/* Build the RFC 5322 message.

   Sent as multipart/alternative: a plain-text part for clients that will not
   render HTML, and an HTML part for the rest. Base64 throughout, because the
   content is Bengali as often as English and quoted-printable would make most
   of it unreadable in the raw.
*/
function buildMessage({ from, fromName, to, toName, subject, text, html, replyTo, listUnsubscribe }) {
  // 12 random bytes is far more than enough to be unique, and keeps the
  // Content-Type line inside the 78 characters a header line should not
  // exceed. 16 bytes pushed it to 85 - legal, but needlessly untidy.
  const boundary = '_rwb_' + crypto.randomBytes(12).toString('hex');
  const headers = [
    `From: ${encodeAddress(from, fromName)}`,
    `To: ${encodeAddress(to, toName)}`,
    `Subject: ${encodeHeader(subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${crypto.randomBytes(16).toString('hex')}@${from.split('@')[1] || 'localhost'}>`,
    'MIME-Version: 1.0',
  ];
  if (replyTo) headers.push(`Reply-To: ${replyTo}`);
  if (listUnsubscribe) {
    headers.push(`List-Unsubscribe: <${listUnsubscribe}>`);
    headers.push('List-Unsubscribe-Post: List-Unsubscribe=One-Click');
  }
  headers.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);

  return headers.join('\r\n') + '\r\n\r\n' +
    `--${boundary}\r\n` +
    'Content-Type: text/plain; charset=UTF-8\r\n' +
    'Content-Transfer-Encoding: base64\r\n\r\n' +
    base64Body(text) + '\r\n' +
    `--${boundary}\r\n` +
    'Content-Type: text/html; charset=UTF-8\r\n' +
    'Content-Transfer-Encoding: base64\r\n\r\n' +
    base64Body(html) + '\r\n' +
    `--${boundary}--\r\n`;
}

/* A line in DATA that begins with a full stop would end the message early.
   The fix is in the spec: double it, and the server removes one. Getting this
   wrong truncates exactly the messages whose wrapped text happens to start a
   line with a dot, which is rare enough to survive testing and reach real
   people. */
function dotStuff(message) {
  return message.replace(/\r\n\./g, '\r\n..');
}

// -------------------------------------------------------------------- sending
async function connect(host, port, secure) {
  return new Promise((resolve, reject) => {
    const onError = err => { cleanup(); reject(err); };
    const timer = setTimeout(() => {
      cleanup();
      socket.destroy();
      reject(new Error(`Could not reach ${host}:${port} within 15 seconds.`));
    }, CONNECT_MS);
    const cleanup = () => { clearTimeout(timer); socket.removeListener('error', onError); };

    // SNI is a hostname; sending an IP there is not allowed and Node warns.
    const sni = net.isIP(host) ? undefined : host;
    const socket = secure
      ? tls.connect({ host, port, servername: sni }, () => { cleanup(); resolve(socket); })
      : net.connect({ host, port }, () => { cleanup(); resolve(socket); });
    socket.once('error', onError);
  });
}

async function upgrade(socket, host) {
  return new Promise((resolve, reject) => {
    const secure = tls.connect({ socket, servername: net.isIP(host) ? undefined : host }, () => {
      secure.removeListener('error', reject);
      resolve(secure);
    });
    secure.once('error', reject);
  });
}

/* Deliver one message. Resolves on a 250 for the final dot - which is the
   only point at which the server has taken responsibility for it - and
   rejects with something a person can act on otherwise. */
async function send(config, message) {
  const port = Number(config.port) || 587;
  // Port 465 means TLS from the first byte, and 587 means upgrade with
  // STARTTLS. That is the convention, not a rule - some hosts put implicit
  // TLS on another port entirely - so it is only the default and `secure`
  // can say otherwise.
  const implicitTls = config.secure === undefined ? port === 465 : !!config.secure;
  const host = String(config.host || '').trim();
  if (!host) throw new Error('No SMTP host is configured.');

  let socket = await connect(host, port, implicitTls);
  let chat = conversation(socket);
  const me = config.clientName || 'remoteworkbd';

  try {
    await expect(chat, null, [220], 'Connecting');
    let greeting = await expect(chat, `EHLO ${me}`, [250], 'EHLO');

    if (!implicitTls) {
      if (!/STARTTLS/i.test(greeting.text)) {
        throw new Error(
          `${host} does not offer STARTTLS on port ${port}, so the password and the ` +
          'message would travel unencrypted. Refusing to send. Try port 465.');
      }
      await expect(chat, 'STARTTLS', [220], 'STARTTLS');
      chat.detach();
      socket = await upgrade(socket, host);
      chat = conversation(socket);
      // The capability list has to be asked for again after the upgrade: what
      // the server offered in the clear does not bind it once encrypted.
      greeting = await expect(chat, `EHLO ${me}`, [250], 'EHLO after STARTTLS');
    }

    if (config.user) {
      const auth = greeting.text.toUpperCase();
      if (auth.includes('AUTH') && auth.includes('PLAIN')) {
        const token = Buffer.from(`\0${config.user}\0${config.pass || ''}`, 'utf8').toString('base64');
        await expect(chat, `AUTH PLAIN ${token}`, [235], 'Signing in to the mail server');
      } else {
        await expect(chat, 'AUTH LOGIN', [334], 'Signing in to the mail server');
        await expect(chat, Buffer.from(String(config.user), 'utf8').toString('base64'),
          [334], 'Mail server username');
        await expect(chat, Buffer.from(String(config.pass || ''), 'utf8').toString('base64'),
          [235], 'Mail server password');
      }
    }

    await expect(chat, `MAIL FROM:<${message.from}>`, [250], 'MAIL FROM');
    await expect(chat, `RCPT TO:<${message.to}>`, [250, 251], 'RCPT TO');
    await expect(chat, 'DATA', [354], 'DATA');

    chat.writeRaw(dotStuff(buildMessage(message)));
    await expect(chat, '.', [250], 'Delivering the message');

    try { chat.write('QUIT'); } catch { /* the message is already accepted */ }
    return true;
  } finally {
    socket.destroy();
  }
}

/* Open a connection, authenticate, and hang up without sending anything.
   What the admin "send a test" button uses to separate "the settings are
   wrong" from "the message was rejected". */
async function check(config) {
  const port = Number(config.port) || 587;
  const implicitTls = config.secure === undefined ? port === 465 : !!config.secure;
  const host = String(config.host || '').trim();
  if (!host) throw new Error('No SMTP host is configured.');

  let socket = await connect(host, port, implicitTls);
  let chat = conversation(socket);
  try {
    await expect(chat, null, [220], 'Connecting');
    let greeting = await expect(chat, 'EHLO remoteworkbd', [250], 'EHLO');
    if (!implicitTls) {
      if (!/STARTTLS/i.test(greeting.text)) {
        throw new Error(`${host} does not offer STARTTLS on port ${port}. Try port 465.`);
      }
      await expect(chat, 'STARTTLS', [220], 'STARTTLS');
      chat.detach();
      socket = await upgrade(socket, host);
      chat = conversation(socket);
      greeting = await expect(chat, 'EHLO remoteworkbd', [250], 'EHLO after STARTTLS');
    }
    if (config.user) {
      const token = Buffer.from(`\0${config.user}\0${config.pass || ''}`, 'utf8').toString('base64');
      const auth = greeting.text.toUpperCase();
      if (auth.includes('PLAIN')) {
        await expect(chat, `AUTH PLAIN ${token}`, [235], 'Signing in to the mail server');
      } else {
        await expect(chat, 'AUTH LOGIN', [334], 'Signing in to the mail server');
        await expect(chat, Buffer.from(String(config.user), 'utf8').toString('base64'), [334], 'Username');
        await expect(chat, Buffer.from(String(config.pass || ''), 'utf8').toString('base64'), [235], 'Password');
      }
    }
    try { chat.write('QUIT'); } catch { /* nothing to lose */ }
    return true;
  } finally {
    socket.destroy();
  }
}

module.exports = { send, check, buildMessage, encodeHeader, dotStuff };
