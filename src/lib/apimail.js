/* ---------------------------------------------------------------------------
   Sending mail over HTTPS instead of SMTP.

   Written because the SMTP client, which is correct, cannot help on a host
   that will not let SMTP out. Railway - and most container hosts - block
   outbound 25, 465 and 587 to stop their addresses being used for spam, and a
   blocked port looks like this:

     Could not open a connection to smtp.gmail.com:587 (ETIMEDOUT)

   No password is wrong, no setting will fix it, and 465 fails the same way.
   The way out is not another port: it is not using SMTP at all. Brevo and the
   others all accept a message as an ordinary HTTPS request on 443, which is
   the same port the site already serves on - so if the site is reachable, its
   mail is sendable.

   Kept deliberately small: one request to send, one to check the key.
   --------------------------------------------------------------------------- */

const TIMEOUT_MS = 20000;

/* Every provider here takes an API key in a header and a JSON body. They
   differ only in the shape of that body, so a provider is a few lines rather
   than a module. */
const PROVIDERS = {
  brevo: {
    name: 'Brevo',
    sendUrl: 'https://api.brevo.com/v3/smtp/email',
    checkUrl: 'https://api.brevo.com/v3/account',
    headers: key => ({ 'api-key': key, 'content-type': 'application/json', accept: 'application/json' }),
    body: (cfg, m) => ({
      sender: { name: m.fromName || cfg.fromName, email: m.from || cfg.from },
      to: [{ email: m.to }],
      subject: m.subject,
      textContent: m.text,
      htmlContent: m.html,
      ...(m.replyTo ? { replyTo: { email: m.replyTo } } : {}),
      ...(m.listUnsubscribe ? { headers: { 'List-Unsubscribe': m.listUnsubscribe } } : {}),
    }),
    // Brevo answers 201 with a messageId when it has taken the message.
    ok: status => status === 201 || status === 200,
  },

  resend: {
    name: 'Resend',
    sendUrl: 'https://api.resend.com/emails',
    checkUrl: 'https://api.resend.com/domains',
    headers: key => ({ authorization: `Bearer ${key}`, 'content-type': 'application/json' }),
    body: (cfg, m) => ({
      from: `${m.fromName || cfg.fromName} <${m.from || cfg.from}>`,
      to: [m.to],
      subject: m.subject,
      text: m.text,
      html: m.html,
      ...(m.replyTo ? { reply_to: m.replyTo } : {}),
    }),
    ok: status => status === 200 || status === 201,
  },
};

/* Where the provider lives.

   Overridable so the whole path can be exercised against a stand-in without
   sending mail to real people, and so anyone who has to send through an
   internal proxy can. Unset - which is the normal case - the real endpoints
   above are used. */
function endpoint(url) {
  const base = String(process.env.MAIL_API_BASE || '').replace(/\/$/, '');
  if (!base) return url;
  return base + new URL(url).pathname;
}

function provider(name) {
  const p = PROVIDERS[String(name || '').toLowerCase()];
  if (!p) throw new Error(`No mail API called "${name}" is known.`);
  return p;
}

/* Pull the human-readable complaint out of whatever shape the provider
   returned. A 401 that reports itself as "[object Object]" teaches nobody
   anything. */
function reason(status, text) {
  let detail = String(text || '').slice(0, 400);
  try {
    const parsed = JSON.parse(text);
    detail = parsed.message || parsed.error || (parsed.errors && JSON.stringify(parsed.errors)) || detail;
    if (typeof detail === 'object') detail = JSON.stringify(detail);
  } catch { /* not JSON; the raw body is the best we have */ }

  if (status === 401 || status === 403) {
    return `The API key was refused (${status}). Check it was copied whole. ${detail}`;
  }
  if (status === 400) {
    return `The message was refused (400). Usually the send-from address is not a verified `
      + `sender with this provider. ${detail}`;
  }
  if (status === 429) return `Rate limited by the provider (429). ${detail}`;
  return `The mail provider answered ${status}. ${detail}`;
}

async function request(url, { method = 'GET', headers, body } = {}) {
  const stop = AbortSignal.timeout(TIMEOUT_MS);
  let res;
  try {
    res = await fetch(url, {
      method, headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: stop,
    });
  } catch (err) {
    // A name with no message here would be the same trap as the SMTP one.
    const why = err.message || err.code || err.name || 'the request failed';
    throw new Error(`Could not reach the mail provider over HTTPS: ${why}`);
  }
  const text = await res.text().catch(() => '');
  return { status: res.status, text };
}

/* Deliver one message. Resolves only when the provider has said it has the
   message - the same rule the SMTP client follows for the final dot. */
async function send(config, message) {
  const p = provider(config.apiProvider);
  const key = String(config.apiKey || '').trim();
  if (!key) throw new Error('No API key is configured for the mail provider.');

  const { status, text } = await request(endpoint(p.sendUrl), {
    method: 'POST',
    headers: p.headers(key),
    body: p.body(config, message),
  });

  if (!p.ok(status)) throw new Error(reason(status, text));
  return true;
}

/* Prove the key works without sending anything, so the setup page can tell
   "the key is wrong" apart from "the message was rejected". */
async function check(config) {
  const p = provider(config.apiProvider);
  const key = String(config.apiKey || '').trim();
  if (!key) throw new Error('Paste the API key first.');

  const { status, text } = await request(endpoint(p.checkUrl), { headers: p.headers(key) });
  if (status < 200 || status >= 300) throw new Error(reason(status, text));
  return true;
}

module.exports = { send, check, PROVIDERS };
