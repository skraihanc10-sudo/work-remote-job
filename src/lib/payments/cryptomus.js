/* ---------------------------------------------------------------------------
   Cryptomus - crypto deposits.

   Two calls and a webhook:
     POST /v1/payment          create an invoice, get a hosted payment page
     POST /v1/payment/info     ask the current state of one invoice
     webhook                   Cryptomus tells us when it changes

   Every request and every webhook carries a `sign`:

     md5( base64( json_body ) + API_KEY )

   The catch worth writing down: Cryptomus computes it the way PHP's
   json_encode does, and PHP escapes forward slashes as \/ by default. A URL in
   the payload is enough to make a Node signature differ from theirs. We send
   the slash-escaped form, and when verifying we accept either, so a change at
   their end cannot silently start rejecting real webhooks.
   --------------------------------------------------------------------------- */

const crypto = require('crypto');

const BASE = 'https://api.cryptomus.com/v1';

function config() {
  return {
    merchant: process.env.CRYPTOMUS_MERCHANT_ID || '',
    payKey: process.env.CRYPTOMUS_PAYMENT_KEY || '',
  };
}

function configured() {
  const c = config();
  return Boolean(c.merchant && c.payKey);
}

// PHP's json_encode with JSON_UNESCAPED_UNICODE: slashes escaped, unicode not.
function phpJson(obj) {
  return JSON.stringify(obj).replace(/\//g, '\\/');
}

function sign(body, key) {
  return crypto.createHash('md5').update(Buffer.from(body).toString('base64') + key).digest('hex');
}

async function call(path, payload) {
  const c = config();
  if (!configured()) throw new Error('Cryptomus is not configured');

  const body = phpJson(payload);
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      merchant: c.merchant,
      sign: sign(body, c.payKey),
    },
    body,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok || (data.state !== undefined && data.state !== 0)) {
    const message = data.message
      || (data.errors && JSON.stringify(data.errors))
      || `Cryptomus returned ${res.status}`;
    throw new Error(message);
  }
  return data.result || data;
}

/* Create an invoice. `orderId` is our deposit row id, which is how the webhook
   finds its way back to the right deposit. */
async function createInvoice({ orderId, amount, currency, callbackUrl, successUrl, returnUrl }) {
  return call('/payment', {
    amount: String(amount),
    currency: currency || 'USD',
    order_id: String(orderId),
    url_callback: callbackUrl,
    url_success: successUrl,
    url_return: returnUrl,
    // Partial payments create a reconciliation problem we would rather not
    // have: one deposit, one payment, or nothing.
    is_payment_multiple: false,
    lifetime: 3600,
  });
}

async function invoiceInfo({ uuid, orderId }) {
  return call('/payment/info', uuid ? { uuid } : { order_id: String(orderId) });
}

/* Verify a webhook. Returns true only if the signature matches with the API
   key we hold, which is what proves Cryptomus sent it and not somebody who
   guessed the URL. */
function verifyWebhook(payload) {
  const c = config();
  if (!configured()) return false;

  const given = String(payload && payload.sign ? payload.sign : '');
  if (!given) return false;

  const rest = { ...payload };
  delete rest.sign;

  const candidates = [sign(phpJson(rest), c.payKey), sign(JSON.stringify(rest), c.payKey)];
  return candidates.some(want => {
    if (want.length !== given.length) return false;
    return crypto.timingSafeEqual(Buffer.from(want), Buffer.from(given));
  });
}

// Cryptomus statuses that mean the money is really there.
const PAID = new Set(['paid', 'paid_over']);
const DEAD = new Set(['fail', 'cancel', 'system_fail', 'wrong_amount']);

function classify(status) {
  if (PAID.has(status)) return 'paid';
  if (DEAD.has(status)) return 'failed';
  return 'pending';
}

module.exports = { configured, createInvoice, invoiceInfo, verifyWebhook, classify, phpJson, sign };
