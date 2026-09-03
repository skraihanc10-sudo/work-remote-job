/* ---------------------------------------------------------------------------
   EPS - Easy Payment System. bKash, Nagad, Rocket, cards, internet banking.

   Three calls:
     POST /v1/Auth/GetToken                          a JWT, cached until it expires
     POST /v1/EPSEngine/InitializeEPS                returns a URL to send the payer to
     GET  /v1/EPSEngine/CheckMerchantTransactionStatus   what actually happened

   Every request carries `x-hash`: base64( HMAC-SHA512( value, hashKey ) ),
   where the value is the username for the token call and the merchant
   transaction id for the other two.

   The important part is not here but at the call site: EPS sends the payer
   back to our success URL in their browser, and a browser redirect is not
   evidence of anything. Nothing is credited until CheckMerchantTransactionStatus
   has been asked, server to server.
   --------------------------------------------------------------------------- */

const crypto = require('crypto');

const HOSTS = {
  sandbox: 'https://sandbox-pgapi.eps.com.bd',
  live: 'https://pgapi.eps.com.bd',
};

function config() {
  return {
    username: process.env.EPS_USERNAME || '',
    password: process.env.EPS_PASSWORD || '',
    hashKey: process.env.EPS_HASH_KEY || '',
    merchantId: process.env.EPS_MERCHANT_ID || '',
    storeId: process.env.EPS_STORE_ID || '',
    sandbox: process.env.EPS_SANDBOX !== '0',
  };
}

function configured() {
  const c = config();
  return Boolean(c.username && c.password && c.hashKey && c.merchantId && c.storeId);
}

function base() {
  return config().sandbox ? HOSTS.sandbox : HOSTS.live;
}

function hash(value) {
  return crypto.createHmac('sha512', Buffer.from(config().hashKey, 'utf8'))
    .update(String(value), 'utf8').digest('base64');
}

/* EPS wants a merchant transaction id of at least ten digits and unique
   forever. Timestamp to the millisecond plus randomness: readable in a support
   conversation, and it will not collide. */
function newTransactionId() {
  const now = new Date();
  const p = n => String(n).padStart(2, '0');
  return `${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}` +
         `${p(now.getHours())}${p(now.getMinutes())}${p(now.getSeconds())}` +
         String(now.getMilliseconds()).padStart(3, '0') +
         crypto.randomInt(100, 999);
}

// The token lives for a while; asking for a new one on every payment would be
// an extra round trip for nothing.
let cached = { token: null, expires: 0 };

async function token() {
  if (cached.token && Date.now() < cached.expires - 60000) return cached.token;

  const c = config();
  const res = await fetch(base() + '/v1/Auth/GetToken', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-hash': hash(c.username) },
    body: JSON.stringify({ userName: c.username, password: c.password }),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.errorCode || data.errorMessage || !data.token) {
    throw new Error(data.errorMessage || `EPS refused the credentials (${res.status})`);
  }

  cached = {
    token: data.token,
    expires: data.expireDate ? new Date(data.expireDate).getTime() : Date.now() + 20 * 60000,
  };
  return cached.token;
}

/* Start a payment. `amount` is in whole taka, not paisa - EPS works in major
   units. Returns { transactionId, redirectUrl }. */
async function initialize({ orderId, merchantTransactionId, amount, customer, urls, ip }) {
  const c = config();
  if (!configured()) throw new Error('EPS is not configured');

  const body = {
    merchantId: c.merchantId,
    storeId: c.storeId,
    CustomerOrderId: String(orderId),
    merchantTransactionId,
    transactionTypeId: 1,             // web
    financialEntityId: 0,
    transitionStatusId: 0,
    totalAmount: amount,
    ipAddress: ip || '0.0.0.0',
    version: '1',
    successUrl: urls.success,
    failUrl: urls.fail,
    cancelUrl: urls.cancel,
    customerName: customer.name,
    customerEmail: customer.email,
    CustomerAddress: customer.address || 'N/A',
    CustomerAddress2: '',
    CustomerCity: customer.city || 'Dhaka',
    CustomerState: customer.state || 'Dhaka',
    CustomerPostcode: customer.postcode || '1200',
    CustomerCountry: customer.country || 'BD',
    CustomerPhone: customer.phone || 'N/A',
    ShipmentName: '', ShipmentAddress: '', ShipmentAddress2: '',
    ShipmentCity: '', ShipmentState: '', ShipmentPostcode: '', ShipmentCountry: '',
    ValueA: String(orderId), ValueB: '', ValueC: '', ValueD: '',
    ShippingMethod: 'NO',
    NoOfItem: '1',
    ProductName: 'Account balance top-up',
    ProductProfile: 'non-physical-goods',
    ProductCategory: 'digital',
    ProductList: [],
  };

  const res = await fetch(base() + '/v1/EPSEngine/InitializeEPS', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-hash': hash(merchantTransactionId),
      Authorization: `Bearer ${await token()}`,
    },
    body: JSON.stringify(body),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.ErrorCode || data.ErrorMessage || !data.RedirectURL) {
    throw new Error(data.ErrorMessage || `EPS could not start the payment (${res.status})`);
  }
  return { transactionId: data.TransactionId, redirectUrl: data.RedirectURL };
}

/* The only thing that decides whether a payment happened. */
async function verify(merchantTransactionId) {
  if (!configured()) throw new Error('EPS is not configured');

  const url = base() + '/v1/EPSEngine/CheckMerchantTransactionStatus?merchantTransactionId=' +
    encodeURIComponent(merchantTransactionId);

  const res = await fetch(url, {
    headers: {
      'x-hash': hash(merchantTransactionId),
      Authorization: `Bearer ${await token()}`,
    },
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`EPS verification failed (${res.status})`);
  if (data.ErrorCode || data.ErrorMessage) {
    throw new Error(data.ErrorMessage || 'EPS verification returned an error');
  }
  return data;
}

function classify(status) {
  const s = String(status || '').toLowerCase();
  if (s === 'success' || s === 'completed' || s === 'paid') return 'paid';
  if (s === 'failed' || s === 'cancelled' || s === 'canceled' || s === 'expired') return 'failed';
  return 'pending';
}

module.exports = { configured, config, newTransactionId, initialize, verify, classify, hash };
