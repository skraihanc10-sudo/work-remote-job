/* ---------------------------------------------------------------------------
   Sign in with Google. The only way into the site.

   The authorization code flow, by hand - no library. The steps:

     1. Send the visitor to Google with a random `state` we also put in a
        cookie. On the way back the two must match, which is what stops
        somebody handing a victim a pre-made sign-in link.
     2. Google returns a code. We exchange it for tokens over TLS, server to
        server, using the client secret.
     3. The id_token is a JWT. Because it came straight from Google's token
        endpoint over a verified TLS connection - not via the browser - the
        payload can be trusted without checking the signature. We still check
        the audience and expiry, so a token minted for a different app is not
        accepted.

   Nothing here is stored beyond the Google account id, the email, the name and
   the picture URL. No password ever exists, so none can leak.
   --------------------------------------------------------------------------- */

const crypto = require('crypto');

const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';

function config() {
  return {
    clientId: process.env.GOOGLE_CLIENT_ID || '',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    // Must match a redirect URI registered in the Google Cloud console exactly.
    redirectUri: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:4700/auth/google/callback',
  };
}

function configured() {
  const c = config();
  return Boolean(c.clientId && c.clientSecret);
}

function newState() {
  return crypto.randomBytes(24).toString('base64url');
}

function authUrl(state) {
  const c = config();
  const params = new URLSearchParams({
    client_id: c.clientId,
    redirect_uri: c.redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    // Ask every time which account to use. People here often have several and
    // silently reusing the last one is how the wrong account gets created.
    prompt: 'select_account',
  });
  return `${AUTH_URL}?${params.toString()}`;
}

function decodeSegment(segment) {
  return JSON.parse(Buffer.from(segment.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
}

async function exchange(code) {
  const c = config();
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: c.clientId,
      client_secret: c.clientSecret,
      redirect_uri: c.redirectUri,
      grant_type: 'authorization_code',
    }),
  });

  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(body.error_description || body.error || `Google refused the sign-in (${res.status})`);
  }
  if (!body.id_token) throw new Error('Google did not return an identity token');

  const parts = String(body.id_token).split('.');
  if (parts.length !== 3) throw new Error('Google returned a malformed identity token');
  const claims = decodeSegment(parts[1]);

  if (claims.aud !== c.clientId) throw new Error('That sign-in was issued for a different app');
  if (claims.iss !== 'https://accounts.google.com' && claims.iss !== 'accounts.google.com') {
    throw new Error('That sign-in did not come from Google');
  }
  if (Number(claims.exp) * 1000 < Date.now()) throw new Error('That sign-in expired. Try again.');
  if (!claims.email) throw new Error('Google did not share an email address');

  // A Google account with an unverified address is not an identity we can hold
  // anybody to, which is the entire reason sign-in is Google-only.
  if (claims.email_verified === false || claims.email_verified === 'false') {
    throw new Error('That Google account has not verified its email address.');
  }

  return {
    sub: String(claims.sub),
    email: String(claims.email).toLowerCase(),
    emailVerified: 1,
    name: String(claims.name || claims.email.split('@')[0]),
    picture: claims.picture ? String(claims.picture) : null,
  };
}

module.exports = { configured, config, newState, authUrl, exchange };
