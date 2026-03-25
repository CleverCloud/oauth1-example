import { createHmac } from "node:crypto";

const API_BASE = "https://api.clever-cloud.com";
const CONSUMER_KEY = process.env.OAUTH_CONSUMER_KEY;
const CONSUMER_SECRET = process.env.OAUTH_CONSUMER_SECRET;

if (!CONSUMER_KEY || !CONSUMER_SECRET) {
  throw new Error("Missing OAUTH_CONSUMER_KEY or OAUTH_CONSUMER_SECRET in environment");
}

// ─── OAuth1 signature helpers ───────────────────────────────────────────────

/**
 * Percent-encode a string per RFC 3986.
 * Unlike encodeURIComponent, this also encodes !'()* characters.
 * @param {string} str
 * @returns {string}
 */
function percentEncode(str) {
  return encodeURIComponent(str).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`
  );
}

/**
 * Build the OAuth1 signature base string.
 * Concatenates HTTP method, URL, and sorted parameters — all percent-encoded.
 * @param {string} method - HTTP method (GET, POST, etc.)
 * @param {string} url - Full URL without query string
 * @param {Record<string, string>} params - OAuth parameters (excluding oauth_signature)
 * @returns {string}
 */
function buildBaseString(method, url, params) {
  const sorted = Object.keys(params)
    .sort()
    .map((k) => `${percentEncode(k)}=${percentEncode(params[k])}`)
    .join("&");

  return `${method.toUpperCase()}&${percentEncode(url)}&${percentEncode(sorted)}`;
}

/**
 * Compute an HMAC-SHA512 signature and return it as base64.
 * @param {string} baseString - The signature base string
 * @param {string} [tokenSecret=""] - The token secret (empty for request token step)
 * @returns {string}
 */
function sign(baseString, tokenSecret = "") {
  const key = `${percentEncode(CONSUMER_SECRET)}&${percentEncode(tokenSecret)}`;
  return createHmac("sha512", key).update(baseString).digest("base64");
}

/**
 * Build the base OAuth parameters common to every request.
 * @returns {Record<string, string>}
 */
function baseOAuthParams() {
  return {
    oauth_consumer_key: CONSUMER_KEY,
    oauth_signature_method: "HMAC-SHA512",
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_nonce: crypto.randomUUID().replace(/-/g, ""),
    oauth_version: "1.0",
  };
}

/**
 * Format parameters as an OAuth Authorization header value.
 * @param {Record<string, string>} params
 * @returns {string}
 */
function authorizationHeader(params) {
  const pairs = Object.entries(params)
    .map(([k, v]) => `${percentEncode(k)}="${percentEncode(v)}"`)
    .join(", ");
  return `OAuth ${pairs}`;
}

/**
 * Sign OAuth parameters and POST them as query string.
 * Used for request_token and access_token endpoints.
 * @param {string} endpoint - Full API URL
 * @param {Record<string, string>} params - OAuth parameters (without signature)
 * @param {string} [tokenSecret=""] - Token secret for signing
 * @returns {Promise<URLSearchParams>} Parsed response
 */
async function postOAuth(endpoint, params, tokenSecret = "") {
  const baseString = buildBaseString("POST", endpoint, params);
  const signed = { ...params, oauth_signature: sign(baseString, tokenSecret) };

  const qs = new URLSearchParams(signed).toString();
  const res = await fetch(`${endpoint}?${qs}`, { method: "POST" });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${endpoint} failed (${res.status}): ${body}`);
  }

  return new URLSearchParams(await res.text());
}

// ─── Temporary storage for request token secrets ────────────────────────────
// These are short-lived (10 min) and only needed between steps 1 and 3.

/** @type {Map<string, string>} */
const pendingSecrets = new Map();

// ─── OAuth1 flow ────────────────────────────────────────────────────────────

/**
 * Step 1: Obtain a request token and return the Clever Cloud authorization URL.
 * @param {string} callbackUrl - Where Clever Cloud redirects after user approval
 * @returns {Promise<string>} The authorization URL to redirect the user to
 */
export async function getRequestToken(callbackUrl) {
  const params = { ...baseOAuthParams(), oauth_callback: callbackUrl };
  const data = await postOAuth(`${API_BASE}/v2/oauth/request_token_query`, params);

  const token = data.get("oauth_token");
  const secret = data.get("oauth_token_secret");

  pendingSecrets.set(token, secret);
  setTimeout(() => pendingSecrets.delete(token), 10 * 60 * 1000);

  return `${API_BASE}/v2/oauth/authorize?oauth_token=${token}`;
}

/**
 * Step 3: Exchange the request token + verifier for an access token.
 * @param {string} oauthToken - Request token from step 1
 * @param {string} oauthVerifier - Verifier code from the callback redirect
 * @returns {Promise<{token: string, secret: string}>}
 */
export async function getAccessToken(oauthToken, oauthVerifier) {
  const tokenSecret = pendingSecrets.get(oauthToken);
  if (!tokenSecret) {
    throw new Error("Unknown or expired request token");
  }
  pendingSecrets.delete(oauthToken);

  const params = {
    ...baseOAuthParams(),
    oauth_token: oauthToken,
    oauth_verifier: oauthVerifier,
  };

  const data = await postOAuth(
    `${API_BASE}/v2/oauth/access_token_query`,
    params,
    tokenSecret
  );

  return { token: data.get("oauth_token"), secret: data.get("oauth_token_secret") };
}

/**
 * Make a signed API call on behalf of the user.
 * @param {string} method - HTTP method
 * @param {string} path - API path (e.g. "/v2/self")
 * @param {{token: string, secret: string}} tokens - User's access token pair
 * @returns {Promise<Response>}
 */
export async function apiCall(method, path, tokens) {
  const url = `${API_BASE}${path}`;
  const params = { ...baseOAuthParams(), oauth_token: tokens.token };

  const baseString = buildBaseString(method, url, params);
  params.oauth_signature = sign(baseString, tokens.secret);

  return fetch(url, {
    method,
    headers: { Authorization: authorizationHeader(params) },
  });
}
