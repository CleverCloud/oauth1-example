import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname, resolve } from "node:path";
import { getRequestToken, getAccessToken, apiCall } from "./oauth.js";

const PORT = parseInt(process.env.PORT || "8080");
const HOST = process.env.APP_HOST || `localhost:${PORT}`;
const PROTOCOL = HOST.includes("localhost") ? "http" : "https";
const BASE_URL = `${PROTOCOL}://${HOST}`;

// ─── Static file serving ────────────────────────────────────────────────────

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

const PUBLIC_DIR = join(import.meta.dirname, "public");

/**
 * Serve a static file from the public/ directory.
 * Uses path.resolve to prevent directory traversal attacks.
 * @param {import("node:http").ServerResponse} res
 * @param {string} filePath - Path relative to public/
 */
async function serveStatic(res, filePath) {
  const fullPath = resolve(PUBLIC_DIR, filePath);

  // Ensure the resolved path is still within the public directory
  if (!fullPath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end("Forbidden");
    return;
  }

  const mime = MIME_TYPES[extname(fullPath)] || "application/octet-stream";

  try {
    const content = await readFile(fullPath);
    res.writeHead(200, { "Content-Type": mime });
    res.end(content);
  } catch {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not Found");
  }
}

// ─── Response helpers ───────────────────────────────────────────────────────

/**
 * Send a JSON response.
 * @param {import("node:http").ServerResponse} res
 * @param {unknown} data
 * @param {number} [status=200]
 */
function sendJSON(res, data, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

/**
 * Send a redirect response.
 * @param {import("node:http").ServerResponse} res
 * @param {string} location
 */
function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

// ─── Route handlers ─────────────────────────────────────────────────────────

/** GET /auth/login — Start OAuth1 flow */
async function handleLogin(_req, res) {
  try {
    const callbackUrl = `${BASE_URL}/auth/callback`;
    const authorizeUrl = await getRequestToken(callbackUrl);
    redirect(res, authorizeUrl);
  } catch (err) {
    console.error("Login error:", err);
    sendJSON(res, { error: err.message }, 500);
  }
}

/** GET /auth/callback — Exchange verifier for access token */
async function handleCallback(req, res) {
  const url = new URL(req.url, BASE_URL);
  const oauthToken = url.searchParams.get("oauth_token");
  const oauthVerifier = url.searchParams.get("oauth_verifier");

  if (!oauthToken || !oauthVerifier) {
    sendJSON(res, { error: "Missing oauth_token or oauth_verifier" }, 400);
    return;
  }

  try {
    const tokens = await getAccessToken(oauthToken, oauthVerifier);
    // Pass tokens via URL hash (never sent to server, never logged)
    const hash = `token=${encodeURIComponent(tokens.token)}&secret=${encodeURIComponent(tokens.secret)}`;
    redirect(res, `${BASE_URL}/#${hash}`);
  } catch (err) {
    console.error("Callback error:", err);
    sendJSON(res, { error: err.message }, 500);
  }
}

/** GET /api/self — Proxy authenticated request to Clever Cloud */
async function handleSelf(req, res) {
  const token = req.headers["x-oauth-token"];
  const secret = req.headers["x-oauth-secret"];

  if (!token || !secret) {
    sendJSON(res, { error: "Missing token headers" }, 401);
    return;
  }

  try {
    const ccRes = await apiCall("GET", "/v2/self", { token, secret });
    const data = await ccRes.json();
    sendJSON(res, data, ccRes.status);
  } catch (err) {
    console.error("API call error:", err);
    sendJSON(res, { error: err.message }, 500);
  }
}

// ─── Router ─────────────────────────────────────────────────────────────────

const routes = {
  "GET /auth/login": handleLogin,
  "GET /auth/callback": handleCallback,
  "GET /api/self": handleSelf,
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url, BASE_URL);
  const routeKey = `${req.method} ${url.pathname}`;

  // API and auth routes
  const handler = routes[routeKey];
  if (handler) {
    await handler(req, res);
    return;
  }

  // Static files: serve index.html for "/" or matching file from public/
  const filePath = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  await serveStatic(res, filePath);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server listening on http://0.0.0.0:${PORT}`);
});
