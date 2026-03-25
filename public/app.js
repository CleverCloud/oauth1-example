// ─── Helpers ────────────────────────────────────────────────────────────────

/** Escape HTML special characters to prevent XSS when injecting into innerHTML */
function esc(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─── Token storage ──────────────────────────────────────────────────────────
// Access tokens are stored in localStorage so the user stays connected
// across page reloads and server restarts.

const TOKEN_KEY = "cc_oauth_token";
const SECRET_KEY = "cc_oauth_secret";

function getStoredTokens() {
  const token = localStorage.getItem(TOKEN_KEY);
  const secret = localStorage.getItem(SECRET_KEY);
  return token && secret ? { token, secret } : null;
}

function storeTokens(token, secret) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(SECRET_KEY, secret);
}

function clearTokens() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(SECRET_KEY);
}

// ─── Hash capture ───────────────────────────────────────────────────────────
// After the OAuth callback, tokens are passed via the URL hash fragment.
// This keeps them out of server logs and browser history.

function captureHashTokens() {
  if (!location.hash) return;

  const params = new URLSearchParams(location.hash.slice(1));
  const token = params.get("token");
  const secret = params.get("secret");

  if (token && secret) {
    storeTokens(token, secret);
    history.replaceState(null, "", location.pathname);
  }
}

// ─── API ────────────────────────────────────────────────────────────────────

/**
 * Fetch the authenticated user's profile from the server proxy.
 * @param {{token: string, secret: string}} tokens
 * @returns {Promise<object>}
 */
async function fetchSelf(tokens) {
  const res = await fetch("/api/self", {
    headers: {
      "x-oauth-token": tokens.token,
      "x-oauth-secret": tokens.secret,
    },
  });

  const data = await res.json();

  if (!res.ok) {
    if (res.status === 401) {
      clearTokens();
      throw new Error("SESSION_EXPIRED");
    }
    throw new Error(data.error || `HTTP ${res.status}`);
  }

  return data;
}

// ─── Rendering ──────────────────────────────────────────────────────────────

const app = document.getElementById("app");

function showLoading() {
  app.innerHTML = `
    <div class="loading">
      <div class="spinner" role="status"></div>
      <span>Connecting to Clever Cloud...</span>
    </div>`;
}

/**
 * Render the profile card with structured user data.
 * @param {object} data - Response from /v2/self
 */
function showProfile(data) {
  const name = esc(data.name) || "Unnamed user";
  const avatarMarkup = data.avatar
    ? `<img class="profile-avatar" src="${esc(data.avatar)}" alt="Profile photo of ${name}">`
    : `<div class="profile-avatar"></div>`;

  /** Build a detail item only if the value is present */
  const detail = (label, value, { monospace = false, fullWidth = false } = {}) => {
    if (!value) return "";
    const valueCls = monospace ? "detail-value monospace" : "detail-value";
    const itemCls = fullWidth ? "detail-item full-width" : "detail-item";
    return `<div class="${itemCls}">
      <span class="detail-label">${label}</span>
      <span class="${valueCls}">${esc(value)}</span>
    </div>`;
  };

  app.innerHTML = `
    <div class="card profile-card">
      <div class="profile-header">
        ${avatarMarkup}
        <div class="profile-identity">
          <h2>${name}</h2>
          <span class="email">${esc(data.email)}</span>
        </div>
        <span class="profile-badge">Authenticated</span>
      </div>
      <div class="profile-details">
        ${detail("Account ID", data.id, { monospace: true, fullWidth: true })}
        ${detail("Language", data.lang)}
        ${detail("Phone", data.phone)}
        ${detail("Role", data.admin ? "Administrator" : "User")}
      </div>
      <details class="raw-response">
        <summary>View raw API response</summary>
        <pre>${esc(JSON.stringify(data, null, 2))}</pre>
      </details>
    </div>
    <div class="actions">
      <span class="endpoint">GET /v2/self</span>
      <button class="btn btn-secondary" id="logout-btn" type="button">Disconnect</button>
    </div>`;

  document.getElementById("logout-btn").addEventListener("click", logout);
}

// SVG icons used across views
const ICON_LOCK = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
</svg>`;

const ICON_SHIELD = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
</svg>`;

function showLogin(errorMessage = "") {
  let errorMarkup = "";
  if (errorMessage) {
    errorMarkup = `<div class="error-message" role="alert">${esc(errorMessage)}</div>`;
  }

  app.innerHTML = `
    ${errorMarkup}
    <div class="card login-card">
      <div class="login-icon">${ICON_LOCK}</div>
      <h2>Sign in to continue</h2>
      <p>Authorize this application to access your Clever Cloud account via OAuth1</p>
      <a href="/auth/login" class="btn" role="button">Login with Clever Cloud</a>
      <div class="login-footer">
        ${ICON_SHIELD}
        <span>Secured with OAuth 1.0a &mdash; HMAC-SHA512</span>
      </div>
    </div>`;
}

function showDisconnected() {
  app.innerHTML = `
    <div class="card disconnected-card">
      <p>You have been disconnected</p>
    </div>`;
  setTimeout(() => showLogin(), 1500);
}

function logout() {
  clearTokens();
  showDisconnected();
}

// ─── Boot ───────────────────────────────────────────────────────────────────

captureHashTokens();
const tokens = getStoredTokens();

if (tokens) {
  showLoading();
  fetchSelf(tokens)
    .then(showProfile)
    .catch((err) => {
      if (err.message === "SESSION_EXPIRED") {
        showLogin("Your session has expired. Please log in again.");
      } else {
        showLogin(`Could not reach Clever Cloud: ${err.message}`);
      }
    });
} else {
  showLogin();
}
