/**
 * CookieJar Lab - Vulnerable Application Server
 *
 * ⚠️  THIS APPLICATION IS INTENTIONALLY INSECURE  ⚠️
 * It exists solely for educational purposes to demonstrate how session
 * cookie theft bypasses passwords and 2FA/MFA.
 *
 * DO NOT deploy this in production. DO NOT use on systems you don't own.
 */

const express = require('express');
const https = require('https');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'cookiejar-vulnerable-secret-do-not-use-in-prod';

// ---------------------------------------------------------------------------
// TLS Detection - HTTPS if certs exist, HTTP otherwise
// ---------------------------------------------------------------------------

const fs = require('fs');
const CERT_DIR = process.env.CERT_PATH || '/app/certs';
const certPath = path.join(CERT_DIR, 'cert.pem');
const keyPath = path.join(CERT_DIR, 'key.pem');
const tlsEnabled = fs.existsSync(certPath) && fs.existsSync(keyPath);

// ---------------------------------------------------------------------------
// Database Setup
// ---------------------------------------------------------------------------

const DB_DIR = process.env.DB_PATH || '/app/data';
fs.mkdirSync(DB_DIR, { recursive: true });
const db = new Database(path.join(DB_DIR, 'vulnerable.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    password_hash TEXT,
    totp_secret TEXT,
    totp_enabled INTEGER DEFAULT 0,
    auth_provider TEXT DEFAULT 'local',
    oauth_id TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Mock OAuth "Database" - simulates Google's user store
// ---------------------------------------------------------------------------

const mockOAuthCodes = new Map(); // auth_code -> user profile
const mockOAuthState = new Map(); // state -> redirect info

/**
 * Mock Google OAuth users - these simulate accounts on Google's side.
 * In a real flow, Google stores these; here we mock them.
 */
const mockGoogleUsers = [
  { id: 'google-001', email: 'alice@gmail.com', name: 'Alice Chen', picture: 'https://via.placeholder.com/96' },
  { id: 'google-002', email: 'bob@gmail.com', name: 'Bob Martinez', picture: 'https://via.placeholder.com/96' },
  { id: 'google-003', email: 'carol@gmail.com', name: 'Carol Nguyen', picture: 'https://via.placeholder.com/96' },
];

// ---------------------------------------------------------------------------
// Helper: Issue JWT Cookie
// ---------------------------------------------------------------------------

/**
 * Issues a JWT session cookie with DELIBERATELY INSECURE settings.
 * In a real application, every one of these settings would be a vulnerability.
 *
 * @param {object} res - Express response object
 * @param {object} payload - Data to encode in the JWT
 * @returns {string} The signed JWT token
 */
function issueSessionCookie(res, payload) {
  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: '7d', // ⚠️ INTENTIONALLY INSECURE - 7-day session is far too long
  });

  res.cookie('session', token, {
    httpOnly: false,                        // ⚠️ INTENTIONALLY INSECURE - allows JavaScript to read the cookie
    secure: tlsEnabled,                     // ⚠️ INTENTIONALLY INSECURE - even with HTTPS, httpOnly:false means JS can still steal it
    sameSite: tlsEnabled ? 'None' : 'Lax', // ⚠️ INTENTIONALLY INSECURE - 'None' sends cookie cross-site (requires secure:true)
    maxAge: 7 * 24 * 60 * 60 * 1000,       // ⚠️ INTENTIONALLY INSECURE - 7 days
    path: '/',
  });

  return token;
}

// ---------------------------------------------------------------------------
// Middleware: Authenticate requests via JWT cookie
// ---------------------------------------------------------------------------

/**
 * Verifies the session JWT from the cookie.
 * No server-side session store - if the JWT is valid, the user is "authenticated".
 * ⚠️ INTENTIONALLY INSECURE - no session revocation, no device binding.
 */
function requireAuth(req, res, next) {
  const token = req.cookies.session;
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

// =========================================================================
// FLOW A: Username + Password + TOTP 2FA
// =========================================================================

/**
 * POST /api/register
 * Register a new user with username and password.
 * Returns a TOTP secret + QR code for 2FA setup.
 */
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Check if user exists
    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existing) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);

    // Generate TOTP secret
    const totpSecret = speakeasy.generateSecret({
      name: `CookieJar Lab (${username})`,
      issuer: 'CookieJar Lab',
    });

    // Store user
    const result = db.prepare(
      'INSERT INTO users (username, email, password_hash, totp_secret, totp_enabled, auth_provider) VALUES (?, ?, ?, ?, 1, ?)'
    ).run(username, email || `${username}@cookiejar.lab`, passwordHash, totpSecret.base32, 'local');

    // Generate QR code as data URL
    const qrDataUrl = await QRCode.toDataURL(totpSecret.otpauth_url);

    res.json({
      message: 'Registration successful',
      userId: result.lastInsertRowid,
      totp: {
        secret: totpSecret.base32,
        qrCode: qrDataUrl,
        otpauthUrl: totpSecret.otpauth_url,
      },
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

/**
 * POST /api/login
 * Authenticate with username + password + TOTP code.
 * Issues a JWT session cookie on success.
 */
app.post('/api/login', async (req, res) => {
  try {
    const { username, password, totpCode } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Look up user
    const user = db.prepare('SELECT * FROM users WHERE username = ? AND auth_provider = ?').get(username, 'local');
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const passwordValid = await bcrypt.compare(password, user.password_hash);
    if (!passwordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify TOTP if enabled
    if (user.totp_enabled) {
      if (!totpCode) {
        return res.status(400).json({ error: 'TOTP code required', requireTotp: true });
      }

      const totpValid = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token: totpCode,
        window: 4, // Allow 4 time steps of drift (2 minutes) for clock skew
      });

      if (!totpValid) {
        return res.status(401).json({ error: 'Invalid TOTP code' });
      }
    }

    // ⚠️ INTENTIONALLY INSECURE - JWT payload contains sensitive data and
    // is the ONLY thing protecting the session. No server-side record.
    const payload = {
      userId: user.id,
      username: user.username,
      email: user.email,
      authMethod: 'password+totp',
      totpVerified: true,
      issuedAt: new Date().toISOString(),
    };

    const token = issueSessionCookie(res, payload);

    res.json({
      message: 'Login successful',
      user: { id: user.id, username: user.username, email: user.email },
      authMethod: 'password+totp',
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// =========================================================================
// FLOW B: Mock Google OAuth
// =========================================================================

/**
 * GET /oauth/google/authorize
 * Simulates Google's OAuth authorization endpoint.
 * Redirects the user to a "consent" page, just like Google would.
 */
app.get('/oauth/google/authorize', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const redirectUri = req.query.redirect_uri || '/oauth/google/callback';

  // Store state for CSRF validation (mimics real OAuth)
  mockOAuthState.set(state, { redirectUri, createdAt: Date.now() });

  // Redirect to our mock consent page
  res.redirect(`/oauth/google/consent?state=${state}`);
});

/**
 * GET /oauth/google/consent
 * Simulated Google consent screen.
 * User picks which "Google account" to sign in with.
 */
app.get('/oauth/google/consent', (req, res) => {
  const { state } = req.query;

  const accountListHtml = mockGoogleUsers.map(u => `
    <div class="oauth-account" onclick="selectAccount('${u.id}', '${state}')">
      <img src="${u.picture}" alt="${u.name}" width="40" height="40">
      <div>
        <strong>${u.name}</strong><br>
        <small>${u.email}</small>
      </div>
    </div>
  `).join('');

  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Sign in | Mock Google OAuth</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #f0f0f0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .consent-box { background: white; border-radius: 12px; padding: 32px; width: 400px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); }
    .consent-box h2 { margin-bottom: 8px; color: #202124; }
    .consent-box p { color: #5f6368; margin-bottom: 20px; font-size: 14px; }
    .mock-badge { background: #fff3cd; border: 1px solid #ffc107; padding: 8px 12px; border-radius: 8px; font-size: 12px; margin-bottom: 20px; }
    .oauth-account { display: flex; align-items: center; gap: 12px; padding: 12px; border: 1px solid #dadce0; border-radius: 8px; margin-bottom: 8px; cursor: pointer; transition: background 0.2s; }
    .oauth-account:hover { background: #f8f9fa; }
    .oauth-account img { border-radius: 50%; }
  </style>
</head>
<body>
  <div class="consent-box">
    <div class="mock-badge">
      &#9888;&#65039; This is a <strong>simulated</strong> Google sign-in page.<br>
      It mirrors the real OAuth flow but runs entirely locally.
    </div>
    <h2>Choose an account</h2>
    <p>to continue to <strong>CookieJar Lab</strong></p>
    ${accountListHtml}
  </div>
  <script>
    function selectAccount(googleId, state) {
      window.location.href = '/oauth/google/approve?google_id=' + googleId + '&state=' + state;
    }
  </script>
</body>
</html>`);
});

/**
 * GET /oauth/google/approve
 * User "approved" on the consent screen. Google would now redirect back
 * to our app's callback with an authorization code.
 */
app.get('/oauth/google/approve', (req, res) => {
  const { google_id, state } = req.query;

  // Validate state
  const stateData = mockOAuthState.get(state);
  if (!stateData) {
    return res.status(400).send('Invalid OAuth state - possible CSRF attack');
  }

  // Find the mock Google user
  const googleUser = mockGoogleUsers.find(u => u.id === google_id);
  if (!googleUser) {
    return res.status(400).send('Invalid Google account');
  }

  // Generate authorization code (mimics what Google does)
  const authCode = crypto.randomBytes(20).toString('hex');
  mockOAuthCodes.set(authCode, {
    user: googleUser,
    createdAt: Date.now(),
    used: false,
  });

  // Clean up state
  mockOAuthState.delete(state);

  // Redirect back to our app's callback - exactly like real Google OAuth
  res.redirect(`/oauth/google/callback?code=${authCode}&state=${state}`);
});

/**
 * GET /oauth/google/callback
 * Our app's OAuth callback. Receives the auth code from "Google",
 * exchanges it for user info, and issues a session cookie.
 *
 * In a real app, this would make a server-to-server call to Google's
 * token endpoint. Here we simulate that exchange.
 */
app.get('/oauth/google/callback', (req, res) => {
  const { code } = req.query;

  // Exchange authorization code for user profile
  const codeData = mockOAuthCodes.get(code);
  if (!codeData || codeData.used) {
    return res.status(400).send('Invalid or expired authorization code');
  }

  // Mark code as used (one-time use, like real OAuth)
  codeData.used = true;

  const googleUser = codeData.user;

  // Create or find user in our database
  let user = db.prepare('SELECT * FROM users WHERE oauth_id = ? AND auth_provider = ?').get(googleUser.id, 'google');

  if (!user) {
    // First-time OAuth login - create user
    const result = db.prepare(
      'INSERT INTO users (username, email, auth_provider, oauth_id) VALUES (?, ?, ?, ?)'
    ).run(googleUser.name.replace(/\s/g, '').toLowerCase(), googleUser.email, 'google', googleUser.id);

    user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
  }

  // Generate mock access token (simulates what Google returns)
  const mockAccessToken = crypto.randomBytes(32).toString('hex');

  // ⚠️ INTENTIONALLY INSECURE - the session cookie issued after OAuth is
  // identical in structure and vulnerability to the password+TOTP flow.
  // This is the KEY insight: OAuth authenticates you to the app, but the
  // app then issues its OWN session token that is just as stealable.
  const payload = {
    userId: user.id,
    username: user.username,
    email: user.email,
    authMethod: 'google-oauth',
    provider: 'google',
    accessToken: mockAccessToken, // ⚠️ INTENTIONALLY INSECURE - leaking tokens in JWT
    issuedAt: new Date().toISOString(),
  };

  issueSessionCookie(res, payload);

  // Redirect to dashboard
  res.redirect('/dashboard.html');
});

// =========================================================================
// Protected API Endpoints
// =========================================================================

/**
 * GET /api/me
 * Returns the current user's profile from the JWT.
 * ⚠️ INTENTIONALLY INSECURE - all data comes from the unrevocable JWT.
 */
app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    user: req.user,
    sessionInfo: {
      issuedAt: req.user.issuedAt,
      expiresAt: new Date(req.user.exp * 1000).toISOString(),
      authMethod: req.user.authMethod,
      tokenAge: `${Math.round((Date.now() / 1000 - req.user.iat) / 60)} minutes`,
    },
  });
});

/**
 * GET /api/cookie-info
 * Returns decoded JWT information for the Cookie Vault page.
 * ⚠️ INTENTIONALLY INSECURE - exposes full token internals to the client.
 */
app.get('/api/cookie-info', requireAuth, (req, res) => {
  const token = req.cookies.session;
  const decoded = jwt.decode(token, { complete: true });

  res.json({
    raw: token,
    header: decoded.header,
    payload: decoded.payload,
    infostealerView: {
      description: 'An infostealer would extract this data from your browser\'s cookie store',
      stolenFields: {
        cookieName: 'session',
        cookieValue: token,
        domain: req.hostname,
        path: '/',
        httpOnly: false,
        secure: tlsEnabled,
      },
      chromeDbPath: '%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies',
      firefoxDbPath: '%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\cookies.sqlite',
    },
  });
});

/**
 * POST /api/replay-session
 * Attack Console endpoint. Accepts a stolen JWT and returns the session
 * data if valid. Demonstrates that a stolen cookie == a stolen session.
 *
 * ⚠️ INTENTIONALLY INSECURE - this is the whole point of the demo.
 * There is NO server-side session validation, NO device binding,
 * NO anomaly detection. If the JWT signature is valid, you're "in".
 */
app.post('/api/replay-session', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // ⚠️ INTENTIONALLY INSECURE - token is valid, so we trust it completely.
    // No check against a session store. No check against device fingerprint.
    // No check if the user has logged out. No rate limiting.
    res.json({
      success: true,
      message: 'Authentication bypassed - no password entered, no 2FA code required',
      user: {
        userId: decoded.userId,
        username: decoded.username,
        email: decoded.email,
        authMethod: decoded.authMethod,
        provider: decoded.provider || 'local',
        totpVerified: decoded.totpVerified || false,
        accessToken: decoded.accessToken || null,
      },
      session: {
        issuedAt: decoded.issuedAt,
        expiresAt: new Date(decoded.exp * 1000).toISOString(),
        remainingTime: `${Math.round((decoded.exp - Date.now() / 1000) / 3600)} hours`,
      },
      attackDetails: {
        passwordRequired: false,
        totpRequired: false,
        oauthRequired: false,
        explanation: decoded.authMethod === 'google-oauth'
          ? 'This session was created via Google OAuth. The user went through Google\'s login + possible 2FA. None of that matters - the session cookie is all you need.'
          : 'This session was created with password + TOTP 2FA. The user entered their password and a time-based code from their authenticator app. None of that matters - the session cookie is all you need.',
      },
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      const decoded = jwt.decode(token);
      res.status(401).json({
        success: false,
        error: 'Token has expired',
        expiredAt: new Date(decoded.exp * 1000).toISOString(),
        explanation: 'The session token has expired. In the real world, infostealers operate quickly - tokens are replayed within minutes of theft.',
      });
    } else if (err.name === 'JsonWebTokenError') {
      res.status(401).json({
        success: false,
        error: 'Invalid token',
        explanation: 'The JWT signature is invalid. This token was either tampered with or signed with a different secret.',
      });
    } else {
      res.status(401).json({
        success: false,
        error: 'Token validation failed',
        details: err.message,
      });
    }
  }
});

/**
 * POST /api/reset-db
 * Drops and recreates the users table - useful for resetting the lab between sessions.
 */
app.post('/api/reset-db', (req, res) => {
  try {
    db.exec('DROP TABLE IF EXISTS users');
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT,
        password_hash TEXT,
        totp_secret TEXT,
        totp_enabled INTEGER DEFAULT 0,
        auth_provider TEXT DEFAULT 'local',
        oauth_id TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      )
    `);
    res.clearCookie('session');
    res.json({ message: 'Database reset - all users removed. You can register again.' });
  } catch (err) {
    console.error('Reset error:', err);
    res.status(500).json({ error: 'Database reset failed' });
  }
});

/**
 * POST /api/logout
 * "Logs out" the user by clearing the cookie.
 * ⚠️ INTENTIONALLY INSECURE - there's no server-side session to invalidate.
 * The JWT remains valid until it expires, even after "logout".
 */
app.post('/api/logout', (req, res) => {
  res.clearCookie('session');
  res.json({
    message: 'Logged out - cookie cleared from YOUR browser',
    warning: 'But the JWT token itself is still valid! If someone copied it before you logged out, they can still use it until it expires.',
  });
});

// =========================================================================
// Start Server
// =========================================================================

if (tlsEnabled) {
  const tlsOptions = {
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
  };
  https.createServer(tlsOptions, app).listen(PORT, '0.0.0.0', () => {
    console.log(`\n🍪 CookieJar Lab - VULNERABLE App`);
    console.log(`   Running on https://cookiejar.test:${PORT} (TLS enabled)`);
    console.log(`   ⚠️  This app is INTENTIONALLY INSECURE - for education only\n`);
  });
} else {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🍪 CookieJar Lab - VULNERABLE App`);
    console.log(`   Running on http://localhost:${PORT}`);
    console.log(`   ⚠️  This app is INTENTIONALLY INSECURE - for education only\n`);
  });
}
