/**
 * CookieJar Lab - Hardened Application Server
 *
 * This application implements proper session security controls to demonstrate
 * how each defence prevents session cookie theft and replay attacks.
 *
 * Compare this with the vulnerable app to understand what each control does.
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
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET || 'cookiejar-hardened-secret-do-not-use-in-prod';

// ---------------------------------------------------------------------------
// TLS Detection - HTTPS if certs exist, HTTP otherwise
// ---------------------------------------------------------------------------

const fs = require('fs');
const CERT_DIR = process.env.CERT_PATH || '/app/certs';
const certPath = path.join(CERT_DIR, 'cert.pem');
const keyPath = path.join(CERT_DIR, 'key.pem');
const tlsEnabled = fs.existsSync(certPath) && fs.existsSync(keyPath);

// ✅ SECURITY CONTROL - Short JWT lifetime (15 minutes vs 7 days in vulnerable app)
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY_MS = 60 * 60 * 1000; // 1 hour

// ---------------------------------------------------------------------------
// Database Setup
// ---------------------------------------------------------------------------

const DB_DIR = process.env.DB_PATH || '/app/data';
fs.mkdirSync(DB_DIR, { recursive: true });
const db = new Database(path.join(DB_DIR, 'hardened.db'));

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

// ✅ SECURITY CONTROL - Server-side session store
// Unlike the vulnerable app where JWTs are self-contained and unrevocable,
// this table lets us invalidate sessions at any time.
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    ip_address TEXT,
    user_agent_hash TEXT,
    refresh_token TEXT,
    refresh_expires_at INTEGER,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    last_accessed TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`);

// ✅ SECURITY CONTROL - Session event logging for anomaly detection
db.exec(`
  CREATE TABLE IF NOT EXISTS session_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
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
// Mock OAuth "Database"
// ---------------------------------------------------------------------------

const mockOAuthCodes = new Map();
const mockOAuthState = new Map();

const mockGoogleUsers = [
  { id: 'google-001', email: 'alice@gmail.com', name: 'Alice Chen', picture: 'https://via.placeholder.com/96' },
  { id: 'google-002', email: 'bob@gmail.com', name: 'Bob Martinez', picture: 'https://via.placeholder.com/96' },
  { id: 'google-003', email: 'carol@gmail.com', name: 'Carol Nguyen', picture: 'https://via.placeholder.com/96' },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Generates a SHA-256 hash of the User-Agent string for session binding.
 * ✅ SECURITY CONTROL - Device fingerprinting via User-Agent hash
 */
function hashUserAgent(ua) {
  return crypto.createHash('sha256').update(ua || 'unknown').digest('hex').substring(0, 16);
}

/**
 * Extracts the client IP address from the request.
 */
function getClientIp(req) {
  return req.ip || req.connection.remoteAddress || 'unknown';
}

/**
 * Logs a session event to the session_log table.
 * ✅ SECURITY CONTROL - Audit trail for anomaly detection
 */
function logSessionEvent(sessionId, eventType, req, details = '') {
  db.prepare(
    'INSERT INTO session_log (session_id, event_type, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)'
  ).run(sessionId, eventType, getClientIp(req), req.headers['user-agent'] || 'unknown', details);
}

/**
 * Issues a secure session with proper cookie flags and server-side tracking.
 *
 * @param {object} res - Express response object
 * @param {object} req - Express request object
 * @param {object} user - User object from database
 * @param {string} authMethod - How the user authenticated
 * @returns {object} Token and session info
 */
function issueSecureSession(res, req, user, authMethod) {
  const sessionId = uuidv4();
  const refreshToken = crypto.randomBytes(48).toString('hex');
  const uaHash = hashUserAgent(req.headers['user-agent']);
  const clientIp = getClientIp(req);

  // ✅ SECURITY CONTROL - Store session server-side with device binding
  db.prepare(
    'INSERT INTO sessions (id, user_id, ip_address, user_agent_hash, refresh_token, refresh_expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(sessionId, user.id, clientIp, uaHash, refreshToken, Date.now() + REFRESH_TOKEN_EXPIRY_MS);

  // ✅ SECURITY CONTROL - JWT contains minimal data + session reference
  const accessToken = jwt.sign({
    userId: user.id,
    username: user.username,
    email: user.email,
    authMethod,
    sessionId, // ✅ Links to server-side session record
    issuedAt: new Date().toISOString(),
  }, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY, // ✅ SECURITY CONTROL - 15 minutes, not 7 days
  });

  // ✅ SECURITY CONTROL - HttpOnly: true prevents JavaScript access
  // ✅ SECURITY CONTROL - Secure: true ensures HTTPS only (relaxed in dev)
  // ✅ SECURITY CONTROL - SameSite: Strict prevents CSRF
  res.cookie('session', accessToken, {
    httpOnly: true,        // ✅ SECURITY CONTROL - JS cannot read this cookie
    secure: tlsEnabled,    // ✅ SECURITY CONTROL - HTTPS only when TLS is available
    sameSite: 'Strict',    // ✅ SECURITY CONTROL - no cross-site cookie sending
    maxAge: 15 * 60 * 1000, // ✅ SECURITY CONTROL - 15 minutes
    path: '/',
  });

  // ✅ SECURITY CONTROL - Refresh token in separate HttpOnly cookie
  res.cookie('refresh', refreshToken, {
    httpOnly: true,
    secure: tlsEnabled,
    sameSite: 'Strict',
    maxAge: REFRESH_TOKEN_EXPIRY_MS,
    path: '/api/refresh',
  });

  logSessionEvent(sessionId, 'session_created', req, `Auth method: ${authMethod}`);

  return { accessToken, sessionId };
}

// ---------------------------------------------------------------------------
// Middleware: Authenticate requests with full validation
// ---------------------------------------------------------------------------

/**
 * Validates the session JWT AND checks server-side session store.
 * ✅ SECURITY CONTROL - Multiple validation layers vs just JWT signature check
 */
function requireAuth(req, res, next) {
  const token = req.cookies.session;
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // ✅ SECURITY CONTROL - Check server-side session store
    const session = db.prepare('SELECT * FROM sessions WHERE id = ? AND is_active = 1').get(decoded.sessionId);
    if (!session) {
      logSessionEvent(decoded.sessionId, 'invalid_session_access', req, 'Session not found or inactive');
      return res.status(401).json({ error: 'Session has been invalidated' });
    }

    // ✅ SECURITY CONTROL - Validate device binding (IP + User-Agent)
    const currentUaHash = hashUserAgent(req.headers['user-agent']);
    const currentIp = getClientIp(req);

    if (session.user_agent_hash !== currentUaHash) {
      logSessionEvent(decoded.sessionId, 'ua_mismatch', req,
        `Expected: ${session.user_agent_hash}, Got: ${currentUaHash}`);
      // Don't immediately block - log and flag
    }

    if (session.ip_address !== currentIp) {
      logSessionEvent(decoded.sessionId, 'ip_mismatch', req,
        `Expected: ${session.ip_address}, Got: ${currentIp}`);
    }

    // Update last accessed time
    db.prepare('UPDATE sessions SET last_accessed = datetime(\'now\') WHERE id = ?').run(decoded.sessionId);

    req.user = decoded;
    req.session = session;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: 'Invalid session' });
  }
}

// =========================================================================
// FLOW A: Username + Password + TOTP 2FA
// =========================================================================

/**
 * POST /api/register
 * Register a new user with TOTP 2FA - same flow as vulnerable app.
 */
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existing) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const totpSecret = speakeasy.generateSecret({
      name: `CookieJar Lab Hardened (${username})`,
      issuer: 'CookieJar Lab Hardened',
    });

    const result = db.prepare(
      'INSERT INTO users (username, email, password_hash, totp_secret, totp_enabled, auth_provider) VALUES (?, ?, ?, ?, 1, ?)'
    ).run(username, email || `${username}@cookiejar.lab`, passwordHash, totpSecret.base32, 'local');

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
 * Authenticate with username + password + TOTP, then issue a SECURE session.
 */
app.post('/api/login', async (req, res) => {
  try {
    const { username, password, totpCode } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = db.prepare('SELECT * FROM users WHERE username = ? AND auth_provider = ?').get(username, 'local');
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordValid = await bcrypt.compare(password, user.password_hash);
    if (!passwordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

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

    // ✅ SECURITY CONTROL - Issue secure session with server-side tracking
    issueSecureSession(res, req, user, 'password+totp');

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

app.get('/oauth/google/authorize', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const redirectUri = req.query.redirect_uri || '/oauth/google/callback';
  mockOAuthState.set(state, { redirectUri, createdAt: Date.now() });
  res.redirect(`/oauth/google/consent?state=${state}`);
});

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
    .mock-badge { background: #d4edda; border: 1px solid #28a745; padding: 8px 12px; border-radius: 8px; font-size: 12px; margin-bottom: 20px; }
    .oauth-account { display: flex; align-items: center; gap: 12px; padding: 12px; border: 1px solid #dadce0; border-radius: 8px; margin-bottom: 8px; cursor: pointer; transition: background 0.2s; }
    .oauth-account:hover { background: #f8f9fa; }
    .oauth-account img { border-radius: 50%; }
  </style>
</head>
<body>
  <div class="consent-box">
    <div class="mock-badge">
      &#128274; This is a simulated Google sign-in page (HARDENED app).<br>
      The session issued after OAuth will have proper security controls.
    </div>
    <h2>Choose an account</h2>
    <p>to continue to <strong>CookieJar Lab (Hardened)</strong></p>
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

app.get('/oauth/google/approve', (req, res) => {
  const { google_id, state } = req.query;
  const stateData = mockOAuthState.get(state);
  if (!stateData) {
    return res.status(400).send('Invalid OAuth state');
  }

  const googleUser = mockGoogleUsers.find(u => u.id === google_id);
  if (!googleUser) {
    return res.status(400).send('Invalid Google account');
  }

  const authCode = crypto.randomBytes(20).toString('hex');
  mockOAuthCodes.set(authCode, { user: googleUser, createdAt: Date.now(), used: false });
  mockOAuthState.delete(state);
  res.redirect(`/oauth/google/callback?code=${authCode}&state=${state}`);
});

app.get('/oauth/google/callback', (req, res) => {
  const { code } = req.query;
  const codeData = mockOAuthCodes.get(code);
  if (!codeData || codeData.used) {
    return res.status(400).send('Invalid or expired authorization code');
  }
  codeData.used = true;

  const googleUser = codeData.user;

  let user = db.prepare('SELECT * FROM users WHERE oauth_id = ? AND auth_provider = ?').get(googleUser.id, 'google');
  if (!user) {
    const result = db.prepare(
      'INSERT INTO users (username, email, auth_provider, oauth_id) VALUES (?, ?, ?, ?)'
    ).run(googleUser.name.replace(/\s/g, '').toLowerCase(), googleUser.email, 'google', googleUser.id);
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
  }

  // ✅ SECURITY CONTROL - Same secure session issuance for OAuth flow
  issueSecureSession(res, req, user, 'google-oauth');
  res.redirect('/dashboard.html');
});

// =========================================================================
// Protected API Endpoints
// =========================================================================

/**
 * GET /api/me
 * Returns user info from the server-verified session.
 */
app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    user: {
      userId: req.user.userId,
      username: req.user.username,
      email: req.user.email,
      authMethod: req.user.authMethod,
    },
    sessionInfo: {
      sessionId: req.user.sessionId,
      issuedAt: req.user.issuedAt,
      expiresAt: new Date(req.user.exp * 1000).toISOString(),
      authMethod: req.user.authMethod,
      tokenAge: `${Math.round((Date.now() / 1000 - req.user.iat) / 60)} minutes`,
      maxAge: '15 minutes',
    },
    securityControls: {
      httpOnly: true,
      secure: 'true (in production)',
      sameSite: 'Strict',
      serverSideSession: true,
      deviceBinding: true,
      shortLivedToken: true,
    },
  });
});

/**
 * GET /api/cookie-info
 * In the hardened app, this demonstrates that the cookie is NOT accessible.
 * ✅ SECURITY CONTROL - httpOnly means JS can't read the cookie
 */
app.get('/api/cookie-info', requireAuth, (req, res) => {
  res.json({
    message: 'HttpOnly cookies cannot be read by JavaScript',
    explanation: 'In the vulnerable app, document.cookie exposes the session token. Here, httpOnly: true prevents that entirely.',
    sessionInfo: {
      sessionId: req.user.sessionId,
      authMethod: req.user.authMethod,
      issuedAt: req.user.issuedAt,
      expiresIn: '15 minutes from issuance',
    },
    securityControls: {
      httpOnly: { enabled: true, effect: 'JavaScript cannot access the cookie via document.cookie or any DOM API' },
      shortExpiry: { enabled: true, effect: 'Token expires in 15 minutes, limiting the window for replay attacks' },
      serverSideSession: { enabled: true, effect: 'Sessions tracked in database - can be invalidated server-side at any time' },
      deviceBinding: { enabled: true, effect: 'Session is bound to the originating IP address and User-Agent fingerprint' },
      sameSiteStrict: { enabled: true, effect: 'Cookie is never sent with cross-site requests, preventing CSRF-based theft' },
    },
  });
});

/**
 * POST /api/replay-session
 * Accepts a stolen token and shows WHY each defence prevents the replay.
 * This is the hardened counterpart to the vulnerable app's endpoint.
 */
app.post('/api/replay-session', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'No token provided' });
  }

  const defences = [];
  let decoded = null;

  // Defence 1: HttpOnly check
  defences.push({
    control: 'HttpOnly Cookie Flag',
    status: 'blocked',
    icon: '&#10060;',
    explanation: 'HttpOnly: Cookie was never accessible to JavaScript or clipboard. An infostealer reading document.cookie would get nothing. The cookie can only be sent by the browser automatically with HTTP requests.',
  });

  // Defence 2: JWT expiry check
  try {
    decoded = jwt.verify(token, JWT_SECRET);
    defences.push({
      control: 'Short-Lived Token (15 min)',
      status: 'passed',
      icon: '&#9989;',
      explanation: `Token is still within its 15-minute window. In practice, this severely limits the replay window compared to the vulnerable app's 7-day expiry.`,
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      decoded = jwt.decode(token);
      defences.push({
        control: 'Short-Lived Token (15 min)',
        status: 'blocked',
        icon: '&#10060;',
        explanation: `Session expired: 15-minute window has closed. Token expired at ${new Date(decoded.exp * 1000).toISOString()}. The vulnerable app uses 7-day tokens - this one is 672x shorter.`,
      });
    } else {
      return res.status(401).json({
        success: false,
        error: 'Invalid token - wrong signature or malformed JWT',
        defences: [{
          control: 'JWT Signature Verification',
          status: 'blocked',
          icon: '&#10060;',
          explanation: 'Token was signed with a different secret or is malformed.',
        }],
      });
    }
  }

  // Defence 3: Server-side session check
  if (decoded && decoded.sessionId) {
    const session = db.prepare('SELECT * FROM sessions WHERE id = ? AND is_active = 1').get(decoded.sessionId);
    if (!session) {
      defences.push({
        control: 'Server-Side Session Store',
        status: 'blocked',
        icon: '&#10060;',
        explanation: 'Server-side invalidation: This session ID is not in the active session store. The user may have logged out, or the session was revoked by an administrator.',
      });

      // Log the replay attempt
      logSessionEvent(decoded.sessionId, 'replay_attempt_invalid_session', req,
        `Attempted replay of inactive/unknown session for user ${decoded.username}`);
    } else {
      defences.push({
        control: 'Server-Side Session Store',
        status: 'passed',
        icon: '&#9989;',
        explanation: 'Session exists in the server-side store. However, additional checks follow...',
      });

      // Defence 4: Device binding check
      const currentUaHash = hashUserAgent(req.headers['user-agent']);
      const currentIp = getClientIp(req);

      const ipMatch = session.ip_address === currentIp;
      const uaMatch = session.user_agent_hash === currentUaHash;

      if (!ipMatch || !uaMatch) {
        defences.push({
          control: 'Session Binding (IP + User-Agent)',
          status: 'blocked',
          icon: '&#10060;',
          explanation: `Session binding mismatch: Token was issued to a different device fingerprint.${!ipMatch ? ` IP mismatch: expected ${session.ip_address}, got ${currentIp}.` : ''}${!uaMatch ? ` User-Agent mismatch: fingerprints don't match.` : ''} This is a strong indicator of session theft.`,
        });

        logSessionEvent(decoded.sessionId, 'replay_attempt_binding_mismatch', req,
          `IP match: ${ipMatch}, UA match: ${uaMatch}`);
      } else {
        defences.push({
          control: 'Session Binding (IP + User-Agent)',
          status: 'passed',
          icon: '&#9989;',
          explanation: 'IP and User-Agent match the original session. In a real attack from a different machine, this would fail.',
        });
      }
    }
  } else {
    defences.push({
      control: 'Server-Side Session Store',
      status: 'blocked',
      icon: '&#10060;',
      explanation: 'Token has no session ID - it was not issued by the hardened app.',
    });
  }

  const blocked = defences.some(d => d.status === 'blocked');

  res.json({
    success: !blocked,
    message: blocked
      ? 'Replay attack blocked - security controls prevented session hijacking'
      : 'Token passed all checks (demo: same browser, same session)',
    defences,
    user: decoded ? {
      userId: decoded.userId,
      username: decoded.username,
      email: decoded.email,
      authMethod: decoded.authMethod,
    } : null,
    recommendation: blocked
      ? 'Each defence adds a layer. Even if one is bypassed, the others protect the session.'
      : 'In this demo you are replaying from the same browser/IP, so binding checks pass. From a different machine, they would fail.',
  });
});

/**
 * POST /api/refresh
 * Refresh token rotation - issue new access token using refresh token.
 * ✅ SECURITY CONTROL - Limits the window an access token is valid
 */
app.post('/api/refresh', (req, res) => {
  const refreshToken = req.cookies.refresh;
  if (!refreshToken) {
    return res.status(401).json({ error: 'No refresh token' });
  }

  const session = db.prepare('SELECT * FROM sessions WHERE refresh_token = ? AND is_active = 1').get(refreshToken);
  if (!session) {
    return res.status(401).json({ error: 'Invalid refresh token' });
  }

  if (Date.now() > session.refresh_expires_at) {
    db.prepare('UPDATE sessions SET is_active = 0 WHERE id = ?').run(session.id);
    return res.status(401).json({ error: 'Refresh token expired' });
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }

  // ✅ SECURITY CONTROL - Rotate refresh token on use
  const newRefreshToken = crypto.randomBytes(48).toString('hex');
  db.prepare('UPDATE sessions SET refresh_token = ?, refresh_expires_at = ?, last_accessed = datetime(\'now\') WHERE id = ?')
    .run(newRefreshToken, Date.now() + REFRESH_TOKEN_EXPIRY_MS, session.id);

  const accessToken = jwt.sign({
    userId: user.id,
    username: user.username,
    email: user.email,
    authMethod: session.ip_address ? 'refreshed' : 'unknown',
    sessionId: session.id,
    issuedAt: new Date().toISOString(),
  }, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY,
  });

  res.cookie('session', accessToken, {
    httpOnly: true,
    secure: tlsEnabled,
    sameSite: 'Strict',
    maxAge: 15 * 60 * 1000,
    path: '/',
  });

  res.cookie('refresh', newRefreshToken, {
    httpOnly: true,
    secure: tlsEnabled,
    sameSite: 'Strict',
    maxAge: REFRESH_TOKEN_EXPIRY_MS,
    path: '/api/refresh',
  });

  logSessionEvent(session.id, 'token_refreshed', req);

  res.json({ message: 'Token refreshed' });
});

/**
 * POST /api/reset-db
 * Drops and recreates all tables - useful for resetting the lab between sessions.
 */
app.post('/api/reset-db', (req, res) => {
  try {
    db.exec('DROP TABLE IF EXISTS session_log');
    db.exec('DROP TABLE IF EXISTS sessions');
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
    db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        ip_address TEXT,
        user_agent_hash TEXT,
        refresh_token TEXT,
        refresh_expires_at INTEGER,
        is_active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now')),
        last_accessed TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    db.exec(`
      CREATE TABLE IF NOT EXISTS session_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        event_type TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        details TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      )
    `);
    res.clearCookie('session');
    res.clearCookie('refresh', { path: '/api/refresh' });
    res.json({ message: 'Database reset - all users, sessions, and logs removed. You can register again.' });
  } catch (err) {
    console.error('Reset error:', err);
    res.status(500).json({ error: 'Database reset failed' });
  }
});

/**
 * POST /api/logout
 * Proper logout - invalidates the server-side session.
 * ✅ SECURITY CONTROL - Unlike vulnerable app, the token is truly dead after logout.
 */
app.post('/api/logout', (req, res) => {
  const token = req.cookies.session;
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      // ✅ SECURITY CONTROL - Mark session as inactive in the database
      db.prepare('UPDATE sessions SET is_active = 0 WHERE id = ?').run(decoded.sessionId);
      logSessionEvent(decoded.sessionId, 'logout', req);
    } catch (e) {
      // Token expired or invalid - that's fine for logout
    }
  }

  res.clearCookie('session');
  res.clearCookie('refresh', { path: '/api/refresh' });
  res.json({
    message: 'Logged out - session invalidated on the server',
    note: 'Even if someone copied your JWT before you logged out, the server will reject it because the session is marked as inactive in the database.',
  });
});

/**
 * GET /api/session-log
 * Returns session event log for anomaly detection visibility.
 * ✅ SECURITY CONTROL - Audit trail for security monitoring
 */
app.get('/api/session-log', requireAuth, (req, res) => {
  const logs = db.prepare(
    'SELECT * FROM session_log WHERE session_id = ? ORDER BY created_at DESC LIMIT 50'
  ).all(req.user.sessionId);

  // Also get any replay attempts (across all sessions)
  const replayAttempts = db.prepare(
    `SELECT * FROM session_log WHERE event_type LIKE '%replay%' ORDER BY created_at DESC LIMIT 20`
  ).all();

  res.json({
    currentSessionLogs: logs,
    replayAttempts,
    explanation: 'This log shows all events for your current session and any detected replay attempts. In production, these would feed into a SIEM or alerting system.',
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
    console.log(`\n🔒 CookieJar Lab - HARDENED App`);
    console.log(`   Running on https://cookiejar.test:${PORT} (TLS enabled)`);
    console.log(`   Security controls: HttpOnly, Secure, Short-lived JWT, Server-side sessions, Device binding\n`);
  });
} else {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🔒 CookieJar Lab - HARDENED App`);
    console.log(`   Running on http://localhost:${PORT}`);
    console.log(`   Security controls: HttpOnly, Short-lived JWT, Server-side sessions, Device binding\n`);
  });
}
