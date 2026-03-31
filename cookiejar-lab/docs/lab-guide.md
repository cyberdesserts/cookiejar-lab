# CookieJar Lab - Lab Guide

> [Home](../../README.md) | [Lab Docs](../README.md) | [Demo](https://cyberdesserts.github.io/cookiejar-lab/demo/)

## Overview

This lab demonstrates a fundamental gap in web security: **authentication protects the login, but not the session**. Passwords, TOTP 2FA, and even Google OAuth all stop at the moment the server issues a session cookie. After that, the cookie IS the identity.

## Prerequisites

- Docker and Docker Compose installed
- A TOTP authenticator app (Google Authenticator, Authy, 1Password, etc.)
- A modern web browser with DevTools (Chrome recommended)

## Lab Exercises

### Exercise 1: Understanding Session Cookies

**Objective**: See what a session cookie contains and how the browser stores it.

1. Start the lab: `docker compose up`
2. Open the vulnerable app (`http://localhost:3001` or `https://cookiejar.test:3001` in HTTPS mode)
3. Register a user  - scan the QR code with your authenticator
4. Log in with username + password + TOTP code
5. Open browser DevTools (F12) → Application → Cookies
6. Find the `session` cookie  - notice:
   - `HttpOnly` is unchecked (false)
   - `SameSite` is None
   - `Expires` is 7 days from now
7. Click "Cookie Vault" in the step bar
8. Compare what you see in DevTools with what the Cookie Vault shows

**Key takeaway**: The session cookie is a JWT containing your full identity. JavaScript can read it because httpOnly is false.

### Exercise 2: Cookie Theft via JavaScript

**Objective**: Demonstrate how infostealers read cookies.

1. While logged in on the vulnerable app, open the browser console (F12 → Console)
2. Type: `document.cookie`
3. You'll see the full session JWT  - this is exactly what infostealer malware reads
4. Now open the hardened app (`http://localhost:3002` or `https://cookiejar.test:3002`) in a new tab
5. Log in and try the same: `document.cookie`
6. Result: empty string  - httpOnly prevents access

**Key takeaway**: httpOnly is the first line of defence against JavaScript-based cookie theft.

### Exercise 3: Session Replay Attack

**Objective**: Impersonate a user using only their stolen session cookie.

1. On the vulnerable app, go to Cookie Vault and click "Copy Cookie"
2. Open the Attack Console (or open it in an incognito window for extra realism)
3. Paste the token and click "Replay Session"
4. Observe: full user profile returned, no password or 2FA required
5. The banner confirms: "Authentication bypassed"

**Key takeaway**: A valid session token IS authentication. The server cannot tell the difference between the real user and an attacker holding the same token.

### Exercise 4: Google OAuth  - Same Vulnerability

**Objective**: Show that OAuth doesn't protect the session.

1. Log out of the vulnerable app
2. Click "Sign in with Google" and pick any mock account
3. After redirect, go to Cookie Vault
4. Notice: the JWT payload says `authMethod: "google-oauth"` and includes a mock access token
5. Copy this cookie and paste it into the Attack Console
6. Same result  - authentication bypassed

**Key takeaway**: Google OAuth protects the login flow (Google verified the user). But your app still issues its own session cookie, and that cookie is just as stealable.

### Exercise 5: Hardened Defences

**Objective**: See each security control in action.

1. Copy a token from the vulnerable app's Cookie Vault
2. Open the hardened app's Attack Console (`/attack-console.html` on the hardened app)
3. Paste the vulnerable app's token and click "Attempt Replay"
4. Read the defence-by-defence breakdown:
   - **HttpOnly**: Cookie was never accessible to JS
   - **Token expiry**: 15 minutes vs 7 days
   - **Server-side session**: Session ID not found in hardened app's store
   - **Device binding**: IP/UA mismatch

5. Now register and log in on the hardened app
6. Try to copy the session cookie  - you can't (httpOnly)
7. Check the Session Event Log from the dashboard  - see your login event and any replay attempts

### Exercise 6: Session Revocation

**Objective**: Compare logout behaviour.

1. On the vulnerable app: log in, copy the session token, log out
2. Paste the token into the Attack Console  - **it still works** (JWT is self-contained, logout only cleared the browser cookie)
3. On the hardened app: the server marks the session as inactive in the database
4. Even if you somehow had the token, the server would reject it

**Key takeaway**: Without server-side session tracking, "logout" is cosmetic  - the token lives on.

### Exercise 7: Audit Trail (Bonus)

**Objective**: See anomaly detection in action.

1. On the hardened app, log in and go to Dashboard
2. Click "Session Event Log"  - see the `session_created` event
3. Go to Attack Console and attempt a replay with any token
4. Go back to Session Event Log  - see the replay attempt logged with IP, User-Agent, and timestamp
5. In production, these logs would feed into a SIEM for automated alerting

## Discussion Questions

1. If httpOnly prevents JavaScript from reading cookies, how do real infostealers steal them?
   - *Answer: They read the browser's cookie database file directly from disk  - it's an SQLite file at a known path.*

2. Does HTTPS (the `secure` flag) prevent cookie theft by infostealers?
   - *Answer: No. The `secure` flag prevents the cookie from being sent over HTTP (protecting against network sniffing), but infostealers read the cookie from the filesystem, not from the network. This lab demonstrates this directly in HTTPS mode: the vulnerable app sets `secure: true` but `httpOnly: false`, so `document.cookie` still returns the full JWT despite HTTPS being active.*

3. What is Device-Bound Session Credentials (DBSC)?
   - *Answer: A Chrome proposal that binds session cookies to a device's TPM, making them unexportable. Even if malware reads the cookie value, it can't be used on another machine.*

4. Why are passkeys (FIDO2) considered more resistant to this attack?
   - *Answer: Passkeys involve a cryptographic challenge-response tied to the specific device and origin. However, they protect the authentication step  - the session cookie issued afterward is still a potential target. The key difference is that passkeys can be combined with token binding to create a fully bound session.*

5. In a zero-trust architecture, how would continuous authentication help?
   - *Answer: Instead of trusting the session cookie for its entire lifetime, the server continuously evaluates risk signals (IP changes, behaviour anomalies, device posture) and can demand re-authentication or terminate the session mid-flight.*

## Further Reading

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Chrome Device-Bound Session Credentials](https://github.com/nicowillis/dbsc)
- [NIST SP 800-63B: Authentication & Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Token Binding (RFC 8471)](https://tools.ietf.org/html/rfc8471)
- [FIDO2/WebAuthn Specification](https://fidoalliance.org/fido2/)

---

<p align="center">
  A <a href="https://cyberdesserts.com">CyberDesserts</a> project - Learn Cybersecurity By Doing
</p>
