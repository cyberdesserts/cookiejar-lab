# CookieJar Lab

**A session replay attack lab for defenders**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A self-contained, Docker-based security lab that demonstrates how **session cookie theft bypasses passwords, 2FA, and even Google OAuth**.

> Part of [CyberDesserts](https://cyberdesserts.com) - Learn Cybersecurity By Doing
> ([GitHub](https://github.com/cyberdesserts))

## What is this?

This lab shows you how stolen browser cookies let attackers bypass passwords and 2FA. You will log in with full security (password + TOTP, or Google OAuth), steal your own session cookie, and replay it to impersonate yourself without any credentials. Then you will switch to a hardened version of the same app and see exactly which defences block the attack.

## Quick Start

```bash
git clone https://github.com/CyberDesserts/cookie-jar.git
cd cookie-jar/cookiejar-lab
docker compose up --build
```

Then open:

- **Vulnerable App**: [http://localhost:3001](http://localhost:3001)
- **Hardened App**: [http://localhost:3002](http://localhost:3002)

You need [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) installed. A TOTP authenticator app (Google Authenticator, Authy, etc.) is optional but recommended for the full 2FA experience.

<details>
<summary><strong>Optional: HTTPS mode</strong></summary>

Uses [mkcert](https://github.com/FiloSottile/mkcert) for trusted local TLS certificates. This makes the lab more realistic: the vulnerable app sets `secure: true` but `httpOnly: false`, showing that HTTPS protects the wire but not the cookie store.

```bash
git clone https://github.com/CyberDesserts/cookie-jar.git
cd cookie-jar/cookiejar-lab
./setup.sh              # Generates certs, configures /etc/hosts
docker compose up --build
```

Then open:

- **Vulnerable App**: [https://cookiejar.test:3001](https://cookiejar.test:3001)
- **Hardened App**: [https://cookiejar.test:3002](https://cookiejar.test:3002)

> **Security note:** mkcert installs a local root CA on your machine. Always run `./cleanup.sh` when you're done with the lab. See [docs/security-notes.md](docs/security-notes.md) for details.

</details>

## What You'll Learn

1. **See cookie theft happen** - Log in with password + TOTP or Google OAuth, then view and copy your session cookie
2. **Replay a stolen session** - Paste the cookie into an Attack Console and watch authentication get bypassed
3. **Understand what stops it** - Switch to the hardened app and see each security control block the attack
4. **Explore interactively** - Open the Interactive Guide for visual diagrams, a JWT explorer, cookie flag heatmaps, and a searchable glossary populated with your live session data
5. **Go deeper** - Read the Concepts page for coverage of cookies, JWTs, and competing session models with security analysis

## Table of Contents

- [Lab Walkthrough](#lab-walkthrough)
  - [Part 1: The Vulnerable App](#part-1-the-vulnerable-app-port-3001)
  - [Part 2: The Hardened App](#part-2-the-hardened-app-port-3002)
- [Why Does This Work?](#why-does-this-work)
- [Google OAuth and the Same Vulnerability](#google-oauth-and-the-same-vulnerability)
- [Real-World Mitigations](#real-world-mitigations)
- [Project Structure](#project-structure)
- [Reset Lab Data](#reset-lab-data)
- [Cleanup (HTTPS Mode)](#cleanup-https-mode)
- [Documentation](#documentation)
- [Legal Disclaimer](#legal-disclaimer)
- [License](#license)

## Lab Walkthrough

### Part 1: The Vulnerable App (port 3001)

**Step 1 - Register**
Open the vulnerable app (`http://localhost:3001` or `https://cookiejar.test:3001` if using HTTPS) and create an account with username + password. You'll see a QR code - scan it with Google Authenticator or Authy to set up TOTP 2FA.

**Step 2 - Log in with 2FA**
Enter your username, password, and the 6-digit TOTP code from your authenticator app. You've now authenticated with "strong" multi-factor authentication.

**Step 3 - Visit the Cookie Vault**
Click "Cookie Vault" on the dashboard. This page shows:
- Your raw session cookie (a JWT token)
- The decoded JWT payload with your user data
- What an infostealer would extract from your browser's cookie database

**Step 4 - Copy the token**
Click "Copy Cookie to Clipboard". This simulates what infostealer malware does when it reads Chrome's cookie SQLite database.

**Step 5 - Replay the attack**
Open the "Attack Console" and paste the stolen token. Click "Replay Session". You'll see:
- Full access to the user's profile
- Auth method: password+totp (bypassed)
- No password entered, no 2FA code required

**Step 6 - Try Google OAuth**
Log out and sign in with "Google OAuth" (simulated). Pick any account on the mock consent screen. Visit Cookie Vault again - the session token has the same structure and same vulnerability.

**Step 7 - Replay the OAuth session**
Copy the OAuth session token, paste it into the Attack Console. Same result: authentication bypassed. Google OAuth protected the *login step*, not the *session*.

### Part 2: The Hardened App (port 3002)

**Step 8 - Register and log in**
Open the hardened app (`http://localhost:3002` or `https://cookiejar.test:3002` if using HTTPS). Create an account with the same flow. Log in.

**Step 9 - Try to read the cookie**
On the dashboard, notice that `document.cookie` returns an empty string. The session cookie has `httpOnly: true` - JavaScript cannot access it at all.

**Step 10 - Attempt replay**
Go to the Attack Console. Try pasting a token from the vulnerable app. The hardened app shows a **defence-by-defence breakdown** of why each control blocks the replay:
- HttpOnly: Cookie was never accessible to JavaScript
- Short-lived token: 15-minute window (vs 7 days)
- Server-side session: Session ID not in active store
- Device binding: IP/User-Agent mismatch

**Step 11 - Check the session log**
Click "Session Event Log" on the dashboard to see the audit trail - every replay attempt is logged with IP, User-Agent, and timestamp.

## Why Does This Work?

Authentication (password, 2FA, OAuth) only protects the **login step**. After successful authentication, the server issues a **session token** - typically a JWT or opaque token stored in a cookie. For subsequent requests, the server checks the session token, not the original credentials.

```
Login:     User -> [Password + 2FA] -> Server -> Session Cookie
Later:     User -> [Session Cookie]  -> Server -> "You're authenticated"
Attacker:  Attacker -> [Stolen Cookie] -> Server -> "You're authenticated"
```

The server cannot distinguish between the legitimate user presenting the cookie and an attacker presenting the same cookie.

## Google OAuth and the Same Vulnerability

Many people assume Google OAuth makes them "more secure" against this attack. Here's what actually happens:

1. User clicks "Sign in with Google"
2. Google verifies the user's identity (password, 2FA, passkeys, etc.)
3. Google redirects back with an authorization code
4. **Your app** exchanges the code for user info
5. **Your app** issues its own session cookie

Step 5 is the critical point: the session cookie issued by *your app* is no different from one issued after a password login. Google OAuth protects the authentication with Google - it does not protect the session with your app.

Infostealers don't attack Google. They attack your browser's cookie store and steal the session cookie your app issued *after* OAuth completed.

## Real-World Mitigations

| Defence | How It Helps | Standard |
|---------|-------------|----------|
| HttpOnly cookies | Prevents JavaScript access to cookies | OWASP |
| Short-lived tokens | Limits replay window | NIST 800-63B |
| Server-side sessions | Enables revocation and logout | OWASP |
| Device-bound sessions | Ties sessions to specific devices | [DBSC (Chrome)](https://github.com/nicowillis/dbsc) |
| FIDO2/Passkeys | Phishing-resistant, device-bound authentication | FIDO Alliance |
| Token binding | Cryptographically binds tokens to TLS connections | RFC 8471 |
| Continuous auth signals | Risk-based session evaluation | Zero Trust |

## Project Structure

```
cookie-jar/                          <- repository root
├── README.md                        # Repo landing page
├── .gitignore                       # Root-level ignores
├── demo/
│   └── index.html                   # Standalone interactive demo (no setup needed)
└── cookiejar-lab/
    ├── .gitignore
    ├── README.md                    # Full lab documentation (this file)
    ├── LICENSE
    ├── setup.sh                     # HTTPS setup
    ├── cleanup.sh                   # HTTPS cleanup
    ├── docker-compose.yml
    ├── certs/                       # Generated by setup.sh (gitignored)
    ├── docs/
    │   ├── lab-guide.md
    │   └── security-notes.md
    ├── vulnerable-app/
    │   ├── Dockerfile
    │   ├── package.json
    │   ├── server.js
    │   └── public/  ...
    └── hardened-app/
        ├── Dockerfile
        ├── package.json
        ├── server.js
        └── public/  ...
```

## Reset Lab Data

The SQLite database persists across Docker restarts (via named volumes). To start fresh:

**From the UI:** Click the **"Reset Lab Database"** button on either login page (bottom of the page). It asks for confirmation, then drops and recreates all tables.

**From the terminal:**

```bash
# Reset the vulnerable app
curl -X POST http://localhost:3001/api/reset-db          # HTTP mode
curl -X POST https://cookiejar.test:3001/api/reset-db    # HTTPS mode

# Reset the hardened app
curl -X POST http://localhost:3002/api/reset-db          # HTTP mode
curl -X POST https://cookiejar.test:3002/api/reset-db    # HTTPS mode
```

**Nuclear option - delete the Docker volumes entirely:**

```bash
docker compose down -v
docker compose up --build
```

## Cleanup (HTTPS Mode)

If you used `./setup.sh` to enable HTTPS, run `./cleanup.sh` when you're done:

```bash
./cleanup.sh
```

This removes the mkcert root CA from your system trust store and deletes the generated certificates. See [docs/security-notes.md](docs/security-notes.md) for more details on what mkcert does and why cleanup matters.

## Documentation

- [Lab Guide](docs/lab-guide.md) - Detailed exercises, discussion questions, and further reading
- [Security Notes](docs/security-notes.md) - mkcert safety guide and HTTPS cleanup checklist

## Legal Disclaimer

**This project is for educational and authorized security testing purposes only.**

- Run only on systems you own or have explicit permission to test
- Do not use techniques demonstrated here against production systems without authorization
- The vulnerable application is intentionally insecure - never expose it to the internet
- The authors are not responsible for misuse of this tool

This project is intended to help security professionals, students, and developers understand session security to **build better defences**.

## License

[MIT](LICENSE)

---

<p align="center">
  A <a href="https://cyberdesserts.com">CyberDesserts</a> project - Learn Cybersecurity By Doing
</p>
