# CookieJar

**A hands-on session security lab showing how stolen cookies bypass passwords, 2FA, and OAuth**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](cookiejar-lab/LICENSE)

> Part of [CyberDesserts](https://cyberdesserts.com) - Learn Cybersecurity By Doing
> ([GitHub](https://github.com/CyberDesserts))

## Interactive Demo

Open [`demo/index.html`](demo/index.html) in your browser - no setup required. The demo is a standalone walkthrough that explains session replay attacks, cookie security flags, and defence strategies with interactive diagrams.

> When hosted via GitHub Pages the demo is available at the repo's Pages URL.

## Full Lab (Docker)

The full lab runs two apps side by side - a deliberately vulnerable app and a hardened app - so you can steal a session cookie and replay it, then see exactly which defences block the same attack.

```bash
git clone https://github.com/cyberdesserts/cookiejar-lab.git
cd cookiejar-lab
docker compose up --build
```

- **Vulnerable App**: [http://localhost:3001](http://localhost:3001)
- **Hardened App**: [http://localhost:3002](http://localhost:3002)

> **Start here:** [Lab Guide](cookiejar-lab/docs/lab-guide.md) - Hands-on exercises with step-by-step instructions

See [`cookiejar-lab/README.md`](cookiejar-lab/README.md) for the full walkthrough, HTTPS setup, and detailed documentation.

## License

[MIT](cookiejar-lab/LICENSE)

---

<p align="center">
  A <a href="https://cyberdesserts.com">CyberDesserts</a> project - Learn Cybersecurity By Doing
</p>
