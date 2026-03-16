# 🔒 ClawVault

**The secure, verified skill marketplace for OpenClaw.**

Built after the [ClawHub supply chain attack](https://awesomeagents.ai/news/openclaw-clawhub-malware-supply-chain/) that compromised 1,184 skills. ClawVault runs every skill through a 4-layer security pipeline before it goes live.

## Features

- ✅ **Automatic security scanning** — static analysis, sandbox execution, dependency audit
- ✅ **Author verification** — GitHub OAuth required, no anonymous uploads
- ✅ **Community review** — 3 approvals before publish
- ✅ **CVE alerts** — get notified when a skill you use has a vulnerability
- ✅ **Premium skill sales** — 90% revenue share for creators

## Quick Start

```bash
# Install a skill
openclaw skill install @clawvault/daily-briefing

# Browse skills
open https://clawvault.dev
```

## Development

```bash
# Frontend (static HTML)
open frontend/index.html

# Backend API
cd backend && python3 main.py
# API runs on http://localhost:3001

# Security Scanner
python3 scanner/scanner.py ./your-skill
```

## Deploy to Railway

1. Create a free account at [railway.app](https://railway.app)
2. Click **New Project → Deploy from GitHub repo**
3. Select this repository
4. Add environment variable: `ADMIN_TOKEN=your-secret-token`
5. Railway detects `railway.json` and `Procfile` automatically — deploy starts

```bash
# Or deploy via CLI
npm i -g @railway/cli
railway login
railway init
railway up
```

**Environment Variables:**
- `ADMIN_TOKEN` — Admin panel password (printed to logs if not set, auto-generated)

## Submit a Skill

1. Push your skill to GitHub
2. Go to clawvault.dev/submit
3. Connect GitHub
4. Automatic scan starts immediately

---

Community project · Not affiliated with OpenClaw · Built to keep the community safe 🔒
