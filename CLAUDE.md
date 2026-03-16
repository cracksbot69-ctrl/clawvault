# ClawVault — Claude Code Instructions (Ralph Loop)

## Project
ClawVault is a secure, verified skill marketplace for OpenClaw — a safe alternative to ClawHub which had a supply-chain attack.

## Tech Stack
- **Backend**: Python FastAPI, SQLite, port 3001
- **Frontend**: Single HTML file with vanilla JS (no build step)
- **Scanner**: Python, in `scanner/scanner.py`
- **Deploy target**: Railway.app (free tier)

## File Structure
```
clawvault/
├── backend/main.py      — FastAPI API server
├── frontend/index.html  — Complete SPA (single file, no build)
├── scanner/scanner.py   — Security scanner
├── prd.json             — Ralph task list
├── requirements.txt     — Python deps
└── Procfile             — Railway start command
```

## How to run
```bash
pip install fastapi uvicorn pydantic
python backend/main.py
# → http://localhost:3001
```

## API Endpoints
- `GET  /api/skills` — list verified skills (?category=&q=&sort=)
- `GET  /api/skills/:id` — get one skill
- `POST /api/submit` — submit new skill (JSON body)
- `GET  /api/status/:id` — check scan status
- `GET  /api/stats` — platform stats
- `GET  /api/admin/queue` — review queue (requires Bearer token)
- `POST /api/admin/approve/:id` — approve skill
- `POST /api/admin/reject/:id` — reject skill (JSON: {reason: ""})
- `POST /api/admin/rescan/:id` — re-run scan
- `DELETE /api/admin/delete/:id` — delete skill

## Submit body format
```json
{
  "name": "my-skill",
  "description": "What it does",
  "github_url": "https://github.com/owner/repo",
  "author": "owner",
  "category": "productivity",
  "version": "1.0.0"
}
```

## Admin auth
Pass header: `Authorization: Bearer <ADMIN_TOKEN>`
Token is printed on startup and set via env var `ADMIN_TOKEN`.

## Ralph instructions
Work through prd.json user stories in order. After each story:
1. Run `python backend/main.py &` then test with curl
2. Mark story as `"passes": true` in prd.json
3. Commit with message: `feat(US-00X): <title>`
4. When ALL stories pass, output: `<promise>COMPLETE</promise>`

## Key rules
- Frontend is ONE index.html file — no npm, no build step
- Backend serves frontend on all non-/api routes
- Keep it simple — no over-engineering
- Test each endpoint with curl before marking pass
