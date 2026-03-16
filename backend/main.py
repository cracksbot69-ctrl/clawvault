"""
ClawVault Backend API
FastAPI — läuft auf port 3001
"""
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import sqlite3, json, os, sys, hashlib, time
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent / "scanner"))
from scanner import SkillScanner

app = FastAPI(title="ClawVault API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

DB_PATH = Path(__file__).parent / "clawvault.db"
scanner = SkillScanner()

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS skills (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL UNIQUE,
                description TEXT,
                author      TEXT,
                github_url  TEXT,
                category    TEXT DEFAULT 'general',
                version     TEXT DEFAULT '1.0.0',
                score       INTEGER DEFAULT 0,
                passed_scan INTEGER DEFAULT 0,
                stars       REAL DEFAULT 0,
                installs    INTEGER DEFAULT 0,
                verified    INTEGER DEFAULT 0,
                featured    INTEGER DEFAULT 0,
                status      TEXT DEFAULT 'pending',
                created_at  TEXT DEFAULT (datetime('now')),
                updated_at  TEXT DEFAULT (datetime('now'))
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                skill_id   TEXT,
                score      INTEGER,
                passed     INTEGER,
                issues     TEXT,
                scanned_at TEXT DEFAULT (datetime('now'))
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS installs (
                skill_id   TEXT,
                ts         TEXT DEFAULT (datetime('now'))
            )
        """)
        # Demo-Skills einfügen
        demo = [
            ("skill-daily-briefing",   "daily-briefing",   "Personalized morning summary: weather, calendar, news, crypto.",        "paulkr",       "https://github.com/paulkr/oc-daily-briefing",   "productivity",  "1.2.0", 98, 1, 4.9, 3200, 1, 1, "verified"),
            ("skill-home-assistant",   "home-assistant",   "Full Home Assistant integration. Control everything via natural language.","homelab_felix","https://github.com/homelab_felix/oc-ha",         "smart-home",    "2.0.1", 95, 1, 4.8, 2100, 1, 0, "verified"),
            ("skill-crypto-alerts",    "crypto-alerts",    "Price alerts, portfolio tracking, DeFi notifications. 500+ tokens.",    "defi_dev",     "https://github.com/defi_dev/oc-crypto",          "finance",       "1.5.3", 97, 1, 4.7, 1800, 1, 0, "verified"),
            ("skill-github-digest",    "github-digest",    "Daily GitHub notification digest. PRs, issues, reviews.",               "opensrc_anna", "https://github.com/opensrc_anna/oc-github",      "developer",     "1.0.2", 100,1, 4.6, 1400, 1, 0, "verified"),
            ("skill-smart-reminders",  "smart-reminders",  "Context-aware reminders. 'remind me when BTC hits 100k' works.",        "remindbot",    "https://github.com/remindbot/oc-remind",         "productivity",  "3.1.0", 96, 1, 4.9, 5100, 1, 1, "verified"),
            ("skill-shelly-control",   "shelly-control",   "Control Shelly smart home devices. All Gen1/Gen2/Gen3.",                "iot_felix",    "https://github.com/iot_felix/oc-shelly",         "smart-home",    "1.1.0", 99, 1, 4.7,  743, 1, 0, "verified"),
            ("skill-ai-summarizer",    "ai-summarizer",    "Summarize any URL, PDF or text. Articles, research, YouTube.",          "aitools",      "https://github.com/aitools/oc-summarize",        "ai",            "2.3.1", 94, 1, 4.8, 4200, 1, 1, "verified"),
            ("skill-spotify",          "spotify-controller","Full Spotify control via natural language.",                           "musicdev",     "https://github.com/musicdev/oc-spotify",         "productivity",  "1.4.0", 97, 1, 4.6, 2900, 1, 0, "verified"),
        ]
        for row in demo:
            try:
                db.execute("""INSERT OR IGNORE INTO skills
                    (id,name,description,author,github_url,category,version,score,passed_scan,stars,installs,verified,featured,status)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", row)
            except Exception:
                pass
        db.commit()

init_db()

# ── Models ────────────────────────────────────────────────────────────────────
class SubmitRequest(BaseModel):
    name: str
    description: str
    github_url: str
    author: str
    category: str = "general"
    premium: bool = False

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/api/skills")
def list_skills(category: str = None, q: str = None, sort: str = "installs"):
    with get_db() as db:
        query = "SELECT * FROM skills WHERE status='verified'"
        params = []
        if category and category != "all":
            query += " AND category=?"; params.append(category)
        if q:
            query += " AND (name LIKE ? OR description LIKE ?)"; params += [f"%{q}%", f"%{q}%"]
        col = {"installs":"installs","stars":"stars","newest":"created_at"}.get(sort,"installs")
        query += f" ORDER BY {col} DESC"
        rows = db.execute(query, params).fetchall()
        return [dict(r) for r in rows]

@app.get("/api/skills/{skill_id}")
def get_skill(skill_id: str):
    with get_db() as db:
        row = db.execute("SELECT * FROM skills WHERE id=?", (skill_id,)).fetchone()
        if not row: raise HTTPException(404, "Skill not found")
        # Install zählen
        db.execute("INSERT INTO installs(skill_id) VALUES(?)", (skill_id,))
        db.execute("UPDATE skills SET installs=installs+1 WHERE id=?", (skill_id,))
        db.commit()
        return dict(row)

@app.post("/api/skills/submit")
def submit_skill(body: SubmitRequest):
    skill_id = "skill-" + hashlib.md5(body.name.encode()).hexdigest()[:8]
    with get_db() as db:
        existing = db.execute("SELECT id FROM skills WHERE name=?", (body.name,)).fetchone()
        if existing:
            raise HTTPException(400, "Skill name already exists")
        db.execute("""INSERT INTO skills(id,name,description,author,github_url,category,status)
                      VALUES(?,?,?,?,?,?,'pending')""",
                   (skill_id, body.name, body.description, body.author, body.github_url, body.category))
        db.commit()
    return {"skill_id": skill_id, "status": "pending", "message": "Submitted! Security scan starting..."}

@app.post("/api/skills/{skill_id}/scan")
def scan_skill(skill_id: str, github_url: str = Form(...)):
    """Scannt einen Skill von einer GitHub URL."""
    import tempfile, subprocess
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            subprocess.run(["git", "clone", "--depth=1", github_url, tmpdir],
                          capture_output=True, timeout=30)
        except Exception as e:
            raise HTTPException(500, f"Clone failed: {e}")
        result = scanner.scan_directory(tmpdir)

    with get_db() as db:
        db.execute("""INSERT INTO scan_results(skill_id,score,passed,issues)
                      VALUES(?,?,?,?)""",
                   (skill_id, result.score, int(result.passed), json.dumps(result.issues)))
        db.execute("UPDATE skills SET score=?, passed_scan=?, updated_at=datetime('now') WHERE id=?",
                   (result.score, int(result.passed), skill_id))
        db.commit()
    return result.to_dict()

@app.get("/api/stats")
def stats():
    with get_db() as db:
        total    = db.execute("SELECT COUNT(*) FROM skills WHERE status='verified'").fetchone()[0]
        installs = db.execute("SELECT SUM(installs) FROM skills").fetchone()[0] or 0
        pending  = db.execute("SELECT COUNT(*) FROM skills WHERE status='pending'").fetchone()[0]
        return {"verified_skills": total, "total_installs": installs, "pending_review": pending, "malware_incidents": 0}

@app.get("/api/install/{skill_name}")
def install_instructions(skill_name: str):
    return {
        "command": f"openclaw skill install @clawvault/{skill_name}",
        "manual": f"openclaw skill install --url https://clawvault.dev/api/skills/{skill_name}"
    }

# Serve frontend
_frontend = Path(__file__).parent.parent / "frontend"
if _frontend.exists():
    @app.get("/")
    def serve_frontend():
        return FileResponse(str(_frontend / "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=3001, reload=True)
