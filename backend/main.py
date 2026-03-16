"""
ClawVault Backend — production-ready
FastAPI, SQLite, GitHub API verification, auto-scanner, admin panel
"""
import sqlite3, json, os, sys, hashlib, tempfile, subprocess, secrets
from pathlib import Path
from datetime import datetime
import urllib.request, urllib.error

from fastapi import FastAPI, HTTPException, Header, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent / "scanner"))
from scanner import SkillScanner

# ── Config ────────────────────────────────────────────────────────────────────
DB_PATH    = Path(__file__).parent / "clawvault.db"
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "clawvault-admin-" + secrets.token_hex(8))
FRONTEND   = Path(__file__).parent.parent / "frontend"

print(f"[ClawVault] Admin token: {ADMIN_TOKEN}")

app = FastAPI(title="ClawVault API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
scanner = SkillScanner()

# ── Database ──────────────────────────────────────────────────────────────────
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as c:
        c.executescript("""
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
            scan_issues TEXT DEFAULT '[]',
            reject_reason TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            updated_at  TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS installs (
            skill_id TEXT,
            ts       TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS scan_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            skill_id   TEXT,
            score      INTEGER,
            passed     INTEGER,
            issues     TEXT,
            scanned_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS reviews (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            skill_id   TEXT NOT NULL,
            author     TEXT DEFAULT 'Anonymous',
            rating     INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
            comment    TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        );
        """)
        # Demo seeds
        seeds = [
            ("skill-daily-briefing",  "daily-briefing",    "Personalized morning summary: weather, calendar, news, crypto.",         "paulkr",       "https://github.com/paulkr/oc-daily-briefing",   "productivity", "1.2.0", 98,4.9,3200,1,1,"verified"),
            ("skill-smart-reminders", "smart-reminders",   "Context-aware reminders. 'remind me when BTC hits 100k' works.",         "remindbot",    "https://github.com/remindbot/oc-remind",         "productivity", "3.1.0", 96,4.9,5100,1,1,"verified"),
            ("skill-ai-summarizer",   "ai-summarizer",     "Summarize any URL, PDF or text. Articles, research, YouTube.",           "aitools",      "https://github.com/aitools/oc-summarize",        "ai",           "2.3.1", 94,4.8,4200,1,1,"verified"),
            ("skill-home-assistant",  "home-assistant",    "Full Home Assistant integration — control everything via voice.",        "homelab_felix","https://github.com/homelab_felix/oc-ha",         "smart-home",   "2.0.1", 95,4.8,2100,1,0,"verified"),
            ("skill-crypto-alerts",   "crypto-alerts",     "Price alerts, portfolio tracking, DeFi notifications. 500+ tokens.",     "defi_dev",     "https://github.com/defi_dev/oc-crypto",          "finance",      "1.5.3", 97,4.7,1800,1,0,"verified"),
            ("skill-github-digest",   "github-digest",     "Daily GitHub notification digest — PRs, issues, reviews.",               "opensrc_anna", "https://github.com/opensrc_anna/oc-github",      "developer",    "1.0.2",100,4.6,1400,1,0,"verified"),
            ("skill-spotify",         "spotify-controller","Full Spotify control via natural language.",                             "musicdev",     "https://github.com/musicdev/oc-spotify",         "productivity", "1.4.0", 97,4.6,2900,1,0,"verified"),
            ("skill-shelly-control",  "shelly-control",    "Control Shelly smart home devices (Gen1/Gen2/Gen3).",                    "iot_felix",    "https://github.com/iot_felix/oc-shelly",         "smart-home",   "1.1.0", 99,4.7, 743,1,0,"verified"),
        ]
        for s in seeds:
            try:
                c.execute("""INSERT OR IGNORE INTO skills
                    (id,name,description,author,github_url,category,version,score,stars,installs,verified,featured,status)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", s)
            except Exception: pass
        c.commit()

init_db()

# ── Helpers ───────────────────────────────────────────────────────────────────
def require_admin(authorization: str = Header(None)):
    if authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(403, "Admin token required")

def gh_api(path: str) -> dict:
    """GitHub API call without auth (public repos only, 60 req/h)."""
    url = f"https://api.github.com{path}"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "ClawVault/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise HTTPException(422, f"GitHub API error: {e.code}")
    except Exception as e:
        raise HTTPException(503, f"GitHub unreachable: {e}")

def verify_github_repo(github_url: str, author: str) -> dict:
    """Verify repo exists, is public, and belongs to author."""
    # Parse URL: https://github.com/owner/repo
    parts = github_url.rstrip("/").split("/")
    if len(parts) < 5 or "github.com" not in parts[2]:
        raise HTTPException(422, "Invalid GitHub URL. Format: https://github.com/owner/repo")
    owner, repo = parts[3], parts[4]
    if owner.lower() != author.lower():
        raise HTTPException(422, f"Repo owner '{owner}' must match author '{author}'")
    data = gh_api(f"/repos/{owner}/{repo}")
    if data.get("private"):
        raise HTTPException(422, "Repo must be public")
    return {"owner": owner, "repo": repo, "stars": data.get("stargazers_count", 0),
            "description": data.get("description", ""), "default_branch": data.get("default_branch", "main")}

def run_scan_background(skill_id: str, github_url: str):
    """Clone repo and scan it — runs in background."""
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            r = subprocess.run(
                ["git", "clone", "--depth=1", github_url, tmpdir],
                capture_output=True, timeout=60
            )
            if r.returncode != 0:
                _update_scan(skill_id, 0, False, [{"severity":"error","file":"clone","message":"Git clone failed"}])
                return
        except subprocess.TimeoutExpired:
            _update_scan(skill_id, 0, False, [{"severity":"error","file":"clone","message":"Clone timeout"}])
            return

        result = scanner.scan_directory(tmpdir)

    _update_scan(skill_id, result.score, result.passed, result.issues)
    # Auto-approve if score >= 80
    if result.passed and result.score >= 80:
        with db() as c:
            c.execute("UPDATE skills SET status='verified', verified=1, updated_at=datetime('now') WHERE id=?", (skill_id,))
            c.commit()

def _update_scan(skill_id, score, passed, issues):
    with db() as c:
        c.execute("INSERT INTO scan_log(skill_id,score,passed,issues) VALUES(?,?,?,?)",
                  (skill_id, score, int(passed), json.dumps(issues)))
        c.execute("""UPDATE skills SET score=?, passed_scan=?, scan_issues=?,
                     status=CASE WHEN ? AND score>=80 THEN 'verified'
                                 WHEN NOT ? THEN 'failed'
                                 ELSE 'review' END,
                     updated_at=datetime('now') WHERE id=?""",
                  (score, int(passed), json.dumps(issues), passed, passed, skill_id))
        c.commit()

# ── Models ────────────────────────────────────────────────────────────────────
class SubmitBody(BaseModel):
    name:        str
    description: str
    github_url:  str
    author:      str
    category:    str = "general"
    version:     str = "1.0.0"

class AdminAction(BaseModel):
    reason: str = ""

# ── Public Routes ─────────────────────────────────────────────────────────────
@app.get("/api/skills")
def list_skills(category: str = None, q: str = None, sort: str = "installs"):
    with db() as c:
        sql = "SELECT * FROM skills WHERE status='verified'"
        params = []
        if category and category != "all":
            sql += " AND category=?"; params.append(category)
        if q:
            sql += " AND (name LIKE ? OR description LIKE ? OR author LIKE ?)"; params += [f"%{q}%"]*3
        col = {"installs":"installs","stars":"stars","score":"score","newest":"created_at"}.get(sort,"installs")
        sql += f" ORDER BY featured DESC, {col} DESC"
        return [dict(r) for r in c.execute(sql, params).fetchall()]

@app.get("/api/skills/{skill_id}")
def get_skill(skill_id: str):
    with db() as c:
        row = c.execute("SELECT * FROM skills WHERE id=?", (skill_id,)).fetchone()
        if not row: raise HTTPException(404, "Skill not found")
        c.execute("UPDATE skills SET installs=installs+1 WHERE id=?", (skill_id,))
        c.execute("INSERT INTO installs(skill_id) VALUES(?)", (skill_id,))
        c.commit()
        return dict(row)

@app.post("/api/submit")
async def submit_skill(body: SubmitBody, bg: BackgroundTasks):
    # 1. Sanitize name
    name = body.name.lower().replace(" ", "-").strip()
    if len(name) < 3 or len(name) > 50:
        raise HTTPException(422, "Skill name must be 3–50 characters")

    # 2. Verify GitHub repo
    gh = verify_github_repo(body.github_url, body.author)

    skill_id = "skill-" + hashlib.sha256(f"{body.author}/{name}".encode()).hexdigest()[:10]

    with db() as c:
        if c.execute("SELECT id FROM skills WHERE name=?", (name,)).fetchone():
            raise HTTPException(409, f"Skill '{name}' already exists")
        c.execute("""INSERT INTO skills(id,name,description,author,github_url,category,version,stars,status)
                     VALUES(?,?,?,?,?,?,?,?,'scanning')""",
                  (skill_id, name, body.description, body.author, body.github_url,
                   body.category, body.version, gh["stars"]))
        c.commit()

    # 3. Scan in background
    bg.add_task(run_scan_background, skill_id, body.github_url)

    return {
        "skill_id": skill_id,
        "status":   "scanning",
        "message":  "Submitted! Security scan running (usually < 60s). Auto-approved if score ≥ 80.",
        "track_url": f"/api/status/{skill_id}"
    }

@app.get("/api/status/{skill_id}")
def skill_status(skill_id: str):
    with db() as c:
        row = c.execute("SELECT id,name,status,score,passed_scan,scan_issues FROM skills WHERE id=?",
                        (skill_id,)).fetchone()
        if not row: raise HTTPException(404, "Skill not found")
        return dict(row)

@app.get("/api/stats")
def stats():
    with db() as c:
        return {
            "verified_skills":  c.execute("SELECT COUNT(*) FROM skills WHERE status='verified'").fetchone()[0],
            "total_installs":   c.execute("SELECT COALESCE(SUM(installs),0) FROM skills").fetchone()[0],
            "pending_review":   c.execute("SELECT COUNT(*) FROM skills WHERE status IN ('pending','review','scanning')").fetchone()[0],
            "failed_scans":     c.execute("SELECT COUNT(*) FROM skills WHERE status='failed'").fetchone()[0],
        }

@app.get("/api/new")
def new_skills(limit: int = 6):
    """Most recently verified skills."""
    with db() as c:
        rows = c.execute(
            "SELECT * FROM skills WHERE status='verified' ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

@app.get("/api/skills/by-name/{name}")
def get_skill_by_name(name: str):
    """Lookup skill by name slug (for /skills/{name} URLs)."""
    with db() as c:
        row = c.execute("SELECT * FROM skills WHERE name=? AND status='verified'", (name,)).fetchone()
        if not row:
            raise HTTPException(404, "Skill not found")
        return dict(row)

@app.get("/api/trending")
def trending():
    """Top 6 skills by installs in last 7 days, falls back to all-time."""
    with db() as c:
        rows = c.execute("""
            SELECT s.*, COUNT(i.skill_id) as recent_installs
            FROM skills s
            LEFT JOIN installs i ON i.skill_id = s.id
              AND i.ts > datetime('now', '-7 days')
            WHERE s.status='verified'
            GROUP BY s.id
            ORDER BY recent_installs DESC, s.installs DESC
            LIMIT 6
        """).fetchall()
        return [dict(r) for r in rows]

@app.get("/api/skills/{skill_id}/reviews")
def get_reviews(skill_id: str):
    with db() as c:
        rows = c.execute(
            "SELECT * FROM reviews WHERE skill_id=? ORDER BY created_at DESC LIMIT 20",
            (skill_id,)
        ).fetchall()
        return [dict(r) for r in rows]

class ReviewBody(BaseModel):
    author: str = "Anonymous"
    rating: int
    comment: str = ""

@app.post("/api/skills/{skill_id}/review")
def post_review(skill_id: str, body: ReviewBody):
    if not 1 <= body.rating <= 5:
        raise HTTPException(422, "Rating must be 1-5")
    with db() as c:
        row = c.execute("SELECT id FROM skills WHERE id=? AND status='verified'", (skill_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Skill not found")
        c.execute(
            "INSERT INTO reviews(skill_id,author,rating,comment) VALUES(?,?,?,?)",
            (skill_id, (body.author or "Anonymous")[:50], body.rating, (body.comment or "")[:500])
        )
        # Recalculate avg stars
        avg = c.execute("SELECT AVG(rating) FROM reviews WHERE skill_id=?", (skill_id,)).fetchone()[0]
        c.execute("UPDATE skills SET stars=ROUND(?,1) WHERE id=?", (avg or 0, skill_id))
        c.commit()
    return {"ok": True}

class ReportBody(BaseModel):
    reason: str = ""

@app.post("/api/skills/{skill_id}/report")
def report_skill(skill_id: str, body: ReportBody):
    """Log a community report for a skill (stored for admin review)."""
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, skill_id TEXT, reason TEXT, created_at TEXT DEFAULT (datetime('now')))")
        c.execute("INSERT INTO reports(skill_id,reason) VALUES(?,?)", (skill_id, (body.reason or "")[:300]))
        c.commit()
    return {"ok": True}

@app.get("/api/categories")
def categories():
    with db() as c:
        rows = c.execute("SELECT category, COUNT(*) as n FROM skills WHERE status='verified' GROUP BY category").fetchall()
        return [dict(r) for r in rows]

# ── Admin Routes ──────────────────────────────────────────────────────────────
@app.get("/api/admin/queue")
def admin_queue(authorization: str = Header(None)):
    require_admin(authorization)
    with db() as c:
        rows = c.execute("SELECT * FROM skills WHERE status IN ('pending','review','scanning','failed') ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

@app.post("/api/admin/approve/{skill_id}")
def admin_approve(skill_id: str, authorization: str = Header(None)):
    require_admin(authorization)
    with db() as c:
        c.execute("UPDATE skills SET status='verified', verified=1, updated_at=datetime('now') WHERE id=?", (skill_id,))
        c.commit()
    return {"ok": True}

@app.post("/api/admin/reject/{skill_id}")
def admin_reject(skill_id: str, body: AdminAction, authorization: str = Header(None)):
    require_admin(authorization)
    with db() as c:
        c.execute("UPDATE skills SET status='rejected', reject_reason=?, updated_at=datetime('now') WHERE id=?",
                  (body.reason, skill_id))
        c.commit()
    return {"ok": True}

@app.delete("/api/admin/delete/{skill_id}")
def admin_delete(skill_id: str, authorization: str = Header(None)):
    require_admin(authorization)
    with db() as c:
        c.execute("DELETE FROM skills WHERE id=?", (skill_id,))
        c.commit()
    return {"ok": True}

@app.post("/api/admin/rescan/{skill_id}")
def admin_rescan(skill_id: str, bg: BackgroundTasks, authorization: str = Header(None)):
    require_admin(authorization)
    with db() as c:
        row = c.execute("SELECT github_url FROM skills WHERE id=?", (skill_id,)).fetchone()
        if not row: raise HTTPException(404)
        c.execute("UPDATE skills SET status='scanning' WHERE id=?", (skill_id,))
        c.commit()
    bg.add_task(run_scan_background, skill_id, row["github_url"])
    return {"ok": True, "message": "Rescan started"}

# ── Serve Frontend ────────────────────────────────────────────────────────────
if FRONTEND.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")

    @app.get("/", response_class=HTMLResponse)
    @app.get("/{path:path}", response_class=HTMLResponse)
    def serve_frontend(path: str = ""):
        return FileResponse(str(FRONTEND / "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=3001, reload=True)
