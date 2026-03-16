"""
ClawVault Security Scanner
Scannt OpenClaw Skills auf Schadcode bevor sie live gehen.
"""
import ast, re, json, os, subprocess, sys
from pathlib import Path
from dataclasses import dataclass, field

@dataclass
class ScanResult:
    passed: bool
    score: int          # 0-100 (100 = sicher)
    issues: list[dict]  = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    info: list[str]     = field(default_factory=list)

    def to_dict(self):
        return {
            "passed": self.passed,
            "score": self.score,
            "issues": self.issues,
            "warnings": self.warnings,
            "info": self.info,
        }

# ── Gefährliche Patterns ──────────────────────────────────────────────────────
DANGEROUS_PATTERNS = [
    # Code-Execution
    (r'\beval\s*\(',              "HIGH",   "eval() detected — arbitrary code execution risk"),
    (r'\bexec\s*\(',              "HIGH",   "exec() detected — arbitrary code execution risk"),
    (r'__import__\s*\(',         "HIGH",   "Dynamic import detected"),
    (r'subprocess\.call\s*\(',   "MEDIUM", "subprocess.call() — command execution"),
    (r'os\.system\s*\(',         "MEDIUM", "os.system() — shell execution"),
    (r'os\.popen\s*\(',          "MEDIUM", "os.popen() — shell execution"),
    # Netzwerk zu unbekannten Hosts
    (r'https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)', "MEDIUM", "Outbound HTTP call to external host"),
    (r'socket\.connect\s*\(',    "MEDIUM", "Raw socket connection"),
    # Verschleierung
    (r'base64\.b64decode',       "HIGH",   "base64 decode — possible payload obfuscation"),
    (r'\\x[0-9a-fA-F]{2}',      "MEDIUM", "Hex-encoded strings detected"),
    (r'chr\(\d+\)',              "MEDIUM", "chr() calls — possible obfuscation"),
    # Daten-Exfiltration
    (r'open\([^)]+["\']w["\']', "LOW",    "File write detected"),
    (r'shutil\.rmtree',          "HIGH",   "shutil.rmtree — recursive file deletion"),
    (r'os\.remove\s*\(',         "LOW",    "File deletion detected"),
    # Credentials
    (r'["\']sk-[a-zA-Z0-9]{20,}', "HIGH", "Hardcoded API key detected"),
    (r'password\s*=\s*["\'][^"\']{6,}', "HIGH", "Hardcoded password detected"),
    (r'secret\s*=\s*["\'][^"\']{8,}',   "HIGH", "Hardcoded secret detected"),
    # JS specific
    (r'Function\s*\(',           "HIGH",   "Function constructor — eval-equivalent"),
    (r'setTimeout\(["\']',       "HIGH",   "String-based setTimeout — eval-equivalent"),
    (r'require\(["\']child_process', "HIGH", "child_process module — command execution"),
    (r'require\(["\']fs["\']',   "LOW",    "fs module — file system access"),
]

# Typosquatting: bekannte Pakete + ähnlich klingende
LEGIT_PACKAGES = {"axios","express","react","lodash","moment","chalk","dotenv","fastapi","requests","numpy","pandas"}
def check_typosquatting(name: str) -> bool:
    for legit in LEGIT_PACKAGES:
        if legit != name and levenshtein(legit, name) <= 2 and len(name) > 3:
            return True
    return False

def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b): a, b = b, a
    row = list(range(len(b)+1))
    for i, ca in enumerate(a):
        new_row = [i+1]
        for j, cb in enumerate(b):
            new_row.append(min(row[j+1]+1, new_row[j]+1, row[j]+(ca!=cb)))
        row = new_row
    return row[-1]

# ── Scanner Klasse ────────────────────────────────────────────────────────────
class SkillScanner:
    def scan_directory(self, path: str) -> ScanResult:
        p = Path(path)
        if not p.exists():
            return ScanResult(passed=False, score=0, issues=[{"level":"HIGH","msg":f"Path not found: {path}"}])

        issues = []
        warnings = []
        info = []

        # Alle Code-Dateien
        code_files = list(p.rglob("*.py")) + list(p.rglob("*.js")) + list(p.rglob("*.ts"))
        if not code_files:
            info.append("No code files found")

        for file in code_files:
            try:
                content = file.read_text(encoding="utf-8", errors="ignore")
                file_issues = self._scan_content(content, str(file.relative_to(p)))
                issues.extend(file_issues)
            except Exception as e:
                warnings.append(f"Could not read {file.name}: {e}")

        # package.json / requirements.txt
        pkg_json = p / "package.json"
        if pkg_json.exists():
            try:
                pkg = json.loads(pkg_json.read_text())
                deps = {**pkg.get("dependencies",{}), **pkg.get("devDependencies",{})}
                for dep in deps:
                    if check_typosquatting(dep):
                        issues.append({"level":"HIGH","file":"package.json","msg":f"Possible typosquat: '{dep}'"})
                info.append(f"package.json: {len(deps)} dependencies")
            except Exception:
                pass

        req_txt = p / "requirements.txt"
        if req_txt.exists():
            for line in req_txt.read_text().splitlines():
                pkg_name = re.split(r'[>=<!]', line.strip())[0].lower()
                if pkg_name and check_typosquatting(pkg_name):
                    issues.append({"level":"HIGH","file":"requirements.txt","msg":f"Possible typosquat: '{pkg_name}'"})

        # Score berechnen
        deductions = {"HIGH": 25, "MEDIUM": 10, "LOW": 3}
        score = max(0, 100 - sum(deductions.get(i["level"],5) for i in issues))
        passed = score >= 60 and not any(i["level"] == "HIGH" for i in issues)

        info.append(f"Scanned {len(code_files)} file(s)")
        return ScanResult(passed=passed, score=score, issues=issues, warnings=warnings, info=info)

    def scan_file(self, path: str) -> ScanResult:
        p = Path(path)
        if not p.exists():
            return ScanResult(passed=False, score=0, issues=[{"level":"HIGH","msg":f"File not found: {path}"}])
        content = p.read_text(encoding="utf-8", errors="ignore")
        issues = self._scan_content(content, p.name)
        deductions = {"HIGH": 25, "MEDIUM": 10, "LOW": 3}
        score = max(0, 100 - sum(deductions.get(i["level"],5) for i in issues))
        passed = score >= 60 and not any(i["level"] == "HIGH" for i in issues)
        return ScanResult(passed=passed, score=score, issues=issues)

    def _scan_content(self, content: str, filename: str) -> list[dict]:
        issues = []
        for pattern, level, msg in DANGEROUS_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                issues.append({"level": level, "file": filename, "msg": msg, "count": len(matches)})
        return issues

# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = SkillScanner()
    result = scanner.scan_directory(path)

    print(f"\n{'='*50}")
    print(f"  ClawVault Security Scanner")
    print(f"{'='*50}")
    print(f"  Path:   {path}")
    print(f"  Score:  {result.score}/100")
    print(f"  Status: {'✓ PASSED' if result.passed else '✗ FAILED'}")
    print(f"{'='*50}\n")

    for item in result.info:
        print(f"  ℹ  {item}")

    if result.warnings:
        print()
        for w in result.warnings:
            print(f"  ⚠  {w}")

    if result.issues:
        print()
        for issue in result.issues:
            icon = {"HIGH":"🔴","MEDIUM":"🟡","LOW":"🔵"}.get(issue["level"],"⚪")
            print(f"  {icon} [{issue['level']}] {issue['file']}: {issue['msg']}")

    print()
    if result.passed:
        print("  ✓ Ready for community review\n")
    else:
        print("  ✗ Fix issues before submitting\n")

    sys.exit(0 if result.passed else 1)
