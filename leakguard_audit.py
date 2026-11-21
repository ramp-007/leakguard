"""leakguard audit - pre-publication audit of a repository (PASS / WARN / BLOCK). Python standard library only.

Called as `leakguard.py audit [--history] [--json]`. Fail-closed: a check that could not run is a BLOCK (optional tools
that are not installed are a WARN). Secret values are never printed or kept: only rule, file, line, cause and fix.
Allow-list: `.leakguard-allow` (committed), one entry per line `<category>|<path glob>|<reason>`. The reason is mandatory.
Findings of the category `secret` can never be allowed.
"""
from __future__ import annotations
import fnmatch
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

PASS, WARN, BLOCK = "PASS", "WARN", "BLOCK"
ALLOW_FILE = ".leakguard-allow"
PERSONAL_RULES = ("personal-email", "private-ip", "home-directory", "tailnet-hostname", "windows-default-hostname", "mac-address", "ssh-public-key", "local-deny-words")
HOME_PATH = re.compile(r"(?:[A-Za-z]:[\\/]+Users[\\/]+|/home/|/Users/)(?!(?:Public|Default|<|\{|\$|%|user|username|name|you|example|\*)[\\/\"' ]?)[A-Za-z0-9._-]{2,}", re.I)
BLOCK_FILES = (".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_ed25519", "*.kdbx", ".npmrc", ".pypirc")
WARN_FILES = ("*.log", "*.sqlite", "*.sqlite3", "*.db", "*.bak", "*.dump", "*.sql", "*.swp", ".DS_Store", "Thumbs.db")
IMAGES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".heic")
SSH_GIT = re.compile(r"git@(?:github|gitlab|bitbucket)\.(?:com|org)$", re.I)  # ssh clone URLs, not people
EXAMPLE_ENV = re.compile(r"\.(example|sample|template)$", re.I)


@dataclass
class Finding:
    level: str
    category: str  # secret / personal / file / identity / readiness / dependency / tool / image
    file: str
    line: int
    cause: str
    fix: str

    def key(self) -> str:
        return f"{self.category}|{self.file}"


def find_tool(lg, name: str) -> str | None:
    exe = name + (".exe" if os.name == "nt" else "")
    env = os.environ.get("LEAKGUARD_" + name.upper().replace("-", "_"))
    if env:
        return env
    for d in (lg.ROOT / ".tools", lg.CENTRAL / "bin"):
        if (d / exe).exists():
            return str(d / exe)
    return shutil.which(name)


def run(cmd: list[str], cwd: Path, timeout: int = 900) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired) as e:
        return -1, f"{type(e).__name__}"


def mask_email(e: str) -> str:
    local, _, dom = e.partition("@")
    return f"{local[:1]}***@{dom}"


def load_allow(root: Path) -> list[tuple[str, str]]:
    f = root / ALLOW_FILE
    out = []
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            parts = [p.strip() for p in line.split("|")]
            if len(parts) == 3 and parts[2] and not line.lstrip().startswith("#") and parts[0] != "secret":
                out.append((parts[0], parts[1]))
    return out


def tracked(lg) -> list[str]:
    return [p for p in lg.git("ls-files", "-z").split("\0") if p]


def snapshot(lg, dest: Path) -> Path:
    """Copy of the tracked files only (what would be published): untracked / ignored files (caches, builds) are not audited."""
    for p in tracked(lg):
        src = lg.ROOT / p
        if src.is_file():
            (dest / p).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / p)
    return dest


def rel(path: str, base: Path) -> str:
    try:
        return os.path.relpath(path, base).replace("\\", "/") if os.path.isabs(path) else path
    except ValueError:
        return path


def check_secrets(lg, history: bool) -> list[Finding]:
    """gitleaks (tracked files, and history with --history) and, when installed, trufflehog (offline: no verification calls)."""
    g = lg.find_gitleaks()
    if not g:
        return [Finding(BLOCK, "tool", "-", 0, "gitleaks is not installed, so secrets were not checked", "python leakguard.py install")]
    out: list[Finding] = []
    cfg = str(lg.config_path())
    with tempfile.TemporaryDirectory() as td:
        snap = snapshot(lg, Path(td) / "tree")
        bl = find_tool(lg, "betterleaks")  # optional second engine with gitleaks-compatible config and report format
        scans = []
        for tool, exe in (("gitleaks", g), ("betterleaks", bl)):
            if exe:
                scans += [(f"{tool} tree", [exe, "dir", str(snap)], snap)] + ([(f"{tool} history", [exe, "git", str(lg.ROOT)], lg.ROOT)] if history else [])
        for label, base, root in scans:
            rep = Path(td) / f"{label.replace(' ', '-')}.json"
            code, _ = run(base + ["--config", cfg, "--redact", "--no-banner", "--report-format", "json", "--report-path", str(rep), "--exit-code", "1"], lg.ROOT)
            if code not in (0, 1) or (code == 1 and not rep.exists()):
                out.append(Finding(BLOCK, "tool", "-", 0, f"{label.split()[0]} ({label.split()[1]}) failed to run (exit {code})", "fix the installation and run again"))
                continue
            for r in json.loads(rep.read_text(encoding="utf-8") or "[]") if rep.exists() else []:
                cat = "personal" if r.get("RuleID", "") in PERSONAL_RULES else "secret"
                where = f" in commit {r['Commit'][:8]}" if label.endswith("history") and r.get("Commit") else ""
                out.append(Finding(BLOCK, cat, rel(r.get("File", "?"), root), int(r.get("StartLine", 0)), f"{r.get('RuleID', 'rule')} ({label.split()[1]}{where})",
                                   "remove it; if it was ever committed, rotate the credential and rewrite history (needs your approval)"))
        t = find_tool(lg, "trufflehog")
        if not t:
            return out + [Finding(WARN, "tool", "-", 0, "trufflehog is not installed (second secret scanner skipped)", "python leakguard.py install-audit-tools")]
        for label, args, root in [("tree", ["filesystem", str(snap)], snap)] + ([("history", ["git", "file://" + lg.ROOT.as_posix()], lg.ROOT)] if history else []):
            code, text = run([t, *args, "--json", "--no-update", "--no-verification"], lg.ROOT)
            if code not in (0, 183):
                out.append(Finding(BLOCK, "tool", "-", 0, f"trufflehog ({label}) failed to run (exit {code})", "fix the installation and run again"))
            for ln in text.splitlines():
                try:
                    d = json.loads(ln)
                except ValueError:
                    continue
                if "DetectorName" in d:
                    data = d.get("SourceMetadata", {}).get("Data", {}) or {}
                    meta = next(iter(data.values()), {}) if data else {}
                    out.append(Finding(BLOCK, "secret", rel(str(meta.get("file", "?")), root), int(meta.get("line", 0) or 0), f"trufflehog detector {d['DetectorName']} ({label})", "remove it and rotate the credential"))
    return out


def check_files(lg, history: bool) -> list[Finding]:
    names = now = tracked(lg)
    nowset = set(now)
    if history:
        names += [p for p in lg.git("log", "--all", "--name-only", "--pretty=format:", "-z").split("\0") if p.strip()]
    out = []
    for p in dict.fromkeys(names):
        base = p.replace("\\", "/").rsplit("/", 1)[-1]
        if any(fnmatch.fnmatch(base, g) for g in BLOCK_FILES) and not EXAMPLE_ENV.search(base):
            out.append(Finding(BLOCK, "file", p, 0, "file type that normally holds credentials", "git rm --cached it, add to .gitignore (if in history: rewrite history, needs your approval)"))
        elif any(fnmatch.fnmatch(base, g) for g in WARN_FILES):
            out.append(Finding(WARN, "file", p, 0, "log / database / backup / editor file", "remove it or add to .gitignore"))
        elif base.lower().endswith(IMAGES) and p in nowset:
            out.append(Finding(WARN, "image", p, 0, "image: may show names, paths, tokens or location (EXIF)", "open it and check; strip metadata"))
    return out


def check_personal(lg) -> list[Finding]:
    out = []
    for p in tracked(lg):
        f = lg.ROOT / p
        if f.suffix.lower() in IMAGES or not f.is_file() or f.stat().st_size > 2_000_000:
            continue
        try:
            lines = f.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for n, ln in enumerate(lines, 1):
            for e in lg.ANY_EMAIL.findall(ln):
                if not lg.OK_EMAIL.search(e) and not SSH_GIT.match(e):
                    out.append(Finding(BLOCK, "personal", p, n, f"e-mail address {mask_email(e)}", "replace with dev@example.com"))
            if HOME_PATH.search(ln):
                out.append(Finding(BLOCK, "personal", p, n, "personal home-directory path (reveals the local user name)", "use ~ or a placeholder path"))
            for w in lg.word_hits(ln):
                out.append(Finding(BLOCK, "personal", p, n, f"a word from your real-name list ({w[:1]}***)", "replace with a placeholder"))
    return out


def check_identity(lg) -> list[Finding]:
    out, seen = [], set()
    for ln in lg.git("log", "--all", "--format=%an|%ae|%cn|%ce").splitlines():
        for who, name, mail in (("author", *ln.split("|")[:2]), ("committer", *ln.split("|")[2:4])):
            if (who, mail) not in seen and not lg.OK_EMAIL.search(mail):
                seen.add((who, mail))
                out.append(Finding(BLOCK, "identity", "(git log)", 0, f"{who} e-mail {mask_email(mail)} is not a placeholder", "rewrite history with a placeholder identity (needs your approval)"))
    return out


def check_readiness(lg) -> list[Finding]:
    names = {p.lower() for p in tracked(lg)}
    spec = [("license", "LICENSE", BLOCK, "no license: nobody may legally use it"), ("readme", "README", WARN, "no README"),
            (".gitignore", ".gitignore", WARN, "no .gitignore"), ("security", "SECURITY.md", WARN, "no SECURITY.md (how to report vulnerabilities)")]
    out = [Finding(lv, "readiness", fname, 0, why, f"add {fname}") for key, fname, lv, why in spec
           if not any(n == key or n.startswith(key + ".") or n.startswith(key + "-") for n in names)]
    out.append(Finding(WARN, "readiness", "-", 0, "third-party code / assets / dependency licenses are not checked automatically", "review them yourself before publishing"))
    return out


def check_dependencies(lg) -> list[Finding]:
    t = find_tool(lg, "osv-scanner")
    if not t:
        return [Finding(WARN, "dependency", "-", 0, "osv-scanner is not installed (known vulnerabilities not checked)", "python leakguard.py install-audit-tools")]
    code, text = run([t, "scan", "source", "--format", "json", "-r", str(lg.ROOT)], lg.ROOT)
    try:
        data = json.loads(text) if text.strip() else {"results": []}
    except ValueError:
        return [Finding(BLOCK, "tool", "-", 0, f"osv-scanner output unreadable (exit {code})", "fix the installation and run again")]
    if code == 128:
        return []  # osv-scanner found no package manifests: nothing to check
    if code not in (0, 1):
        return [Finding(WARN, "dependency", "-", 0, f"osv-scanner could not scan (exit {code}); no lock file?", "check by hand")]
    return [Finding(WARN, "dependency", r.get("source", {}).get("path", "?"), 0, f"{p['package']['name']} {p['package']['version']}: {len(p.get('vulnerabilities', []))} known vulnerabilities",
                    "upgrade the package") for r in data.get("results", []) for p in r.get("packages", []) if p.get("vulnerabilities")]


def run_audit(lg, args: list[str]) -> int:
    history, as_json = "--history" in args, "--json" in args
    findings: list[Finding] = []
    for name, fn in (("secrets", lambda: check_secrets(lg, history)), ("files", lambda: check_files(lg, history)), ("personal", lambda: check_personal(lg)),
                     ("identity", lambda: check_identity(lg)), ("readiness", lambda: check_readiness(lg)), ("dependencies", lambda: check_dependencies(lg))):
        try:
            findings += fn()
        except Exception as e:  # fail-closed: a check that crashed is a BLOCK
            findings.append(Finding(BLOCK, "tool", "-", 0, f"check '{name}' crashed: {type(e).__name__}", "fix and run again"))
    findings = list({(f.category, f.file, f.line) if f.category in ("personal", "secret") and f.line else id(f): f for f in findings}.values())
    allow = load_allow(lg.ROOT)
    findings = [f for f in findings if f.category == "secret" or f.level == BLOCK and f.category == "tool" or not any(c == f.category and fnmatch.fnmatch(f.file, g) for c, g in allow)]
    verdict = BLOCK if any(f.level == BLOCK for f in findings) else WARN if findings else PASS
    if as_json:
        print(json.dumps({"verdict": verdict, "history": history, "findings": [f.__dict__ for f in findings]}, ensure_ascii=False, indent=2))
    else:
        for f in sorted(findings, key=lambda x: (x.level != BLOCK, x.category, x.file, x.line)):
            print(f"[{f.level}] {f.file}{':' + str(f.line) if f.line else ''}  {f.cause}\n        fix: {f.fix}")
        print(f"\nleakguard audit: {verdict}  ({sum(f.level == BLOCK for f in findings)} BLOCK, {sum(f.level == WARN for f in findings)} WARN; history {'checked' if history else 'NOT checked - add --history before publishing'})")
    return 1 if verdict == BLOCK else 0
