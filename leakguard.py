#!/usr/bin/env python3
# leakguard-managed: generated copy of the leakguard engine; refresh with `leakguard.py init --update` from the leakguard repo
"""leakguard - keep personal information out of git history. Python standard library only.

Use in a repository (these are what the hooks / CI call):
  staged            check the staged changes (pre-commit)
  message <file>    check a commit message (commit-msg)
  push [remote]     refuse pushes to public GitHub repositories (or ones not confirmed private), then check every commit
                    about to be pushed; reads the pre-push hook's stdin
  all               check the whole history (CI); only commits after .leakguard-baseline if that file exists
  baseline          accept the history up to HEAD as reviewed (writes .leakguard-baseline)
  install           fetch gitleaks (checksum verified) and enable the hooks of this repo

Set up other repositories / this machine (run from a copy of the leakguard repo):
  init [path]       put the harness into a repository: engine, rules, hooks, CI workflow, ignore rules, hooks path
                    (--update refreshes files previously generated; --no-identity keeps git user.email as is;
                    --private writes .leakguard-profile so that host names and private/Tailscale IPs are allowed)
  setup-global      copy the engine to ~/.config/leakguard and set git's init.templateDir so that every new
                    `git init` / `git clone` gets the hooks
  setup-agents      rules for the Codex CLI (~/.codex/AGENTS.md); other agents read the repo's AGENTS.md that `init` writes
  setup-claude      Claude Code integration (idempotent): skill, rules block in ~/.claude/CLAUDE.md, SessionStart hook
  pull-words <host> merge another machine's real-name list into this one over ssh (never through GitHub)
  selftest          check that a brand-new repository on this machine is protected
  install-audit-tools  fetch TruffleHog, osv-scanner and Betterleaks (pinned, checksum verified) for `audit`
  guard-tool        Claude Code PreToolUse hook: audit before `gh repo edit --visibility public`, `gh release create` ... (deny on BLOCK, ask otherwise)
  approve-publish   (the person only) after a clean audit, allow ONE push of the current HEAD to a public GitHub repository within an hour
  audit [--history] [--json]  pre-publication audit (PASS / WARN / BLOCK): secrets, personal info, files, identities, readiness, dependencies
  survey [dir ...]  list the git repositories under the given directories (default: cwd) and whether each has the harness
  session-check     for editor/agent start-up hooks: print a warning when the current repo has no harness

What is checked
  1. gitleaks: default secret rules plus .gitleaks.toml (e-mail addresses, private/Tailscale IPs, home directories,
     *.ts.net, Windows default host names, MAC addresses; placeholders are allow-listed).
  2. Your own real names (host names, user names, IPs ...): one per line in .leakwords of the repo and in
     ~/.config/leakguard/words. Neither file is ever committed. Checked in diffs, file names, messages, identities.
  3. Commit identity: author/committer e-mail must be a placeholder (@example.com) or a GitHub noreply address.
  4. Push target: a push to a PUBLIC GitHub repository is refused (looked up with `gh`; unknown = refused) unless the person ran
     `approve-publish` for exactly these commits within the last hour (one push; needs a clean audit).

Profiles: "strict" (default; everything above) and "private" (.leakguard-profile contains `private`, and every GitHub
remote is confirmed private/internal - anything unclear falls back to strict). Private allows private/Tailscale IPs,
*.ts.net and host names (.leakwords lines are then ignored unless written `always:<word>`). It still blocks secrets,
e-mail addresses, home-directory paths, MAC addresses and SSH public keys.
"""
from __future__ import annotations
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "1"
GITLEAKS_VERSION = "8.30.1"
SELF = Path(__file__).resolve()
CLAUDE_HOME = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
CENTRAL = Path(os.environ.get("LEAKGUARD_HOME") or Path.home() / ".config" / "leakguard")
ZERO = "0" * 40
BLOCK_BEGIN, BLOCK_END = "<!-- leakguard:begin (managed by leakguard.py; edit the templates in the leakguard repo, do not edit this block here) -->", "<!-- leakguard:end -->"
MANAGED = "leakguard-managed"  # marker in generated files
# placeholders that may appear as identity / in messages
OK_EMAIL = re.compile(r"@(?:example\.(?:com|org|net)|users\.noreply\.github\.com)$|^noreply@anthropic\.com$", re.I)
ANY_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
DEFAULT_IDENTITY = ("Dev", "dev@example.com")


def _run(args, cwd=None) -> str:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout


def write_lf(path: Path, text: str) -> None:
    path.write_bytes(text.encode("utf-8"))  # Path.write_text(newline=) needs Python 3.10; macOS ships 3.9


def toplevel(path: Path | str = ".") -> Path | None:
    out = _run(["git", "rev-parse", "--show-toplevel"], cwd=str(path)).strip()
    return Path(out) if out else None


ROOT: Path = toplevel() or Path.cwd()


def set_root(p: Path) -> None:
    global ROOT, _profile_cache
    ROOT = p
    _profile_cache = None


def git(*args: str) -> str:
    return _run(["git", *args], cwd=str(ROOT))


# ---------------------------------------------------------------- profile (strict / private)
PROFILE_FILE = ".leakguard-profile"  # committed marker: its content is "private"
PRIVATE_RULES = ("private-ip", "tailnet-hostname", "windows-default-hostname")  # rules the private profile relaxes
_profile_cache: str | None = None


def wants_private() -> bool:
    env = os.environ.get("LEAKGUARD_PROFILE", "").strip().lower()
    if env:
        return env == "private"
    f = ROOT / PROFILE_FILE
    return f.exists() and f.read_text(encoding="utf-8").strip().lower() == "private"


def _remotes_private() -> bool:
    """True when no GitHub remote is public or unconfirmed. CI passes LEAKGUARD_VISIBILITY (the repository's own visibility)."""
    vis = os.environ.get("LEAKGUARD_VISIBILITY", "").strip().lower()
    if vis:
        return vis in ("private", "internal")
    for remote in git("remote").split():
        slug = github_slug(git("remote", "get-url", "--push", remote).strip())
        if slug and github_visibility(*slug) not in ("private", "internal"):
            return False
    return True


def profile() -> str:
    """'private' only if the repo asks for it AND it is confirmed private (or has no GitHub remote); anything unclear is 'strict'."""
    global _profile_cache
    if _profile_cache is None:
        _profile_cache = "private" if wants_private() and _remotes_private() else "strict"
    return _profile_cache


# ---------------------------------------------------------------- real names
def words() -> list[str]:
    """Real names to refuse. The private profile only refuses lines written as `always:<word>`; strict refuses all."""
    private = profile() == "private"
    out: list[str] = []
    for f in (ROOT / ".leakwords", CENTRAL / "words"):
        if not f.exists():
            continue
        for line in f.read_text(encoding="utf-8").splitlines():
            w = line.strip()
            if not w or w.startswith("#"):
                continue
            always = w.lower().startswith("always:")
            w = w[len("always:"):].strip() if always else w
            if w and (always or not private):
                out.append(w)
    return list(dict.fromkeys(out))


def word_hits(text: str) -> list[str]:
    low = text.lower()
    return sorted({w for w in words() if w.lower() in low})


# ---------------------------------------------------------------- gitleaks binary
def find_gitleaks() -> str | None:
    if os.environ.get("LEAKGUARD_GITLEAKS"):
        return os.environ["LEAKGUARD_GITLEAKS"]
    exe = "gitleaks.exe" if os.name == "nt" else "gitleaks"
    for d in (ROOT / ".tools", CENTRAL / "bin"):
        if (d / exe).exists():
            return str(d / exe)
    return shutil.which("gitleaks")


def _asset_suffix() -> str:
    sysname = {"Windows": "windows", "Linux": "linux", "Darwin": "darwin"}.get(platform.system(), "")
    m = platform.machine().lower()
    arch = "arm64" if m in ("arm64", "aarch64") else "x64" if m in ("amd64", "x86_64") else ""
    if not sysname or not arch:
        raise SystemExit(f"leakguard: no gitleaks build known for {platform.system()} {platform.machine()}; install gitleaks yourself and put it on PATH")
    return f"{sysname}_{arch}." + ("zip" if sysname == "windows" else "tar.gz")


def install_gitleaks(dest: Path | None = None) -> str:
    dest = dest or CENTRAL / "bin"
    base = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/"
    asset = f"gitleaks_{GITLEAKS_VERSION}_{_asset_suffix()}"
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        blob = Path(td) / asset
        sums = urllib.request.urlopen(base + f"gitleaks_{GITLEAKS_VERSION}_checksums.txt", timeout=60).read().decode()
        blob.write_bytes(urllib.request.urlopen(base + asset, timeout=300).read())
        want = next((l.split()[0] for l in sums.splitlines() if l.strip().endswith(asset)), None)
        got = hashlib.sha256(blob.read_bytes()).hexdigest()
        if not want or want != got:
            raise SystemExit(f"leakguard: checksum mismatch for {asset} (expected {want}, got {got}); not installed")
        if asset.endswith(".zip"):
            zipfile.ZipFile(blob).extract("gitleaks.exe", dest)
        else:
            tarfile.open(blob).extract("gitleaks", dest)
            (dest / "gitleaks").chmod(0o755)
    return str(dest / ("gitleaks.exe" if os.name == "nt" else "gitleaks"))


def need_gitleaks() -> str:
    g = find_gitleaks()
    if not g:
        raise SystemExit("leakguard: gitleaks is not installed. Run:  python scripts/leakguard.py install")
    return g


def base_config() -> Path:
    """The repo's own .gitleaks.toml, else the central one (repos set up through the git template only)."""
    for p in (ROOT / ".gitleaks.toml", CENTRAL / "templates" / "gitleaks.toml", SELF.parent / "templates" / "gitleaks.toml"):
        if p.exists():
            return p
    raise SystemExit("leakguard: no .gitleaks.toml found. Run: python <leakguard>/leakguard.py init")


def config_path() -> Path:
    """Base rules plus one rule for the words in .leakwords (generated inside .git, never committed)."""
    base, ws, private = base_config(), words(), profile() == "private"
    if not ws and not private:
        return base
    d = Path(git("rev-parse", "--absolute-git-dir").strip()) / "leakguard"  # worktree では .git がファイルのため
    d.mkdir(parents=True, exist_ok=True)
    text = f'title = "local"\n[extend]\npath = {json.dumps(str(base))}\n'
    if private:
        text += (f'[[allowlists]]\ndescription = "private profile: host names and private/Tailscale IPs are allowed"\n'
                 f'targetRules = [{", ".join(json.dumps(r) for r in PRIVATE_RULES)}]\nregexTarget = "match"\nregexes = [\'\'\'(?s).+\'\'\']\n')
    if ws:
        pat = "|".join(re.escape(w) for w in ws)
        kw = ", ".join(json.dumps(w.lower()) for w in ws)
        text += f'[[rules]]\nid = "local-deny-words"\ndescription = "A real name listed in .leakwords"\nregex = \'\'\'(?i)(?:{pat})\'\'\'\nkeywords = [{kw}]\n'
    (d / "local.toml").write_text(text, encoding="utf-8")
    return d / "local.toml"


# ---------------------------------------------------------------- checks
def run_gitleaks(*scan: str) -> bool:
    cmd = [need_gitleaks(), "git", str(ROOT), *scan, "--config", str(config_path()), "--redact", "--no-banner", "--exit-code", "1", "-v"]
    sys.path.insert(0, str(SELF.parent))
    from leakguard_limits import run_limited

    code, out, err, reason = run_limited(cmd, ROOT)
    if reason:
        print(f"leakguard: gitleaks {reason}; commit/push blocked (nothing was verified)", file=sys.stderr)
    if code != 0:
        print((out + err).strip(), file=sys.stderr)
    return code == 0


def check_identity(lines: list[tuple[str, str, str]]) -> list[str]:
    bad = []
    for label, name, email in lines:
        if not OK_EMAIL.search(email or ""):
            bad.append(f"{label} e-mail is not a placeholder: {email!r}  (use e.g. dev@example.com: git config user.email dev@example.com)")
        if word_hits(f"{name} {email}"):
            bad.append(f"{label} name/e-mail contains a word from .leakwords")
    return bad


def check_text(label: str, text: str) -> list[str]:
    bad = []
    for e in ANY_EMAIL.findall(text):
        if not OK_EMAIL.search(e):
            bad.append(f"{label}: e-mail address {e!r}")
    for w in word_hits(text):
        bad.append(f"{label}: contains {w!r} (listed in .leakwords)")
    return bad


def fail(problems: list[str]) -> int:
    if not problems:
        return 0
    print("\nleakguard: BLOCKED - personal information would be committed/pushed:", file=sys.stderr)
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    print("Replace it with a placeholder (see docs/LEAK_GUARD.md). Do not bypass with --no-verify.", file=sys.stderr)
    return 1


def cmd_staged() -> int:
    ident = git("var", "GIT_AUTHOR_IDENT").strip(), git("var", "GIT_COMMITTER_IDENT").strip()
    people = []
    for label, s in zip(("author", "committer"), ident):
        m = re.match(r"(.*) <(.*)> \d+ [+-]\d{4}$", s)
        people.append((label, m.group(1) if m else s, m.group(2) if m else ""))
    problems = check_identity(people)
    problems += check_text("file name", git("diff", "--cached", "--name-only", "-z").replace("\0", "\n"))
    if not run_gitleaks("--staged", "--pre-commit"):
        problems.append("gitleaks found a secret or personal-information pattern in the staged changes (details above)")
    return fail(problems)


def cmd_message(path: str) -> int:
    text = "\n".join(l for l in Path(path).read_text(encoding="utf-8", errors="replace").splitlines() if not l.startswith("#"))
    return fail(check_text("commit message", text))


def commits_in(rev: str) -> list[tuple[str, ...]]:
    out = git("log", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e", *rev.split())
    rows = []
    for rec in out.split("\x1e"):
        f = rec.strip("\n").split("\x1f")
        if len(f) == 6:
            rows.append(tuple(f))
    return rows


BASELINE = ".leakguard-baseline"


def cmd_baseline() -> int:
    """Accept the history up to HEAD as already reviewed; `all` then scans only what comes after it."""
    (ROOT / BASELINE).write_text(git("rev-parse", "HEAD").strip() + "\n", encoding="utf-8")
    print(f"leakguard: wrote {BASELINE} (history up to this commit is no longer scanned by `all`)")
    return 0


def baseline_exclusion() -> str:
    f = ROOT / BASELINE
    sha = f.read_text(encoding="utf-8").strip() if f.exists() else ""
    return f" ^{sha}" if re.fullmatch(r"[0-9a-f]{40}", sha) else ""


def history_rev() -> str:
    return "--all" + baseline_exclusion()


def scan_history(rev: str) -> int:
    problems = []
    for h, an, ae, cn, ce, body in commits_in(rev):
        problems += [f"{h[:8]}: {p}" for p in check_identity([("author", an, ae), ("committer", cn, ce)])]
        problems += [f"{h[:8]}: {p}" for p in check_text("message", body)]
        problems += [f"{h[:8]}: {p}" for p in check_text("file name", git("diff-tree", "--no-commit-id", "--name-only", "-r", "--root", "-z", h).replace("\0", "\n"))]
    if not run_gitleaks(f"--log-opts={rev}"):
        problems.append("gitleaks found a secret or personal-information pattern in the history (details above)")
    return fail(problems)


def find_gh() -> str | None:
    """gh on PATH, else the usual Homebrew locations (a non-login ssh session on macOS has no /opt/homebrew/bin on PATH)."""
    found = shutil.which("gh")
    if found:
        return found
    return next((p for p in ("/opt/homebrew/bin/gh", "/usr/local/bin/gh") if os.access(p, os.X_OK)), None)


def github_slug(url: str) -> tuple[str, str] | None:
    """(owner, repo) for a github.com remote URL (https, scp-like ssh or ssh://), else None."""
    m = re.match(r"^(?:https?://(?:[^@/]+@)?|ssh://(?:[^@/]+@)?|[^@/\s]+@)github\.com[/:]([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", url.strip())
    return (m.group(1), m.group(2)) if m else None


def github_visibility(owner: str, repo: str) -> str | None:
    """'public' / 'private' / 'internal', or None when it cannot be determined (no gh, not logged in, no access, no such repo)."""
    gh = find_gh()
    if not gh:
        return None
    r = subprocess.run([gh, "api", f"repos/{owner}/{repo}", "--jq", ".visibility"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    v = r.stdout.strip()
    return v if r.returncode == 0 and v in ("public", "private", "internal") else None


def check_remote_not_public(remote: str) -> list[str]:
    """Pushing to a public GitHub repository is forbidden. Anything on GitHub that is not confirmed private/internal is refused too."""
    url = git("remote", "get-url", "--push", remote).strip() if remote else ""
    if not url and ("://" in remote or "@" in remote):
        url = remote  # pushed by URL: the hook's first argument is the URL itself
    slug = github_slug(url) if url else None
    if not slug:
        return []  # not GitHub (a local share, another host): nothing to look up
    v = github_visibility(*slug)
    if v in ("private", "internal"):
        return []
    if v == "public":
        return [f"the remote {remote or url!r} is a PUBLIC GitHub repository ({slug[0]}/{slug[1]}); pushing to public repositories is forbidden"]
    return [f"cannot confirm that GitHub repository {slug[0]}/{slug[1]} is private (is `gh` installed and logged in? does the repo exist?); push refused"]


def is_nopush(root: Path) -> bool:
    """`git config leakguard.nopush true` marks a repository that is never pushed (e.g. an Obsidian vault): no harness is required."""
    return _run(["git", "config", "--type=bool", "--get", "leakguard.nopush"], cwd=str(root)).strip() == "true"


def cmd_push(remote: str = "") -> int:
    if is_nopush(ROOT):
        return fail(["this repository is marked leakguard.nopush (never pushed); push refused. Remove the mark with: git config --unset leakguard.nopush"])
    problems = check_remote_not_public(remote)
    lines = [l.split() for l in sys.stdin.read().splitlines() if len(l.split()) >= 4]
    if problems:
        sys.path.insert(0, str(SELF.parent))
        from leakguard_publish import consume_approval

        # the exception: a confirmed-PUBLIC remote (never an unconfirmed one) with the person's fresh approval for exactly these commits
        if not (all("is a PUBLIC GitHub repository" in p for p in problems) and consume_approval(sys.modules[__name__], [l[1] for l in lines if l[1] != ZERO])):
            return fail(problems + ["to publish on purpose, the person runs: python <leakguard>/leakguard.py approve-publish  (agents must not)"])
        print("leakguard: publishing approved by the person for this commit (one push).", file=sys.stderr)
    rc = 0
    for parts in lines:
        _lref, lsha, _rref, rsha = parts[:4]
        if lsha == ZERO:
            continue  # deleting a branch
        rc |= scan_history((lsha if rsha == ZERO else f"{rsha}..{lsha}") + baseline_exclusion())
    return rc


# ---------------------------------------------------------------- install / init / setup
def harness_state(root: Path) -> dict:
    hp = _run(["git", "config", "--get", "core.hooksPath"], cwd=str(root)).strip()
    remote = bool(_run(["git", "remote"], cwd=str(root)).strip())
    return {
        "engine": (root / "scripts" / "leakguard.py").exists(),
        "rules": (root / ".gitleaks.toml").exists(),
        "hooks": hp == ".githooks" and (root / ".githooks" / "pre-push").exists(),
        "ci": (root / ".github" / "workflows" / "leakguard.yml").exists(),
        "remote": remote,
        "email": _run(["git", "config", "user.email"], cwd=str(root)).strip(),
    }


def cmd_install() -> int:
    if not find_gitleaks():
        print(f"installing gitleaks {GITLEAKS_VERSION} into {CENTRAL / 'bin'} ...")
        print("installed:", install_gitleaks())
    subprocess.run(["git", "config", "core.hooksPath", ".githooks"], cwd=ROOT, check=True)
    for h in (ROOT / ".githooks").glob("*"):
        try:
            h.chmod(0o755)
        except OSError:
            pass
    print("hooks enabled (core.hooksPath=.githooks)")
    email = git("config", "user.email").strip()
    if not OK_EMAIL.search(email):
        print(f"note: git user.email is {email!r}. Commits will be blocked until you run: git config user.email dev@example.com")
    if not words():
        print("note: no real-name list yet. Put host names / user names / IPs / e-mail, one per line, in .leakwords (this repo) or ~/.config/leakguard/words (all repos); both are never committed.")
    return 0


def templates_dir() -> Path:
    for d in (SELF.parent / "templates", CENTRAL / "templates"):
        if (d / "gitleaks.toml").exists():
            return d
    raise SystemExit("leakguard: templates not found. Run init from a copy of the leakguard repository (or after `setup-global`).")


def _write(path: Path, data: bytes, update: bool, report: list[str]) -> None:
    rel = path.relative_to(ROOT).as_posix()
    if path.exists():
        cur = path.read_bytes()
        if cur == data:
            report.append(f"  = {rel} (unchanged)")
            return
        if not update:
            report.append(f"  ! {rel} exists and differs - kept (use --update to replace generated files)")
            return
        if MANAGED.encode() not in cur[:300] and path.name not in ("pre-commit", "commit-msg", "pre-push"):
            report.append(f"  ! {rel} was not generated by leakguard - kept")
            return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    report.append(f"  + {rel}")


def _append_lines(path: Path, lines: list[str], report: list[str]) -> None:
    cur = path.read_text(encoding="utf-8") if path.exists() else ""
    have = set(cur.splitlines())
    add = [l for l in lines if l not in have]
    if add:
        write_lf(path, cur + ("" if cur.endswith("\n") or not cur else "\n") + "\n".join(add) + "\n")
        report.append(f"  + {path.name}: {', '.join(add)}")


def cmd_init(args: list[str]) -> int:
    update, ident = "--update" in args, "--no-identity" not in args
    paths = [a for a in args if not a.startswith("--")]
    target = toplevel(paths[0] if paths else ".")
    if not target:
        raise SystemExit("leakguard init: not inside a git repository (run `git init` first)")
    set_root(target)
    if is_nopush(target):
        print(f"leakguard init: {target} is marked leakguard.nopush (never pushed); harness not installed. To protect it anyway: git config --unset leakguard.nopush")
        return 0
    t = templates_dir()
    report: list[str] = []
    if "--private" in args:  # private repository: host names and private/Tailscale IPs are allowed (secrets and e-mail stay blocked)
        _write(ROOT / PROFILE_FILE, b"private\n", True, report)
    lf = lambda p: p.read_bytes().replace(b"\r\n", b"\n")
    _write(ROOT / "scripts" / "leakguard.py", lf(SELF), update, report)
    _write(ROOT / "scripts" / "leakguard_limits.py", lf(SELF.parent / "leakguard_limits.py"), update, report)
    for mod in ("leakguard_audit.py", "leakguard_tools.py", "leakguard_guard.py", "leakguard_publish.py"):
        _write(ROOT / "scripts" / mod, lf(SELF.parent / mod), update, report)
    _write(ROOT / ".gitleaks.toml", lf(t / "gitleaks.toml"), update, report)
    for h in ("pre-commit", "commit-msg", "pre-push"):
        _write(ROOT / ".githooks" / h, lf(t / "hooks" / h), update, report)
    _write(ROOT / ".github" / "workflows" / "leakguard.yml", lf(t / "leakguard.yml"), update, report)
    doc = t / "LEAK_GUARD.md"
    if doc.exists():
        _write(ROOT / "docs" / "LEAK_GUARD.md", lf(doc), update, report)
    blk = t / "agents" / "AGENTS.block.md"
    if blk.exists():
        report.append(("  + " if upsert_block(ROOT / "AGENTS.md", blk.read_text(encoding="utf-8"), "# AGENTS.md\n\n") else "  = ") + "AGENTS.md (leakguard rules for AI agents)")
    _append_lines(ROOT / ".gitignore", [".leakwords", ".tools/"], report)
    _append_lines(ROOT / ".gitattributes", [".githooks/* text eol=lf", "scripts/leakguard.py text eol=lf"], report)
    # hooks must be LF, executable
    for h in (ROOT / ".githooks").glob("*"):
        try:
            h.chmod(0o755)
        except OSError:
            pass
    subprocess.run(["git", "config", "core.hooksPath", ".githooks"], cwd=ROOT, check=True)
    report.append("  + git config core.hooksPath .githooks")
    if ident and not OK_EMAIL.search(git("config", "user.email").strip()):
        subprocess.run(["git", "config", "user.name", DEFAULT_IDENTITY[0]], cwd=ROOT, check=True)
        subprocess.run(["git", "config", "user.email", DEFAULT_IDENTITY[1]], cwd=ROOT, check=True)
        report.append(f"  + git config user.name/user.email = {DEFAULT_IDENTITY[0]} <{DEFAULT_IDENTITY[1]}> (this repo only)")
    print(f"leakguard init: {ROOT}")
    print("\n".join(report))
    if not find_gitleaks():
        print(f"installing gitleaks {GITLEAKS_VERSION} into {CENTRAL / 'bin'} ...")
        install_gitleaks()
    # report what is already in the history (informational: init itself never fails on it)
    if git("rev-parse", "--verify", "HEAD").strip():
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "leakguard.py"), "all"], cwd=ROOT, capture_output=True, text=True)
        print("history scan:", "clean" if r.returncode == 0 else "FOUND PROBLEMS - details below\n" + r.stderr.strip())
    print("done. Review the new files and commit them. Real names go in .leakwords / ~/.config/leakguard/words (never committed).")
    return 0


HOOK_TEMPLATE = """#!/bin/sh
# leakguard (git template): runs the central leakguard for repositories that have not been `init`-ed. Replaced by .githooks/ after `leakguard.py init`.
exec "{python}" "{engine}" {cmd}
"""


def cmd_setup_global() -> int:
    """Copy engine + templates to ~/.config/leakguard (self-contained), install gitleaks, set git's init.templateDir."""
    CENTRAL.mkdir(parents=True, exist_ok=True)
    engine = CENTRAL / "leakguard.py"
    if SELF != engine:
        shutil.copyfile(SELF, engine)
        shutil.copyfile(SELF.parent / "leakguard_limits.py", engine.parent / "leakguard_limits.py")
        for mod in ("leakguard_audit.py", "leakguard_tools.py", "leakguard_guard.py", "leakguard_publish.py"):
            shutil.copyfile(SELF.parent / mod, engine.parent / mod)
        src = SELF.parent / "templates"
        if src.exists():
            shutil.rmtree(CENTRAL / "templates", ignore_errors=True)
            shutil.copytree(src, CENTRAL / "templates")
    if not (CENTRAL / "words").exists():
        (CENTRAL / "words").write_text("# Real names (host names, user names, IPs, e-mail), one per line. Applies to every repo; never committed anywhere.\n", encoding="utf-8")
    if not find_gitleaks():
        print("installed:", install_gitleaks())
    tdir = CENTRAL / "git-template"
    cur = _run(["git", "config", "--global", "--get", "init.templateDir"]).strip()
    if cur and Path(cur).resolve() != tdir.resolve():
        print(f"git already uses init.templateDir={cur!r}; not replacing it. Copy the hooks from {tdir / 'hooks'} into it yourself.")
    hooks = tdir / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    py = str(Path(sys.executable)).replace("\\", "/")
    for name, cmd in (("pre-commit", "staged"), ("commit-msg", 'message "$1"'), ("pre-push", 'push "$1"')):
        f = hooks / name
        write_lf(f, HOOK_TEMPLATE.format(python=py, engine=str(engine).replace("\\", "/"), cmd=cmd))
        try:
            f.chmod(0o755)
        except OSError:
            pass
    if not cur:
        subprocess.run(["git", "config", "--global", "init.templateDir", str(tdir)], check=True)
    print(f"central copy: {CENTRAL}\nnew `git init` / `git clone` now get leakguard hooks (init.templateDir={tdir if not cur else cur}).")
    print(f"Real names for all repos: {CENTRAL / 'words'}")
    return 0


def upsert_block(path: Path, text: str, heading: str = "") -> bool:
    """Put `text` between the leakguard markers in `path` (created if missing, other content untouched). True if the file changed."""
    block = f"{BLOCK_BEGIN}\n" + text.replace("\r\n", "\n").strip("\n") + f"\n{BLOCK_END}\n"
    head = BLOCK_BEGIN.split(" (")[0]
    cur = path.read_text(encoding="utf-8").replace("\r\n", "\n") if path.exists() else ""
    if head in cur and BLOCK_END in cur:
        a, z = cur.index(head), cur.index(BLOCK_END) + len(BLOCK_END) + 1
        new = cur[:a] + block + cur[z:]
    else:
        new = (cur.rstrip("\n") + "\n\n" if cur.strip() else heading) + block
    if new == cur:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    write_lf(path, new)
    return True


def merge_words(current: str, incoming: str) -> tuple[str, int]:
    """Union of two word lists; comment lines of the current file are kept, new words are appended."""
    have = {l.strip().lower() for l in current.splitlines() if l.strip() and not l.lstrip().startswith("#")}
    add = []
    for l in incoming.splitlines():
        w = l.strip()
        if w and not w.startswith("#") and w.lower() not in have:
            have.add(w.lower())
            add.append(w)
    return current.rstrip("\n") + ("\n" if current.strip() else "") + "".join(w + "\n" for w in add), len(add)


def cmd_pull_words(host: str) -> int:
    """Merge the real-name list of another machine (over ssh) into this one. The list never goes through GitHub."""
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", host, "cat ~/.config/leakguard/words"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise SystemExit(f"leakguard: could not read the list from {host}: {r.stderr.strip()[:200]}")
    CENTRAL.mkdir(parents=True, exist_ok=True)
    f = CENTRAL / "words"
    merged, n = merge_words(f.read_text(encoding="utf-8") if f.exists() else "", r.stdout)
    write_lf(f, merged)
    print(f"{n} new word(s) added from {host} -> {f}")
    return 0


def cmd_setup_claude() -> int:
    """Claude Code integration, idempotent: skill, rules block in ~/.claude/CLAUDE.md, SessionStart hook in settings.json."""
    t = templates_dir() / "claude"
    if not t.exists():
        raise SystemExit("leakguard: templates/claude not found")
    CLAUDE_HOME.mkdir(parents=True, exist_ok=True)
    out = []
    # skills
    for sd in sorted((t / "skills").glob("*/SKILL.md")):
        dst = CLAUDE_HOME / "skills" / sd.parent.name / "SKILL.md"
        src = sd.read_bytes().replace(b"\r\n", b"\n")
        try:  # the skills directory may be a link to somewhere unreachable (e.g. a junction to another drive): then skip only the skills
            dst.parent.mkdir(parents=True, exist_ok=True)
            if not dst.exists() or dst.read_bytes() != src:
                dst.write_bytes(src)
                out.append(f"  + {dst}")
        except OSError as e:
            out.append(f"  ! skill not installed: {sd.parent.name} ({e.__class__.__name__}: {CLAUDE_HOME / 'skills'} is not writable); the rules and the hooks still work")
    # rules block
    md = CLAUDE_HOME / "CLAUDE.md"
    if upsert_block(md, (t / "CLAUDE.block.md").read_text(encoding="utf-8"), "# Personal rules (all projects)\n\n"):
        out.append(f"  + {md} (leakguard block)")
    # SessionStart hook
    sj = CLAUDE_HOME / "settings.json"
    data = json.loads(sj.read_text(encoding="utf-8")) if sj.exists() and sj.read_text(encoding="utf-8").strip() else {}
    ss = data.setdefault("hooks", {}).setdefault("SessionStart", [])
    if not any("leakguard" in h.get("command", "") and "session-check" in h.get("command", "") for e in ss for h in e.get("hooks", [])):
        if sj.exists() and not (CLAUDE_HOME / "settings.json.bak-leakguard").exists():
            shutil.copyfile(sj, CLAUDE_HOME / "settings.json.bak-leakguard")
        cmd = '{ python "$HOME/.config/leakguard/leakguard.py" session-check || python3 "$HOME/.config/leakguard/leakguard.py" session-check; } 2>/dev/null || true'
        ss.append({"hooks": [{"type": "command", "command": cmd, "timeout": 10}]})
        write_lf(sj, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        out.append(f"  + {sj} (SessionStart hook; backup: settings.json.bak-leakguard)")
    pt = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
    if not any("leakguard" in h.get("command", "") and "guard-tool" in h.get("command", "") for e in pt for h in e.get("hooks", [])):
        gcmd = 'python "$HOME/.config/leakguard/leakguard.py" guard-tool 2>/dev/null || python3 "$HOME/.config/leakguard/leakguard.py" guard-tool 2>/dev/null || true'
        pt.append({"matcher": "Bash|mcp__.*", "hooks": [{"type": "command", "command": gcmd, "timeout": 1800}]})
        write_lf(sj, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        out.append(f"  + {sj} (PreToolUse hook: audit before publishing)")
    print("leakguard setup-claude: " + ("changed" if out else "already up to date"))
    print("\n".join(out))
    return 0


def cmd_selftest() -> int:
    """Does a brand-new repository on THIS machine get protected? (git template hooks, central engine, gitleaks, rules)"""
    ok = True

    def say(good: bool, what: str) -> None:
        nonlocal ok
        ok &= good
        print(("  ok   " if good else "  FAIL ") + what)

    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "t"
        d.mkdir()
        g = lambda *a: subprocess.run(["git", *a], cwd=d, capture_output=True, text=True, encoding="utf-8", errors="replace")
        g("init", "-q")
        g("config", "user.name", DEFAULT_IDENTITY[0])
        g("config", "user.email", DEFAULT_IDENTITY[1])
        say((d / ".git" / "hooks" / "pre-commit").exists() and (d / ".git" / "hooks" / "pre-push").exists(), "new `git init` gets the hooks (init.templateDir)")
        say(find_gitleaks() is not None, "gitleaks found")
        (d / "a.txt").write_text("server = " + ".".join(["192", "168", "77", "5"]) + "\n", encoding="utf-8")
        g("add", "a.txt")
        r = g("commit", "-q", "-m", "x")
        say(r.returncode != 0 and "BLOCKED" in r.stderr, "a private IP in a commit is refused")
        (d / "a.txt").write_text("server = 192.168.1.20\n", encoding="utf-8")
        g("add", "a.txt")
        r = g("commit", "-q", "-m", "ok")
        say(r.returncode == 0, "a placeholder commit goes through")
        say(bool(words()), f"real-name list has entries ({CENTRAL / 'words'})")
        gh = find_gh()
        say(True, "gh " + (f"found ({gh})" if gh else "NOT found: every push to GitHub from this machine is refused (cannot confirm private)"))
    print("selftest:", "all good" if ok else "PROBLEMS")
    return 0 if ok else 1


def cmd_setup_agents() -> int:
    """Rules for AI tools other than Claude Code: the Codex CLI reads ~/.codex/AGENTS.md. Other tools read AGENTS.md of each repository (written by `init`)."""
    t = templates_dir() / "agents" / "AGENTS.block.md"
    home = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")
    changed = upsert_block(home / "AGENTS.md", t.read_text(encoding="utf-8"), "# Personal rules (all projects)\n\n")
    print(f"leakguard setup-agents: {'changed' if changed else 'already up to date'} ({home / 'AGENTS.md'})")
    return 0


def cmd_survey(dirs: list[str]) -> int:
    roots = [Path(d).resolve() for d in (dirs or ["."])]
    seen: list[Path] = []
    for base in roots:
        for dp, dn, _fn in os.walk(base):
            depth = len(Path(dp).relative_to(base).parts)
            if ".git" in dn or (Path(dp) / ".git").is_file():
                seen.append(Path(dp))
                dn[:] = []
                continue
            dn[:] = [d for d in dn if d not in ("node_modules", ".venv", "venv", "__pycache__", "dist", "build") and not d.startswith(".")]
            if depth >= 3:
                dn[:] = []
    w = max([len(str(r)) for r in seen] + [4]) + 2
    print(f"{'repo':{w}}engine rules hooks ci   remote user.email")
    for r in sorted(seen):
        s = harness_state(r)
        yn = lambda b: "yes " if b else "NO  "
        print(f"{str(r):{w}}{yn(s['engine'])}   {yn(s['rules'])}  {yn(s['hooks'])}  {yn(s['ci'])}  {yn(s['remote'])}  {s['email']}")
    todo = [r for r in seen if not harness_state(r)["hooks"]]
    print(f"\n{len(seen)} repositories, {len(todo)} without the harness. Add it with:  python leakguard.py init <path>")
    return 0


def cmd_session_check() -> int:
    """Silent when fine. Otherwise one short paragraph (an agent start-up hook turns stdout into context)."""
    root = toplevel(".")
    if not root or is_nopush(root):
        return 0
    s = harness_state(root)
    if s["hooks"] and s["engine"]:
        if not OK_EMAIL.search(s["email"]):
            print(f"[leakguard] git user.email is {s['email']!r}: commits here will be blocked. Run: git config user.email dev@example.com")
        return 0
    eng = CENTRAL / "leakguard.py"
    print(f"[leakguard] This repository ({root.name}) has no leak-prevention harness (hooks/rules for personal information). "
          f"Before committing or pushing, add it: python \"{eng}\" init \"{root}\"  (then commit the generated files). "
          "Never write e-mail addresses, home-directory paths or secrets into files or commit metadata; host names and private/Tailscale IPs only in a private repository "
          f"(`init --private`), otherwise use placeholders.")
    return 0


def main(argv: list[str]) -> int:
    c = argv[1] if len(argv) > 1 else ""
    if c == "install":
        return cmd_install()
    if c == "staged":
        return cmd_staged()
    if c == "message" and len(argv) > 2:
        return cmd_message(argv[2])
    if c == "push":
        return cmd_push(argv[2] if len(argv) > 2 else "")
    if c == "all":
        return scan_history(history_rev())
    if c == "baseline":
        return cmd_baseline()
    if c == "init":
        return cmd_init(argv[2:])
    if c == "setup-global":
        return cmd_setup_global()
    if c == "setup-agents":
        return cmd_setup_agents()
    if c == "setup-claude":
        return cmd_setup_claude()
    if c == "pull-words" and len(argv) > 2:
        return cmd_pull_words(argv[2])
    if c == "selftest":
        return cmd_selftest()
    if c == "approve-publish":
        sys.path.insert(0, str(SELF.parent))
        from leakguard_publish import approve_publish

        return approve_publish(sys.modules[__name__])
    if c == "guard-tool":
        sys.path.insert(0, str(SELF.parent))
        from leakguard_guard import run_guard

        return run_guard(SELF, sys.stdin.read())
    if c == "install-audit-tools":
        sys.path.insert(0, str(SELF.parent))
        from leakguard_tools import install_audit_tools

        return install_audit_tools(CENTRAL)
    if c == "audit":
        sys.path.insert(0, str(SELF.parent))
        from leakguard_audit import run_audit

        return run_audit(sys.modules[__name__], argv[2:])
    if c == "survey":
        return cmd_survey(argv[2:])
    if c == "session-check":
        return cmd_session_check()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
