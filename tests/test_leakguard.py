"""leakguard end to end: real git, real hooks, real gitleaks, in throw-away repositories. Machine-wide settings are isolated per test."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "scripts" / "leakguard.py" if (ROOT / "scripts" / "leakguard.py").exists() else ROOT / "leakguard.py"
SRC = ROOT / "leakguard.py"
sys.path.insert(0, str(ROOT))
import leakguard  # noqa: E402

GL = leakguard.find_gitleaks()
pytestmark = pytest.mark.skipif(not GL, reason="gitleaks not installed (run: python leakguard.py setup-global)")

# built at run time so this file itself holds no address-shaped strings
IP_REAL = ".".join(["192", "168", "7", "44"])
IP_PLACEHOLDER = ".".join(["192", "168", "1", "20"])
MAIL_REAL = "someone" + "@" + "mail-example.net"
MAIL_OK = "dev" + "@" + "example.com"
HOME = "C:\\" + "Users\\" + "realperson\\Desktop"
HOST = "DESKTOP-" + "AB12CD3"
TS = "box.tail1a2b3c" + ".ts" + ".net"


@pytest.fixture
def env(tmp_path):
    """Isolated machine: own leakguard home, own global git config, the gitleaks binary we found."""
    home = tmp_path / "lghome"
    gcfg = tmp_path / "gitconfig"
    gcfg.write_text("", encoding="utf-8")
    e = {**os.environ, "LEAKGUARD_HOME": str(home), "GIT_CONFIG_GLOBAL": str(gcfg), "GIT_CONFIG_NOSYSTEM": "1", "CLAUDE_CONFIG_DIR": str(tmp_path / "claude"), "CODEX_HOME": str(tmp_path / "codex"), "LEAKGUARD_GITLEAKS": GL,
         "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]}
    return e


def sh(cwd, *a, env=None, check=True):
    return subprocess.run(["git", *a], cwd=cwd, capture_output=True, text=True, env=env, check=check)


def lg(cwd, env, *a, stdin=None, script=None):
    return subprocess.run([sys.executable, str(script or SRC), *a], cwd=cwd, capture_output=True, text=True, input=stdin, env=env)


def new_repo(tmp_path, env, name="r", identity=True):
    d = tmp_path / name
    d.mkdir()
    sh(d, "init", "-q", env=env)
    if identity:
        sh(d, "config", "user.name", "Dev", env=env)
        sh(d, "config", "user.email", MAIL_OK, env=env)
    return d


def stage(d, env, name, text):
    (d / name).parent.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(text, encoding="utf-8")
    sh(d, "add", name, env=env)


# ---------------------------------------------------------------- checks (engine called directly)
@pytest.mark.parametrize("what,text", [
    ("private ip", f"server = {IP_REAL}\n"),
    ("e-mail", f"contact: {MAIL_REAL}\n"),
    ("home dir", f"path = {HOME}\n"),
    ("windows host name", f"host: {HOST}\n"),
    ("tailnet name", f"url: http://{TS}:8765\n"),
])
def test_staged_personal_information_is_blocked(tmp_path, env, what, text):
    d = new_repo(tmp_path, env)
    stage(d, env, "notes.txt", text)
    r = lg(d, env, "staged")
    assert r.returncode == 1 and "BLOCKED" in r.stderr, (what, r.stdout, r.stderr)


def test_own_words_from_repo_and_global_list_are_blocked(tmp_path, env):
    d = new_repo(tmp_path, env)
    (d / ".leakwords").write_text("# mine\nrepo-secret-host\n", encoding="utf-8")
    Path(env["LEAKGUARD_HOME"]).mkdir(parents=True)
    (Path(env["LEAKGUARD_HOME"]) / "words").write_text("global-secret-host\n", encoding="utf-8")
    for w in ("repo-secret-host", "GLOBAL-secret-host"):
        stage(d, env, "n.txt", f"ssh {w}\n")
        assert lg(d, env, "staged").returncode == 1, w
    sh(d, "reset", "-q", env=env)
    stage(d, env, "repo-secret-host.txt", "harmless\n")  # file names are checked as well
    assert lg(d, env, "staged").returncode == 1


def test_placeholders_and_clean_files_pass(tmp_path, env):
    d = new_repo(tmp_path, env)
    stage(d, env, "notes.txt", f"server = {IP_PLACEHOLDER}\nmail = {MAIL_OK}\nnet = 100.64.0.10\nssh sshuser@prod-server\n")
    r = lg(d, env, "staged")
    assert r.returncode == 0, r.stderr


def test_secret_with_default_rules_is_blocked(tmp_path, env):
    d = new_repo(tmp_path, env)
    stage(d, env, "k.txt", "token = ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\n")
    assert lg(d, env, "staged").returncode == 1


def test_real_identity_is_blocked(tmp_path, env):
    d = new_repo(tmp_path, env)
    sh(d, "config", "user.email", MAIL_REAL, env=env)
    stage(d, env, "a.txt", "ok\n")
    r = lg(d, env, "staged")
    assert r.returncode == 1 and "not a placeholder" in r.stderr


def test_commit_message_is_checked(tmp_path, env):
    d = new_repo(tmp_path, env)
    f = tmp_path / "msg"
    f.write_text(f"fix for {MAIL_REAL}\n\n# comment line is ignored\n", encoding="utf-8")
    assert lg(d, env, "message", str(f)).returncode == 1
    f.write_text(f"fix\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n# {MAIL_REAL}\n", encoding="utf-8")
    assert lg(d, env, "message", str(f)).returncode == 0


def test_baseline_skips_old_history_but_still_catches_new_leaks(tmp_path, env):
    d = new_repo(tmp_path, env)
    stage(d, env, "old.txt", f"server = {IP_REAL}\n")
    sh(d, "commit", "-q", "--no-verify", "-m", "old", env=env)
    assert lg(d, env, "all").returncode == 1
    assert lg(d, env, "baseline").returncode == 0
    assert lg(d, env, "all").returncode == 0
    stage(d, env, "new.txt", f"server = {IP_REAL}\n")
    sh(d, "commit", "-q", "--no-verify", "-m", "new", env=env)
    assert lg(d, env, "all").returncode == 1


def test_baseline_applies_to_the_first_push_of_a_branch(tmp_path, env):
    d = new_repo(tmp_path, env)
    stage(d, env, "old.txt", f"server = {IP_REAL}\n")
    sh(d, "commit", "-q", "--no-verify", "-m", "old", env=env)
    lg(d, env, "baseline")
    head = sh(d, "rev-parse", "HEAD", env=env).stdout.strip()
    assert lg(d, env, "push", "origin", stdin=f"refs/heads/b {head} refs/heads/b {'0' * 40}\n").returncode == 0


def test_history_and_push_scan_catch_what_bypassed_the_hooks(tmp_path, env):
    d = new_repo(tmp_path, env)
    stage(d, env, "ok.txt", "fine\n")
    sh(d, "commit", "-q", "-m", "clean", env=env)
    assert lg(d, env, "all").returncode == 0
    base = sh(d, "rev-parse", "HEAD", env=env).stdout.strip()
    stage(d, env, "bad.txt", f"server = {IP_REAL}\n")
    sh(d, "commit", "-q", "--no-verify", "-m", "sneaky", env=env)
    head = sh(d, "rev-parse", "HEAD", env=env).stdout.strip()
    assert lg(d, env, "all").returncode == 1
    assert lg(d, env, "push", "origin", stdin=f"refs/heads/main {head} refs/heads/main {base}\n").returncode == 1
    assert lg(d, env, "push", "origin", stdin=f"refs/heads/main {base} refs/heads/main {'0' * 40}\n").returncode == 0


# ---------------------------------------------------------------- private profile
def private_repo(tmp_path, env, remote=None):
    d = new_repo(tmp_path, env)
    (d / ".leakguard-profile").write_text("private\n", encoding="utf-8")
    if remote:
        sh(d, "remote", "add", "origin", remote, env=env)
    return d


@pytest.mark.parametrize("what,text", [
    ("private ip", f"server = {IP_REAL}\n"),
    ("windows host name", f"host: {HOST}\n"),
    ("tailnet name", f"url: http://{TS}:8765\n"),
    ("tailscale ip", "node = " + ".".join(["100", "101", "5", "9"]) + "\n"),
])
def test_private_profile_allows_hosts_and_private_ips(tmp_path, env, what, text):
    d = private_repo(tmp_path, env)
    stage(d, env, "notes.txt", text)
    r = lg(d, env, "staged")
    assert r.returncode == 0, (what, r.stderr)


@pytest.mark.parametrize("what,text", [
    ("e-mail", f"contact: {MAIL_REAL}\n"),
    ("home dir", f"path = {HOME}\n"),
    ("token", "token = ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\n"),
])
def test_private_profile_still_blocks_secrets_and_personal_data(tmp_path, env, what, text):
    d = private_repo(tmp_path, env)
    stage(d, env, "notes.txt", text)
    r = lg(d, env, "staged")
    assert r.returncode == 1 and "BLOCKED" in r.stderr, (what, r.stderr)


def test_private_profile_ignores_plain_words_but_keeps_always_words(tmp_path, env):
    d = private_repo(tmp_path, env)
    (d / ".leakwords").write_text("my-host\nalways:my-secret-name\n", encoding="utf-8")
    stage(d, env, "n.txt", "ssh my-host\n")
    assert lg(d, env, "staged").returncode == 0
    stage(d, env, "n.txt", "ssh my-host my-secret-name\n")
    assert lg(d, env, "staged").returncode == 1


def test_profile_file_alone_is_strict_without_the_marker(tmp_path, env):
    d = new_repo(tmp_path, env)
    stage(d, env, "notes.txt", f"server = {IP_REAL}\n")
    assert lg(d, env, "staged").returncode == 1


def test_private_profile_falls_back_to_strict_when_visibility_is_not_private(tmp_path, env):
    d = private_repo(tmp_path, env)
    stage(d, env, "notes.txt", f"server = {IP_REAL}\n")
    for vis in ("public", "unknown"):
        r = lg(d, {**env, "LEAKGUARD_VISIBILITY": vis}, "staged")
        assert r.returncode == 1, vis
    assert lg(d, {**env, "LEAKGUARD_VISIBILITY": "private"}, "staged").returncode == 0


def test_private_profile_with_an_unconfirmed_github_remote_is_strict(tmp_path, env):
    d = private_repo(tmp_path, env, remote="https://github.com/nobody-here/none-existing-repo.git")
    stage(d, env, "notes.txt", f"server = {IP_REAL}\n")
    assert lg(d, {**env, "PATH": str(Path(sys.executable).parent)}, "staged").returncode == 1  # no gh on PATH: cannot confirm


def test_init_private_writes_the_marker(tmp_path, env):
    d = new_repo(tmp_path, env)
    assert lg(d, env, "init", str(d), "--private").returncode == 0
    assert (d / ".leakguard-profile").read_text().strip() == "private"
    (d / "n.txt").write_text(f"server = {IP_REAL}\n", encoding="utf-8")
    sh(d, "add", "n.txt", env=env)
    assert sh(d, "commit", "-q", "-m", "private host ip", env=env, check=False).returncode == 0


# ---------------------------------------------------------------- init: the harness lands in another repository
def test_init_installs_the_harness_and_git_really_blocks(tmp_path, env):
    d = new_repo(tmp_path, env, identity=False)
    sh(d, "config", "user.email", MAIL_REAL, env=env)  # a real address is configured
    r = lg(d, env, "init", str(d))
    assert r.returncode == 0, r.stderr
    for f in ("scripts/leakguard.py", ".gitleaks.toml", ".githooks/pre-commit", ".githooks/commit-msg", ".githooks/pre-push", ".github/workflows/leakguard.yml", "docs/LEAK_GUARD.md"):
        assert (d / f).exists(), f
    assert sh(d, "config", "core.hooksPath", env=env).stdout.strip() == ".githooks"
    assert sh(d, "config", "user.email", env=env).stdout.strip() == MAIL_OK  # identity replaced by a placeholder
    ign = (d / ".gitignore").read_text()
    assert ".leakwords" in ign and ".tools/" in ign
    # real git, real hook
    (d / "n.txt").write_text(f"server = {IP_REAL}\n", encoding="utf-8")
    sh(d, "add", "n.txt", env=env)
    bad = sh(d, "commit", "-q", "-m", "x", env=env, check=False)
    assert bad.returncode != 0 and "BLOCKED" in bad.stderr
    (d / "n.txt").write_text(f"server = {IP_PLACEHOLDER}\n", encoding="utf-8")
    sh(d, "add", "n.txt", env=env)
    ok = sh(d, "commit", "-q", "-m", "fine", env=env, check=False)
    assert ok.returncode == 0, ok.stderr
    # commit message with an address is refused by the commit-msg hook
    (d / "m.txt").write_text("a\n", encoding="utf-8")
    sh(d, "add", "m.txt", env=env)
    assert sh(d, "commit", "-q", "-m", f"mail {MAIL_REAL}", env=env, check=False).returncode != 0


def test_init_is_idempotent_and_update_only_touches_generated_files(tmp_path, env):
    d = new_repo(tmp_path, env)
    assert lg(d, env, "init", str(d)).returncode == 0
    again = lg(d, env, "init", str(d)).stdout
    assert "+ scripts/" not in again and "+ .gitleaks.toml" not in again and "+ .githooks" not in again and "unchanged" in again
    (d / ".gitleaks.toml").write_text((d / ".gitleaks.toml").read_text() + "\n# local tweak\n")
    kept = lg(d, env, "init", str(d)).stdout
    assert "kept" in kept and "local tweak" in (d / ".gitleaks.toml").read_text()
    lg(d, env, "init", str(d), "--update")
    assert "local tweak" not in (d / ".gitleaks.toml").read_text()  # generated file refreshed
    (d / "docs" / "LEAK_GUARD.md").write_text("my own doc\n")
    lg(d, env, "init", str(d), "--update")
    assert (d / "docs" / "LEAK_GUARD.md").read_text() == "my own doc\n"  # not ours (no marker): never overwritten


def test_init_on_a_repo_with_a_leaky_history_reports_it(tmp_path, env):
    d = new_repo(tmp_path, env)
    stage(d, env, "bad.txt", f"server = {IP_REAL}\n")
    sh(d, "commit", "-q", "-m", "old", env=env)
    out = lg(d, env, "init", str(d)).stdout
    assert "FOUND PROBLEMS" in out


# ---------------------------------------------------------------- machine-wide: new repos get hooks automatically
def test_setup_global_makes_every_new_repo_protected(tmp_path, env):
    r = lg(tmp_path, env, "setup-global")
    assert r.returncode == 0, r.stderr
    home = Path(env["LEAKGUARD_HOME"])
    assert (home / "leakguard.py").exists() and (home / "templates" / "gitleaks.toml").exists() and (home / "words").exists()
    tdir = sh(tmp_path, "config", "--global", "init.templateDir", env=env).stdout.strip()
    assert tdir and (Path(tdir) / "hooks" / "pre-commit").exists()
    d = new_repo(tmp_path, env, name="fresh")  # plain `git init`, no init command
    assert (d / ".git" / "hooks" / "pre-commit").exists() and (d / ".git" / "hooks" / "pre-push").exists()
    (d / "n.txt").write_text(f"server = {IP_REAL}\n", encoding="utf-8")
    sh(d, "add", "n.txt", env=env)
    bad = sh(d, "commit", "-q", "-m", "x", env=env, check=False)
    assert bad.returncode != 0 and "BLOCKED" in bad.stderr
    # clone gets them too
    ok = new_repo(tmp_path, env, name="src")
    stage(ok, env, "a.txt", "fine\n")
    sh(ok, "commit", "-q", "--no-verify", "-m", "base", env=env)
    c = tmp_path / "cloned"
    sh(tmp_path, "clone", "-q", str(ok), str(c), env=env)
    assert (c / ".git" / "hooks" / "pre-commit").exists()


def test_setup_global_does_not_replace_an_existing_template_dir(tmp_path, env):
    sh(tmp_path, "config", "--global", "init.templateDir", str(tmp_path / "mine"), env=env)
    r = lg(tmp_path, env, "setup-global")
    assert "not replacing" in r.stdout
    assert sh(tmp_path, "config", "--global", "init.templateDir", env=env).stdout.strip() == str(tmp_path / "mine")


# ---------------------------------------------------------------- survey / session check
def test_survey_lists_repos_and_session_check_nags_only_when_needed(tmp_path, env):
    a = new_repo(tmp_path, env, name="has")
    b = new_repo(tmp_path, env, name="lacks")
    lg(a, env, "init", str(a))
    out = lg(tmp_path, env, "survey", str(tmp_path)).stdout
    cols = {Path(l.split("  ")[0]).name: l[len(l.split("  ")[0]):].split()[:4] for l in out.splitlines() if l.startswith(str(tmp_path))}  # engine rules hooks ci
    assert cols["has"] == ["yes"] * 4 and cols["lacks"] == ["NO"] * 4
    assert "1 without" in out
    assert lg(a, env, "session-check").stdout == ""
    nag = lg(b, env, "session-check").stdout
    assert "[leakguard]" in nag and "init" in nag
    assert lg(tmp_path, env, "session-check").stdout == ""  # not a repository: silent


def test_nopush_mark_silences_session_check_skips_init_and_refuses_push(tmp_path, env):
    d = new_repo(tmp_path, env, name="vault")
    sh(d, "config", "leakguard.nopush", "true", env=env)
    assert lg(d, env, "session-check").stdout == ""
    r = lg(d, env, "init", str(d))
    assert r.returncode == 0 and "nopush" in r.stdout and not (d / "scripts").exists()
    assert sh(d, "config", "--get", "core.hooksPath", env=env, check=False).stdout.strip() == ""
    p = lg(d, env, "push", "origin")
    assert p.returncode == 1 and "nopush" in p.stderr


def test_engine_copy_in_this_repo_matches_the_source():
    copy = ROOT / "scripts" / "leakguard.py"
    if copy.exists():
        assert copy.read_bytes().replace(b"\r\n", b"\n") == SRC.read_bytes().replace(b"\r\n", b"\n"), "run: python leakguard.py init --update"


# ---------------------------------------------------------------- pushing to public repositories is forbidden
@pytest.mark.parametrize("url,slug", [
    ("https://github.com/o/r.git", ("o", "r")), ("https://" + "tok" + "@" + "github.com/o/r", ("o", "r")), ("git@github.com:o/r.git", ("o", "r")),
    ("ssh://git@github.com/o/r.git", ("o", "r")), ("https://gitlab.com/o/r.git", None), ("//localhost/share/r.git", None), ("D:/x/r.git", None),
])
def test_github_slug(url, slug):
    assert leakguard.github_slug(url) == slug


@pytest.mark.parametrize("vis,blocked", [("public", True), (None, True), ("private", False), ("internal", False)])
def test_push_to_github_needs_a_confirmed_private_repo(tmp_path, env, monkeypatch, vis, blocked):
    d = new_repo(tmp_path, env)
    sh(d, "remote", "add", "origin", "https://github.com/o/r.git", env=env)
    monkeypatch.setattr(leakguard, "ROOT", d)
    monkeypatch.setattr(leakguard, "github_visibility", lambda o, r: vis)
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO(""))
    assert (leakguard.cmd_push("origin") == 1) is blocked


def test_push_to_a_non_github_remote_is_not_looked_up(tmp_path, env, monkeypatch):
    d = new_repo(tmp_path, env)
    sh(d, "remote", "add", "share", str(tmp_path / "bare.git"), env=env)
    monkeypatch.setattr(leakguard, "ROOT", d)
    monkeypatch.setattr(leakguard, "github_visibility", lambda o, r: pytest.fail("must not be called"))
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO(""))
    assert leakguard.cmd_push("share") == 0


def test_pushing_by_url_is_checked_too(tmp_path, env, monkeypatch):
    d = new_repo(tmp_path, env)
    monkeypatch.setattr(leakguard, "ROOT", d)
    monkeypatch.setattr(leakguard, "github_visibility", lambda o, r: "public")
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO(""))
    assert leakguard.cmd_push("https://github.com/o/r.git") == 1


# ---------------------------------------------------------------- sharing with another PC
def test_setup_claude_is_idempotent_and_keeps_existing_settings(tmp_path, env):
    import json
    cdir = Path(env["CLAUDE_CONFIG_DIR"])
    cdir.mkdir(parents=True)
    (cdir / "settings.json").write_text(json.dumps({"model": "sonnet", "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "other-tool"}]}]}}), encoding="utf-8")
    (cdir / "CLAUDE.md").write_text("# My rules\n\n- keep this line\n", encoding="utf-8")
    first = lg(tmp_path, env, "setup-claude")
    assert first.returncode == 0 and "changed" in first.stdout, first.stderr
    s = json.loads((cdir / "settings.json").read_text(encoding="utf-8"))
    cmds = [h["command"] for e in s["hooks"]["SessionStart"] for h in e["hooks"]]
    assert s["model"] == "sonnet" and "other-tool" in cmds and sum("session-check" in c for c in cmds) == 1
    assert (cdir / "settings.json.bak-leakguard").exists()
    md = (cdir / "CLAUDE.md").read_text(encoding="utf-8")
    assert "keep this line" in md and "公開（public）リポジトリへは原則 push しない" in md
    assert (cdir / "skills" / "leakguard-init" / "SKILL.md").exists()
    again = lg(tmp_path, env, "setup-claude")
    assert "already up to date" in again.stdout
    assert (cdir / "CLAUDE.md").read_text(encoding="utf-8") == md  # block replaced in place, not appended twice


def test_setup_claude_refreshes_a_stale_block(tmp_path, env):
    cdir = Path(env["CLAUDE_CONFIG_DIR"])
    lg(tmp_path, env, "setup-claude")
    md = cdir / "CLAUDE.md"
    text = md.read_text(encoding="utf-8")
    a, z = text.index("<!-- leakguard:begin"), text.index("<!-- leakguard:end -->")
    md.write_text(text[:a] + text[a:z].replace("絶対に push しない", "STALE") + text[z:], encoding="utf-8")
    lg(tmp_path, env, "setup-claude")
    assert "STALE" not in md.read_text(encoding="utf-8")


def test_merge_words_unions_without_duplicates():
    merged, n = leakguard.merge_words("# mine\nAlpha\n", "# theirs\nalpha\nbeta\n\ngamma\n")
    assert n == 2 and merged == "# mine\nAlpha\nbeta\ngamma\n"
    assert leakguard.merge_words("", "x\n") == ("x\n", 1)


def test_selftest_passes_on_a_set_up_machine(tmp_path, env):
    assert lg(tmp_path, env, "setup-global").returncode == 0
    (Path(env["LEAKGUARD_HOME"]) / "words").write_text("some-real-name\n", encoding="utf-8")
    r = lg(tmp_path, env, "selftest")
    assert r.returncode == 0 and "all good" in r.stdout and "FAIL" not in r.stdout, r.stdout + r.stderr


def test_setup_claude_survives_an_unwritable_skills_dir(tmp_path, env):
    cdir = Path(env["CLAUDE_CONFIG_DIR"])
    cdir.mkdir(parents=True)
    (cdir / "skills").write_text("a file where the skills directory should be\n", encoding="utf-8")  # mkdir under it fails
    r = lg(tmp_path, env, "setup-claude")
    assert r.returncode == 0, r.stderr
    assert "skill not installed" in r.stdout
    assert "leakguard:begin" in (cdir / "CLAUDE.md").read_text(encoding="utf-8") and (cdir / "settings.json").exists()


def test_init_writes_agent_rules_into_agents_md_without_touching_other_content(tmp_path, env):
    d = new_repo(tmp_path, env)
    (d / "AGENTS.md").write_text("# Project agent notes\n\n- run the tests before committing\n", encoding="utf-8")
    assert lg(d, env, "init", str(d)).returncode == 0
    md = (d / "AGENTS.md").read_text(encoding="utf-8")
    assert "run the tests before committing" in md and "--no-verify" in md and "公開（public）リポジトリへは原則 push しない" in md
    again = lg(d, env, "init", str(d)).stdout
    assert "= AGENTS.md" in again and (d / "AGENTS.md").read_text(encoding="utf-8") == md  # block replaced in place, not appended twice
    d2 = new_repo(tmp_path, env, name="fresh")
    lg(d2, env, "init", str(d2))
    assert (d2 / "AGENTS.md").read_text(encoding="utf-8").startswith("# AGENTS.md")


def test_setup_agents_writes_the_codex_global_rules_idempotently(tmp_path, env):
    codex = Path(env["CODEX_HOME"])
    codex.mkdir()
    (codex / "AGENTS.md").write_text("# mine\n\n- keep me\n", encoding="utf-8")
    assert "changed" in lg(tmp_path, env, "setup-agents").stdout
    md = (codex / "AGENTS.md").read_text(encoding="utf-8")
    assert "keep me" in md and "--no-verify" in md
    assert "already up to date" in lg(tmp_path, env, "setup-agents").stdout
    assert (codex / "AGENTS.md").read_text(encoding="utf-8") == md
