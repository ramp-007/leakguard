"""leakguard audit: PASS / WARN / BLOCK in throw-away repositories (fake secrets built at run time)."""
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_leakguard import MAIL_OK, MAIL_REAL, env, lg, new_repo, sh  # noqa: E402,F401

FAKE_PAT = "ghp_" + "R2d7Kx9QmZ4vB1nLc8WfT3yHs6UjPa0EoXiN"


def clean_repo(tmp_path, env):
    d = new_repo(tmp_path, env)
    for name, text in (("README.md", "# demo\n"), ("LICENSE", "MIT\n"), (".gitignore", ".env\n"), ("SECURITY.md", "report to dev\n")):
        (d / name).write_text(text, encoding="utf-8")
    sh(d, "add", "-A", env=env)
    sh(d, "commit", "-q", "-m", "init", env=env, check=False)
    sh(d, "commit", "-q", "--allow-empty", "-m", "x", env=env, check=False)
    return d


def audit(d, env, *a):
    return lg(d, env, "audit", "--json", *a)


def test_clean_repo_has_no_block(tmp_path, env):
    d = clean_repo(tmp_path, env)
    r = audit(d, env)
    out = json.loads(r.stdout)
    assert out["verdict"] in ("PASS", "WARN") and r.returncode == 0


def test_secret_and_personal_info_block_and_values_are_not_printed(tmp_path, env):
    d = clean_repo(tmp_path, env)
    (d / "app.py").write_text(f'token = "{FAKE_PAT}"\nmail = "{MAIL_REAL}"\n', encoding="utf-8")
    (d / ".env").write_text("A=1\n", encoding="utf-8")
    sh(d, "add", "-f", "app.py", ".env", env=env)
    r = audit(d, env)
    assert r.returncode == 1 and json.loads(r.stdout)["verdict"] == "BLOCK"
    assert FAKE_PAT not in r.stdout + r.stderr and MAIL_REAL not in r.stdout + r.stderr
    cats = {(f["category"], f["file"]) for f in json.loads(r.stdout)["findings"]}
    assert ("secret", "app.py") in cats and ("personal", "app.py") in cats and ("file", ".env") in cats


def test_secrets_cannot_be_allow_listed_but_other_findings_can(tmp_path, env):
    d = clean_repo(tmp_path, env)
    (d / "app.py").write_text(f'token = "{FAKE_PAT}"\n', encoding="utf-8")
    (d / "docs.md").write_text(f"contact {MAIL_REAL}\n", encoding="utf-8")
    (d / ".leakguard-allow").write_text("secret|app.py|nope\npersonal|docs.md|public contact address, reviewed\n", encoding="utf-8")
    sh(d, "add", "-A", env=env)
    found = {(f["category"], f["file"]) for f in json.loads(audit(d, env).stdout)["findings"]}
    assert ("secret", "app.py") in found and ("personal", "docs.md") not in found


def test_missing_gitleaks_is_a_block_not_a_pass(tmp_path, env):
    d = clean_repo(tmp_path, env)
    r = audit(d, {**env, "LEAKGUARD_GITLEAKS": "", "LEAKGUARD_HOME": str(tmp_path / "nowhere"), "PATH": str(Path(sys.executable).parent) + os.pathsep + str(Path(shutil.which("git")).parent)})
    assert r.returncode == 1 and "gitleaks is not installed" in r.stdout


def test_history_with_a_real_author_email_is_a_block(tmp_path, env):
    d = clean_repo(tmp_path, env)
    sh(d, "config", "user.email", MAIL_REAL, env=env)
    sh(d, "commit", "-q", "--allow-empty", "--no-verify", "-m", "x", env=env, check=False)
    r = audit(d, env, "--history")
    assert any(f["category"] == "identity" for f in json.loads(r.stdout)["findings"])


def hook(d, env, command, tool="Bash"):
    payload = json.dumps({"tool_name": tool, "tool_input": {"command": command}, "cwd": str(d)})
    r = lg(d, env, "guard-tool", stdin=payload)
    return r, (json.loads(r.stdout)["hookSpecificOutput"] if r.stdout.strip() else None)


def test_guard_ignores_ordinary_commands(tmp_path, env):
    d = clean_repo(tmp_path, env)
    r, out = hook(d, env, "ls -la && git status")
    assert r.returncode == 0 and out is None


def test_guard_asks_when_audit_has_no_blocker_and_denies_on_block(tmp_path, env):
    d = clean_repo(tmp_path, env)
    for cmd in ("gh repo edit me/x --visibility public --accept-visibility-change-consequences", "gh release create v1 --notes x", "gh api -X PATCH repos/me/x -f private=false"):
        assert hook(d, env, cmd)[1]["permissionDecision"] == "ask", cmd
    (d / "app.py").write_text(f'token = "{FAKE_PAT}"\n', encoding="utf-8")
    sh(d, "add", "-f", "app.py", env=env)
    out = hook(d, env, "gh repo edit me/x --visibility public")[1]
    assert out["permissionDecision"] == "deny" and FAKE_PAT not in out["permissionDecisionReason"]


def test_guard_denies_publishing_when_the_audit_cannot_run(tmp_path, env):
    d = tmp_path / "plain"
    d.mkdir()
    out = hook(d, {**env, "LEAKGUARD_GITLEAKS": "", "LEAKGUARD_HOME": str(tmp_path / "nowhere"), "PATH": str(Path(sys.executable).parent) + os.pathsep + str(Path(shutil.which("git")).parent)}, "gh release create v1")[1]
    assert out["permissionDecision"] == "deny"


def test_betterleaks_adds_a_second_engine_when_installed(tmp_path, env):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import leakguard
    import leakguard_audit
    bl = leakguard_audit.find_tool(leakguard, "betterleaks")
    if not bl:
        pytest.skip("betterleaks not installed (run: leakguard.py install-audit-tools)")
    d = clean_repo(tmp_path, env)
    (d / "app.py").write_text('password = "Sup3r$ecretPassw0rd!2024"\n', encoding="utf-8")
    sh(d, "add", "-f", "app.py", env=env)
    r = audit(d, {**env, "LEAKGUARD_BETTERLEAKS": bl})
    assert any(f["file"] == "app.py" and f["category"] == "secret" for f in json.loads(r.stdout)["findings"])


def test_guard_denies_an_agent_running_approve_publish(tmp_path, env):
    d = clean_repo(tmp_path, env)
    out = hook(d, env, "python ~/.config/leakguard/leakguard.py approve-publish")[1]
    assert out["permissionDecision"] == "deny"


@pytest.mark.parametrize("cmd,publishes", [
    ("gh api repos/o/r/releases/latest", False), ("gh api repos/o/r --jq .visibility", False),
    ("gh api -X PATCH repos/o/r -f private=false", True), ("gh api repos/o/r/releases -f tag_name=v1", True), ("gh api --method POST repos/o/r/releases", True),
])
def test_guard_does_not_treat_read_only_gh_api_as_publishing(cmd, publishes):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import leakguard_guard
    assert leakguard_guard.is_publish("Bash", {"command": cmd}) is publishes
