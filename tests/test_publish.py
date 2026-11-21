"""The exception to "never push to a public repository": a fresh approval by the person, for exactly these commits, after a clean audit."""
import io
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_leakguard import env, new_repo, sh  # noqa: E402,F401

import leakguard  # noqa: E402
import leakguard_publish  # noqa: E402

ZERO = "0" * 40


def ready_repo(tmp_path, env, monkeypatch, vis="public"):
    d = new_repo(tmp_path, env)
    for name, text in (("README.md", "# demo\n"), ("LICENSE", "MIT\n"), (".gitignore", ".env\n"), ("SECURITY.md", "report to dev\n")):
        (d / name).write_text(text, encoding="utf-8")
    sh(d, "add", "-A", env=env)
    sh(d, "commit", "-q", "-m", "init", env=env, check=False)
    sh(d, "remote", "add", "origin", "https://github.com/o/r.git", env=env)
    monkeypatch.setattr(leakguard, "ROOT", d)
    monkeypatch.setattr(leakguard, "github_visibility", lambda o, r: vis)
    return d, sh(d, "rev-parse", "HEAD", env=env).stdout.strip()


def push(head):
    sys.stdin = io.StringIO(f"refs/heads/master {head} refs/heads/master {ZERO}\n")
    return leakguard.cmd_push("origin")


def test_public_push_is_refused_without_approval(tmp_path, env, monkeypatch):
    d, head = ready_repo(tmp_path, env, monkeypatch)
    assert push(head) == 1


def test_approval_allows_exactly_one_push_of_that_commit(tmp_path, env, monkeypatch):
    d, head = ready_repo(tmp_path, env, monkeypatch)
    assert leakguard_publish.approve_publish(leakguard) == 0
    assert push(head) == 0
    assert push(head) == 1  # used up


def test_approval_is_bound_to_the_approved_commit_and_expires(tmp_path, env, monkeypatch):
    d, head = ready_repo(tmp_path, env, monkeypatch)
    leakguard_publish.approve_publish(leakguard)
    assert push("1" * 40) == 1  # another commit
    p = leakguard_publish.approval_path(leakguard)
    p.write_text(json.dumps({"head": head, "expires": int(time.time()) - 1}), encoding="utf-8")
    assert push(head) == 1  # stale


def test_no_approval_is_recorded_when_the_audit_blocks(tmp_path, env, monkeypatch):
    d, head = ready_repo(tmp_path, env, monkeypatch)
    (d / "LICENSE").unlink()
    sh(d, "add", "-A", env=env)
    sh(d, "commit", "-q", "-m", "rm license", env=env, check=False)
    assert leakguard_publish.approve_publish(leakguard) == 1
    assert not leakguard_publish.approval_path(leakguard).exists()


def test_an_unconfirmed_remote_cannot_be_unlocked_by_approval(tmp_path, env, monkeypatch):
    d, head = ready_repo(tmp_path, env, monkeypatch, vis=None)
    leakguard_publish.approve_publish(leakguard)
    assert push(head) == 1
