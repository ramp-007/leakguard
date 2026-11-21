"""leakguard approve-publish - the one exception to "never push to a public repository".

The PERSON (not an agent) runs `leakguard.py approve-publish` in the repository. It runs `audit --history`; on BLOCK nothing happens.
Otherwise it records an approval bound to the current HEAD commit, valid for one hour and for one push. pre-push accepts a push
to a confirmed-public GitHub repository only with such an approval for exactly the commits being pushed (the normal history checks still run).
Claude Code's PreToolUse hook denies `approve-publish` when an agent tries to run it; other agents are told by the rules not to.
"""
from __future__ import annotations
import json
import time
from pathlib import Path

VALID_SECONDS = 3600


def approval_path(lg) -> Path:
    return Path(lg.git("rev-parse", "--absolute-git-dir").strip()) / "leakguard" / "publish-approval.json"


def approve_publish(lg) -> int:
    from leakguard_audit import run_audit

    if run_audit(lg, ["--history"]) != 0:
        print("\nleakguard: audit says BLOCK; no approval recorded. Fix the findings first.")
        return 1
    head = lg.git("rev-parse", "HEAD").strip()
    if not head:
        print("leakguard: no commit to approve.")
        return 1
    p = approval_path(lg)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"head": head, "expires": int(time.time()) + VALID_SECONDS}), encoding="utf-8")
    print(f"\nleakguard: approved publishing commit {head[:8]} for {VALID_SECONDS // 60} minutes (one push). Push now: git push")
    return 0


def consume_approval(lg, pushed: list[str]) -> bool:
    """True (and the approval is used up) when a fresh approval exists for exactly the commits being pushed."""
    p = approval_path(lg)
    try:
        a = json.loads(p.read_text(encoding="utf-8"))
        ok = bool(pushed) and a["expires"] >= time.time() and all(sha == a["head"] for sha in pushed)
    except (OSError, ValueError, KeyError):
        return False
    if ok:
        p.unlink(missing_ok=True)
    return ok
