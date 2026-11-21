"""leakguard guard-tool - Claude Code PreToolUse hook: audit before a repository is made public or a release is published.

Reads the hook JSON on stdin. Publishing operations (`gh repo edit --visibility public`, `gh repo create --public`,
`gh release create/upload`, `gh api` calls that set visibility or create releases, GitHub MCP tools with the same meaning)
run `leakguard audit --history` first: BLOCK -> deny; PASS / WARN -> ask the person (never allowed silently).
Anything else is passed through untouched. If the audit itself breaks, a publishing operation is denied (fail-closed).
This hook is not the only layer: pre-push and CI cover tools other than Claude Code.
"""
from __future__ import annotations
import json
import re
import subprocess
import sys
from pathlib import Path

PUBLISH = [
    re.compile(r"\bgh\s+repo\s+(?:edit|create)\b[^\n;&|]*?--(?:visibility[ =]+public|public)\b"),
    re.compile(r"\bgh\s+repo\s+edit\b[^\n;&|]*--accept-visibility-change-consequences"),
    re.compile(r"\bgh\s+release\s+(?:create|upload|edit)\b"),
    re.compile(r"\bgit\s+push\b[^\n;&|]*\s--(?:tags|follow-tags)\b"),
]
GH_API = re.compile(r"\bgh\s+api\b[^\n;&|]*")
GH_WRITES = re.compile(r"(?:-X|--method)[ =]*(?:POST|PATCH|PUT)|\s(?:-f|-F|--field|--raw-field|--input)\b", re.I)
GH_TARGET = re.compile(r"releases\b|visibility|\bprivate\s*=\s*false|\"private\"\s*:\s*false")
MCP_PUBLISH = re.compile(r"(?:create|update)_(?:release|repository)|visibility|publish", re.I)


def is_publish(tool: str, tool_input: dict) -> bool:
    if tool == "Bash":
        cmd = str(tool_input.get("command", ""))
        if any(p.search(cmd) for p in PUBLISH):
            return True
        return any(GH_WRITES.search(m.group(0)) and GH_TARGET.search(m.group(0)) for m in GH_API.finditer(cmd))  # read-only `gh api` GETs are not publishing
    return tool.startswith("mcp__") and "github" in tool.lower() and bool(MCP_PUBLISH.search(tool))


def decision(kind: str, reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": kind, "permissionDecisionReason": reason}}, ensure_ascii=False))


def run_guard(engine: Path, stdin_text: str) -> int:
    try:
        ev = json.loads(stdin_text)
        tool, tin = str(ev.get("tool_name", "")), ev.get("tool_input") or {}
    except ValueError:
        return 0  # not a hook payload: nothing to judge
    if tool == "Bash" and re.search(r"\bapprove-publish\b", str(tin.get("command", ""))):
        decision("deny", "approve-publish is the person's decision, not an agent's. Ask the user to run it themselves (in Claude Code: type `! python ~/.config/leakguard/leakguard.py approve-publish`).")
        return 0
    if not is_publish(tool, tin):
        return 0
    cwd = str(ev.get("cwd") or ".")
    try:
        r = subprocess.run([sys.executable, str(engine), "audit", "--history"], cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800)
        summary = "\n".join(l for l in r.stdout.splitlines() if l.startswith("[BLOCK]") or l.startswith("leakguard audit:"))[:2000]
        if r.returncode != 0:
            decision("deny", f"leakguard audit says BLOCK; publishing refused. Fix the findings (run `python {engine} audit --history`), then retry.\n{summary}")
        else:
            decision("ask", f"leakguard audit did not find a blocker ({summary.splitlines()[-1] if summary else 'WARN/PASS'}). Publishing is irreversible: confirm yourself.")
    except (OSError, subprocess.TimeoutExpired) as e:
        decision("deny", f"leakguard audit could not run ({type(e).__name__}); publishing refused (fail-closed).")
    return 0
