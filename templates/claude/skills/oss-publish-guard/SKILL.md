---
name: oss-publish-guard
description: Take a repository from "I want to publish this" to published, safely, end to end — the person does not need to remember any steps. Use when the user says things like "公開したい", "OSS にしたい", "GitHub で public にして", "公開しても大丈夫？", "リリースしたい", "make this public", "publish this", "open source this", or before `gh repo edit --visibility public`, `gh release create`, a push to a public remote. Runs the audit (secrets, personal info, files, history, identities, license, dependencies), fixes what it can, hands over to `open-sourcing` for license/docs/CI/release, and tells the person the exact one line they must type themselves.
---

# oss-publish-guard — 公開までを一人で案内する

The person must not have to remember the procedure: run the whole flow below, report in Japanese, and at the end give the **one command only they may run**. Works the same in any agent (Claude Code, Codex, OpenCode, pi, Hermes, dsh): it only runs commands and reads their output. Engine: `~/.config/leakguard/leakguard.py`.

## Flow
1. **Audit with history** from the repository root: `python ~/.config/leakguard/leakguard.py audit --history` (add `--json` to parse). Never judge from a tree-only run: a deleted file is still in history.
   - `[WARN] ... not installed`: ask the user once, then run `python ~/.config/leakguard/leakguard.py install-audit-tools` (gitleaks: `... install`) and audit again.
2. **BLOCK → fix, then audit again.** Show each finding (file:line, cause, fix); never print a secret's value. Fix the working tree yourself when safe (placeholders, `.gitignore`, `git rm --cached`, adding LICENSE after asking which one). If a finding is in history (`history in commit ...`): the credential must be **rotated** by the person, and rewriting history (`git filter-repo`) or recreating the repository needs their explicit approval; never do either on your own. Repeat until no BLOCK.
3. **WARN → list them and let the person decide.** Typical: missing SECURITY.md/.gitignore, images to look at (EXIF, screenshots), third-party licenses and dependency conditions (manual review).
4. **Hand over to `open-sourcing`** (Trail of Bits skill) for license choice, README, SECURITY.md, CI hardening, repository settings and release automation. Apply only what the person agrees to.
5. **Final audit** (step 1 again) and show the verdict.
6. **Tell the person what only they can do**, in this form, with nothing else to remember:
   > 公開の準備ができました（監査: PASS/WARN）。公開するには、あなた自身が次の 1 行を入力してください（AI は実行できません）:
   > `! python ~/.config/leakguard/leakguard.py approve-publish`
   > そのあと 1 時間以内に、公開する操作（`gh repo edit --visibility public` / `git push` / `gh release create`）を私に頼んでください。

   `approve-publish` re-runs the audit and records a one-time approval for the current commit. After the person has run it, you may run the publishing command they asked for (the PreToolUse hook will still ask them to confirm).

## Never
- run `approve-publish` yourself, bypass with `--no-verify`, edit `core.hooksPath`, or remove the audit to get a PASS;
- paste scanner output that contains secret values into chat, commits or logs;
- treat "could not run" as PASS: it is a BLOCK (fail-closed);
- add to `.leakguard-allow` without a written reason (secrets can never be allowed; replace fake secret strings instead).
