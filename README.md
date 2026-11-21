English | [日本語](README.ja.md)
# leakguard

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)
![Platform: Windows | macOS | Linux](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)

A harness that keeps personal information and secrets out of git / GitHub — installed into any repository with one command.

It mechanically blocks commits and pushes that contain real names, e-mail addresses, private IPs, or secrets, instead of relying on human or LLM attention.

## Features

- **Pure Python standard library** — no dependencies for the tool itself
- Secret scanning by [gitleaks](https://github.com/gitleaks/gitleaks), installed at a pinned version with checksum verification
- **Real-name list**: list your own host names, user names, real IPs and e-mail addresses; a commit is stopped if any of them appears in the diff, a file name, the commit message, or the author identity
- **Pushes to public repositories are refused by default** (visibility is checked with `gh`; anything not confirmed private is refused). The only exception is the owner's `approve-publish` (clean audit + valid for one push within one hour)
- **Pre-publication audit (`audit`)**: checks secrets, personal information, unwanted files, committer identities, LICENSE and more, and reports PASS / WARN / BLOCK
- Idempotent: running any setup command again produces the same result; existing files are never overwritten silently — differences are reported

## Requirements

| Item | Requirement |
|---|---|
| OS | Windows 10 / 11, macOS, or Linux (x64 or ARM64) |
| Python | 3.9 or later (standard library only) |
| Git | Required |
| gitleaks | Installed automatically at pinned v8.30.1 with checksum verification on first setup (a `gitleaks` already on PATH is also used) |
| GitHub CLI (`gh`) | Optional. Used to check push-target visibility and for `pull-words`. Without it, pushes to GitHub are refused as "cannot be confirmed" |

## Installation

```sh
git clone https://github.com/ramp-007/leakguard.git
cd leakguard
python leakguard.py setup-global   # once per machine: central copy + gitleaks + git template
python leakguard.py setup-claude   # optional: Claude Code integration (skill, rules, SessionStart hook)
```

On Windows, `py -3` works in place of `python`.

## Quick start

```sh
python leakguard.py init <repo>    # install the harness into an existing repository
python leakguard.py survey <dir>   # list the repositories under a directory and their setup status
```

What `init` generates:

| File | Role |
|---|---|
| `scripts/leakguard.py` etc. | A copy of the engine (self-contained per repository; CI does not depend on anything external) |
| `.gitleaks.toml` | gitleaks default rules plus e-mail, private/Tailscale IPs, home directories, `*.ts.net`, `DESKTOP-xxxx`, MAC addresses, SSH public keys |
| `.githooks/pre-commit` `commit-msg` `pre-push` | Checks before commit, on the message, and before push (sets `core.hooksPath`) |
| `.github/workflows/leakguard.yml` | Checks the whole history on GitHub (the last line of defense) |
| `docs/LEAK_GUARD.md` | Usage notes for that repository (currently Japanese) |
| `.gitignore` / `.gitattributes` | Ignores `.leakwords` and `.tools/`; pins hooks to LF |
| git `user.email` | If set to a real-name address, replaced with a placeholder **for that repository only** |

## What is checked

See [docs/LEAK_GUARD.md](docs/LEAK_GUARD.md) (Japanese) for details. In short:

1. **gitleaks** (default rules + custom rules; placeholders are allow-listed)
2. **Your real-name list** (below)
3. **Commit author / committer e-mail** must be an `@example.com` placeholder or a GitHub noreply address (gitleaks does not inspect identities or messages, so leakguard checks them itself)
4. **Push-target visibility** (pushes to public repositories are refused by default)

### Profiles

- `strict` (default): everything above; real names, private IPs and host names are refused
- `private`: enabled with `init --private`, and only takes effect when every GitHub remote is confirmed private/internal. Allows private/Tailscale IPs and host names (secrets, e-mail addresses and home paths are still refused). Falls back to strict whenever anything cannot be confirmed

### Real-name list (never committed)

Write your real names (host names, user names, real IPs, e-mail addresses), one per line:

- `~/.config/leakguard/words` — shared by all repositories
- `<repo>/.leakwords` — per repository (`init` adds it to .gitignore)

These files themselves are never committed.

## Commands

Run `python leakguard.py` for the full list.

| Command | Purpose |
|---|---|
| `setup-global` | Install on this machine (new `git init` / `git clone` repositories get the hooks automatically) |
| `setup-claude` / `setup-agents` | Integration for Claude Code / Codex and other agents |
| `init [path]` | Install the harness into a repository (`--update` refreshes generated files; `--private` selects the private profile) |
| `survey [dir]` | List setup status of repositories below a directory |
| `audit [--history] [--json]` | Pre-publication audit (PASS / WARN / BLOCK) |
| `approve-publish` | Owner only: allow one public push of the current HEAD after a clean audit |
| `pull-words <host>` | Fetch the real-name list from another machine over ssh (never via GitHub) |
| `selftest` | Verify that a brand-new repository on this machine is protected |
| `session-check` | For agent start-up hooks: warn when the current repository has no harness |

## Installing on another machine

The tool, rules, hooks and CI template are installed by cloning this repository.
**The real-name list never travels through GitHub** (use `pull-words` over ssh, or copy it by hand).

```sh
gh auth login
git clone https://github.com/ramp-007/leakguard.git ~/leakguard
python ~/leakguard/leakguard.py setup-global
python ~/leakguard/leakguard.py setup-claude        # optional
python ~/.config/leakguard/leakguard.py pull-words <ssh host that has your word list>
python ~/.config/leakguard/leakguard.py survey ~
```

To update: on each machine, `git pull` → `setup-global` → `setup-claude`; in each repository, `init --update`.

## AI agent integration

- Registering `session-check` as a SessionStart hook warns, in context, when a session starts in a repository without the harness
- The `leakguard-init` skill runs the installation procedure as-is
- The `oss-publish-guard` skill and a PreToolUse hook run `audit --history` before publication actions (such as `gh repo edit --visibility public`) and refuse them on BLOCK

## Tests

```sh
pytest tests/
```

The tests use real git, hooks and gitleaks against throwaway repositories, and verify detection, blocking, `init` idempotency, `setup-global` and `survey`. Machine-wide state is isolated with environment variables (`LEAKGUARD_HOME`, `GIT_CONFIG_GLOBAL`).

## Security

If you find a vulnerability or a detection bypass, please do not open a public issue — follow [SECURITY.md](SECURITY.md) instead.

## License

[MIT License](LICENSE)

leakguard uses [gitleaks](https://github.com/gitleaks/gitleaks) (MIT) as its secret-scanning engine. gitleaks is not bundled; it is downloaded from its official release with checksum verification during first setup.
