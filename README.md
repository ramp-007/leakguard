# leakguard

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)
![Platform: Windows | macOS | Linux](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)

個人情報・秘密情報を git / GitHub に入れないためのハーネスを、**任意のリポジトリへ 1 コマンドで入れる**ツール。

A harness that keeps personal information and secrets out of git history — installed into any repository with one command. It mechanically blocks commits and pushes that contain real names, e-mail addresses, private IPs, or secrets, instead of relying on human or LLM attention.

LLM や人の注意に頼らず、コミット・push の時点で機械的に止めるのが目的です。

## 特徴

- **標準ライブラリのみの Python スクリプト**（本体に依存パッケージなし）
- 秘密検出は [gitleaks](https://github.com/gitleaks/gitleaks)（固定バージョンをチェックサム検証して自動導入）
- **実名リスト方式**: 自分のホスト名・ユーザー名・実 IP・実メールをリスト化し、差分・ファイル名・コミットメッセージ・作者名のどこに現れても停止
- **公開リポジトリへの push を原則拒否**（`gh` で可視性を照会し、private と確認できないものも拒否）。公開は本人の `approve-publish`（監査クリーン＋1時間・1回限り）だけが例外
- **公開前監査 `audit`**: 秘密・個人情報・不要ファイル・コミット者・LICENSE 等を PASS / WARN / BLOCK で判定
- 何度実行しても同じ結果（冪等）。既存ファイルは上書きせず、差分を知らせる

## 対応環境

| 項目 | 要件 |
|---|---|
| OS | Windows 10 / 11、macOS、Linux（いずれも x64 / ARM64） |
| Python | 3.9 以上（標準ライブラリのみ） |
| Git | 必須 |
| gitleaks | 初回セットアップ時に固定版 v8.30.1 をチェックサム検証して自動導入（PATH にある場合はそれも可） |
| GitHub CLI (`gh`) | 任意。push 先の可視性照会などに使う。無い場合、GitHub への push は「確認できない」として拒否される |

## インストール

```sh
git clone https://github.com/ramp-007/leakguard.git
cd leakguard
python leakguard.py setup-global   # この PC に1回だけ: 中央コピー配置＋gitleaks導入＋git テンプレート設定
python leakguard.py setup-claude   # 任意: Claude Code 連携（スキル・規則・SessionStart フック）
```

Windows では `python` の代わりに `py -3` でも動きます。

## クイックスタート

```sh
python leakguard.py init <repo>    # 既存リポジトリにハーネス一式を入れる
python leakguard.py survey <dir>   # ディレクトリ配下のリポジトリの導入状況を一覧する
```

`init` が行うこと:

| 生成物 | 役割 |
|---|---|
| `scripts/leakguard.py` ほか | エンジン本体のコピー（そのリポジトリだけで完結。CI も外部に依存しない） |
| `.gitleaks.toml` | gitleaks の既定ルール + メール・私設/Tailscale IP・ホームディレクトリ・`*.ts.net`・`DESKTOP-xxxx`・MAC・SSH 公開鍵 |
| `.githooks/pre-commit` `commit-msg` `pre-push` | コミット前・メッセージ・push 前の検査（`core.hooksPath` を設定） |
| `.github/workflows/leakguard.yml` | GitHub 上で履歴全体を検査（最後の防壁） |
| `docs/LEAK_GUARD.md` | そのリポジトリ向けの使い方 |
| `.gitignore` / `.gitattributes` | `.leakwords`、`.tools/` を無視、フックを LF に固定 |
| git の `user.email` | 本名のメールが設定されていれば、**そのリポジトリだけ** 仮名に |

## 検査の中身

詳しくは [docs/LEAK_GUARD.md](docs/LEAK_GUARD.md)。要点:

1. **gitleaks**（既定ルール + 自作ルール。プレースホルダは allowlist）
2. **実名リスト**（下記）
3. **コミット作者・コミッターのメール**は `@example.com` か GitHub noreply のみ（gitleaks は作者・メッセージを見ないので自前で検査）
4. **push 先の可視性**（公開リポジトリへの push は原則拒否）

### プロファイル

- `strict`（既定）: 上記すべてを適用。実名・私設 IP・ホスト名を拒否
- `private`: `init --private` で指定し、かつ GitHub remote がすべて private/internal と確認できた場合のみ有効。私設/Tailscale IP とホスト名を許可する（秘密・メール・ホームパスは引き続き拒否）。確認できなければ strict に戻る

### 実名リスト（コミットしない）

自分の実名（ホスト名・ユーザー名・実 IP・実メール）を 1 行 1 語で書きます。

- `~/.config/leakguard/words` — **全リポジトリ共通**
- `<repo>/.leakwords` — そのリポジトリだけ（`init` が gitignore する）

このファイル自体は決してコミットされません。

## 主なコマンド

`python leakguard.py` で一覧が出ます。

| コマンド | 用途 |
|---|---|
| `setup-global` | この PC への導入（新しい `git init` / `git clone` に自動でフックが入る） |
| `setup-claude` / `setup-agents` | Claude Code / Codex 等のエージェント連携 |
| `init [path]` | リポジトリへハーネスを導入（`--update` で生成物だけ更新、`--private` で private プロファイル） |
| `survey [dir]` | 配下リポジトリの導入状況を一覧 |
| `audit [--history] [--json]` | 公開前監査（PASS / WARN / BLOCK） |
| `approve-publish` | 本人専用: 監査クリーンな HEAD の公開 push を1回だけ許可 |
| `pull-words <host>` | 実名リストを ssh 経由で別 PC から取り込む（GitHub は経由しない） |
| `selftest` | この PC の新規リポジトリが保護されるか検証 |
| `session-check` | エージェント起動時フック用: ハーネスが無いリポジトリで警告 |

## 別の PC に入れる

ツール本体・ルール・フック・CI のひな形はこのリポジトリから clone して入ります。
**実名リストだけは GitHub を通しません**（`pull-words` で ssh 経由、または手でコピー）。

```sh
gh auth login
git clone https://github.com/ramp-007/leakguard.git ~/leakguard
python ~/leakguard/leakguard.py setup-global
python ~/leakguard/leakguard.py setup-claude        # 任意
python ~/.config/leakguard/leakguard.py pull-words <実名リストのある PC の ssh ホスト>
python ~/.config/leakguard/leakguard.py survey ~
```

ツールを更新したら、各 PC で `git pull` → `setup-global` → `setup-claude`、リポジトリ側は `init --update`。

## AI エージェントとの連携

- `session-check` を SessionStart フックに登録すると、ハーネスが無いリポジトリでセッションを始めたときに警告が文脈に入ります
- スキル `leakguard-init` が導入手順をそのまま実行します
- スキル `oss-publish-guard` と PreToolUse フックが、公開操作（`gh repo edit --visibility public` 等）の前に `audit --history` を走らせ、BLOCK なら拒否します

## テスト

```sh
pytest tests/
```

実際の git・フック・gitleaks を使い、使い捨てのリポジトリで検知・ブロック・`init` の冪等性・`setup-global`・`survey` を検証します。マシン全体の設定は環境変数（`LEAKGUARD_HOME`、`GIT_CONFIG_GLOBAL`）で分離しています。

## セキュリティ

脆弱性や検出漏れを見つけたら、内容を公開 Issue に書かず、[SECURITY.md](SECURITY.md) の手順で報告してください。

## ライセンス

[MIT License](LICENSE)

秘密検出エンジンとして [gitleaks](https://github.com/gitleaks/gitleaks)（MIT）を利用しています。leakguard 本体は gitleaks を同梱せず、初回セットアップ時に公式リリースからチェックサム検証のうえ取得します。
