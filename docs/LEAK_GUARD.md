---
summary: 個人情報・秘密情報が git / GitHub に入らないようにする仕組み（gitleaks + フック + CI）の使い方と設計。
type: spec
status: active
pinned: false
updatedAt: 2026-10-06
---
<!-- leakguard-managed: refresh with `leakguard.py init --update` -->

# leakguard — 個人情報を git に入れない仕組み

導入元: leakguard リポジトリ（`python leakguard.py init` で生成。他のリポジトリへの導入・全体設定もそこから）。

LLM や人の注意に頼らず、**ツールが機械的に止める**。実体は `scripts/leakguard.py`（標準ライブラリのみ）と、[gitleaks](https://github.com/gitleaks/gitleaks)、`.githooks/`、`.github/workflows/leakguard.yml`。

## 3 つの層
| 層 | いつ | 何を見る |
|---|---|---|
| `pre-commit` / `commit-msg` | コミット時 | ステージした差分、ファイル名、コミットメッセージ、作者/コミッターの e-mail |
| `pre-push` | push 時 | これから送る**全コミット**（差分・メッセージ・作者）。`--no-verify` でコミット時の検査をすり抜けた分もここで止まる |
| GitHub Actions | push / PR | 履歴全体（汎用ルールのみ。実名リストは CI に無い） |

## 検査内容
1. **gitleaks の既定ルール**（約 200 種の API キー・トークン・秘密鍵）＋ `.gitleaks.toml` の自作ルール:
   メールアドレス / プライベート・Tailscale IPv4 / ホームディレクトリ（`C:\Users\<名前>`、`/home/<名前>`）/ `*.ts.net` / Windows 既定のコンピュータ名（`DESKTOP-XXXXXXX`）/ MAC アドレス / SSH 公開鍵。
   許可する仮名は各ルールの allowlist に書く（`192.168.1.20`・`192.168.1.30`・`100.64.0.x`・`dev@example.com` など）。
2. **`.leakwords`（コミットしない）**: 自分の実名（ホスト名・ユーザー名・実 IP・実メールなど）を 1 行 1 語で書く。大文字小文字を区別せず、差分・ファイル名・メッセージ・作者名で見つかったら止める。gitleaks の追加ルールにも実行時に変換される（`.git/leakguard/` に生成、コミットされない）。
4. **push 先**: **公開（public）の GitHub リポジトリへの push は原則拒否**する（`gh` で可視性を照会。private/internal と確認できないものも拒否）。GitHub 以外のリモート（ローカル共有など）は照会しない。例外は 1 つだけ: 利用者本人が `python scripts/leakguard.py approve-publish` を実行したとき。`audit --history` が BLOCK でなければ、現在の HEAD に結び付いた承認が 1 時間・1 回の push だけ有効になる。確認できない（unknown）リモートは承認があっても拒否する。AI は実行しない（Claude Code ではフックが拒否する）。
3. **コミットの身元**: 作者・コミッターの e-mail は `@example.com` か `@users.noreply.github.com` のみ。gitleaks は作者やメッセージを見ないので、この部分は leakguard 自身が検査する。

## セットアップ（clone ごとに 1 回）
全リポジトリ共通の実名リストは `~/.config/leakguard/words` に置ける（`.leakwords` と合算される）。
```
python scripts/leakguard.py install        # gitleaks を .tools/ に取得（バージョン固定・チェックサム検証）し、フックを有効化
git config user.name  "Dev"
git config user.email "dev@example.com"
```
`.leakwords` を作る（例は `.leakwords` 自身のコメント参照）。実名の対応表は `LOCAL.md`（これも git-ignore）。

## プロファイル（strict / private）
| | strict（既定・public・不明） | private |
|---|---|---|
| ローカルIP・Tailscale IP、`*.ts.net`、Windows 既定のPC名 | 拒否 | 許可 |
| `.leakwords` の語 | 拒否 | 無視（`always:語` と書いた行だけ拒否） |
| メール、ホームパス、MAC、SSH 公開鍵 | 拒否 | 拒否 |
| API キー・トークン・秘密鍵（gitleaks 既定） | 拒否 | 拒否 |
| public への push | 拒否 | 拒否 |

- private にするには `python scripts/leakguard.py init . --private`（`.leakguard-profile` に `private` と書く。コミットする）。
- private が効くのは、GitHub の remote がすべて private/internal と確認できたとき、または GitHub の remote が無いときだけ。確認できなければ strict に戻る。CI は `LEAKGUARD_VISIBILITY` でリポジトリ自身の可視性を受け取る。
- push しないリポジトリ（Obsidian の Vault など）は `git config leakguard.nopush true` で印を付ける（リポジトリごとの設定で、コミットされない）。セッション開始時の警告は出ず、`init` は何も導入せずに終わり、`push` は拒否される。印を外すには `git config --unset leakguard.nopush`。
- グローバルIP・SSH接続先・ポート番号は検査しない（「必要なときだけ書く」）。

## 運用ルール
- strict のリポジトリでは、文書・コード・テストに**仮名**を使う: `prod-server` / `gpu-pc-1` / `gpu-pc-2` / `sshuser` / `serveruser` / `192.168.1.20` / `192.168.1.30` / `100.64.0.10` など。実名は `LOCAL.md` と `.leakwords`、`config/server.url` にだけ置く。
- 新しい実名（機器・ユーザー・IP）が増えたら、**同じ日に `.leakwords` へ追記**する。
- 許可する仮名を増やすときは `.gitleaks.toml` の allowlist と `OK_EMAIL`（`leakguard.py`）を直す。誤検知を黙らせる目的でルールを緩めない。
- `git commit --no-verify` / `git push --no-verify` / フックの無効化はしない（AI も同様）。止まったら中身を直す。
- 履歴に実名が入ってしまったら、push 前なら履歴を書き換えて消す（`git filter-branch` 等）。**push 済みなら漏れたものとして扱い**、トークン類は失効させる。

## テスト
`tests/test_leakguard.py`: 使い捨ての git リポジトリで、実際の leakguard + gitleaks に、各種の個人情報・秘密を与えてブロックされること、仮名が通ること、フックを迂回したコミットも `pre-push` / `all` で止まること、このリポジトリ自体がクリーンであることを確認する。

## 参考にした実践
- gitleaks の設定拡張: `[extend] useDefault = true` を付けないと自作ルールだけになり既定ルールが動かない（[How to Implement Secret Scanning with gitleaks](https://oneuptime.com/blog/post/2026-01-25-secret-scanning-gitleaks/view)）。
- フレームワークなしのローカル pre-commit フック（[Add a Local Gitleaks Pre-Commit Hook](https://www.d4b.dev/blog/2026-02-01-gitleaks-pre-commit-hook/)）。
- gitleaks の allowlist は `regexTarget = "match"` で値に絞る（`paths` で除外するとファイル全体が検査対象外になる）。
- GitHub のシークレットスキャン（push protection）は個人の private リポジトリでは使えない（GitHub Advanced Security が必要）ため、同じ役割をローカルフックと Actions で補う。

## 公開前の監査（`audit`）
OSS として公開する前に、`python scripts/leakguard.py audit --history` を実行する。判定は **PASS / WARN / BLOCK**（BLOCK なら終了コード 1）。検査が実行できなかったときも BLOCK（fail-closed）。出力は「ファイル:行・原因・修正方法」だけで、秘密の値は出さない。

| 検査 | 内容 |
|---|---|
| 秘密情報 | gitleaks（tracked ファイルと `--history` で履歴）＋ TruffleHog（`install-audit-tools` 後。外部 API での有効性確認は無効） |
| 個人情報 | 実メール、ホームディレクトリのパス、`.leakwords` の語 |
| 不要ファイル | `.env`・鍵・`.npmrc` など（BLOCK）、ログ・DB・バックアップ（WARN）。履歴に残っていれば削除済みでも検出 |
| コミット者 | 作者・コミッターの e-mail が仮名か |
| 公開準備 | LICENSE（無ければ BLOCK）、README、`.gitignore`、SECURITY.md。第三者の著作物・依存ライセンスは自動判定せず WARN で目視を促す |
| 依存の脆弱性 | osv-scanner（`install-audit-tools` 後） |
| 画像 | スクリーンショット等は WARN（EXIF・写り込みを目視） |

- **許可リスト**: `.leakguard-allow` に `<カテゴリ>|<パスの glob>|<理由>` を 1 行ずつ。理由は必須。**秘密情報（secret）は許可できない**。
- **公開操作の監視**: `setup-claude` が Claude Code の PreToolUse フックを入れる。`gh repo edit --visibility public`・`gh repo create --public`・`gh release create`・`gh api`（公開・リリース）・GitHub MCP の同等の操作の前に `audit --history` を走らせ、BLOCK なら拒否、それ以外も利用者の承認を求める（勝手には通さない）。
- Claude Code 以外からの操作は、`pre-push`（public への push は拒否）と、公開後に動く CI の監査ステップで受ける。
- 履歴の書き換え・認証情報の失効は、自動では実行しない。利用者の承認を取る。
- スキル `oss-publish-guard`（`setup-claude` が入れる）が、この手順をエージェントに案内する。
