# Security Policy

## Reporting a vulnerability

If you find a detection bypass (a commit or push that should have been stopped going through), a way to defeat a block, or a problem where leakguard itself outputs or transmits secret information, please **do not open a public issue**. Use GitHub's Private vulnerability reporting instead (this repository's Security tab → "Report a vulnerability").

Please include reproduction steps and the affected version (commit). Do not include real secrets — dummy values reproduce the same behavior.

## Scope notes

- leakguard runs locally and never sends the content it inspects anywhere. The only exception is tool download: gitleaks and related tools are fetched from their official releases and verified by checksum before use.
- The real-name lists (`~/.config/leakguard/words`, `<repo>/.leakwords`) exist only on the user's machines and are not part of this repository.

---

## 脆弱性の報告（日本語）

leakguard の検出漏れ（止めるべきコミット・push が通ってしまう）、誤ったブロック解除、または leakguard 自体が秘密情報を出力・送信してしまう問題を見つけたら、**公開 Issue には書かず**、GitHub の Private vulnerability reporting（このリポジトリの Security タブ → "Report a vulnerability"）で報告してください。

報告には、再現手順と対象バージョン（コミット）を含めてください。実際の秘密情報そのものは含めないでください（ダミー値で再現できます）。

- leakguard はローカルで動作し、検査対象の内容を外部に送信しません。例外はツールの取得のみです: gitleaks 等を公式リリースから取得し、チェックサムを検証してから使います。
- 実名リスト（`~/.config/leakguard/words`、`<repo>/.leakwords`）は利用者の PC 上にのみ置かれ、このリポジトリには含まれません。
