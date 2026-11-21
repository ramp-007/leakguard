# Security Policy

## Reporting a vulnerability

leakguard の検出漏れ（止めるべきコミット・push が通ってしまう）、誤ったブロック解除、
または leakguard 自体が秘密情報を出力・送信してしまう問題を見つけたら、
**公開 Issue には書かず**、GitHub の Private vulnerability reporting
（このリポジトリの Security タブ → "Report a vulnerability"）で報告してください。

報告には、再現手順と対象バージョン（コミット）を含めてください。
実際の秘密情報そのものは含めないでください（ダミー値で再現できます）。

## Scope notes

- leakguard はローカルで動作し、検査対象の内容を外部に送信しません。
  例外はツールの取得のみです: gitleaks 等を公式リリースから取得し、
  チェックサムを検証してから使います。
- 実名リスト（`~/.config/leakguard/words`、`<repo>/.leakwords`）は
  利用者の PC 上にのみ置かれ、このリポジトリには含まれません。
