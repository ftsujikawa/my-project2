# .codex/plans/2026-05-14-add-passkey.md

## Goal

認証フローに WebAuthn (パスキー) を追加する。

## Constraints

- 既存のメール+パスワードログインは温存
- DB マイグレーション必要、down 可能なこと
- `pnpm typecheck` / `pnpm test` / `pnpm e2e` すべて緑

## Steps

1. ER 設計: `passkeys` テーブル追加 (user_id, credential_id, public_key, sign_count)
2. マイグレーション生成 (drizzle-kit)
3. 登録 API `/api/passkey/register` 追加 (challenge 発行→検証→保存)
4. 認証 API `/api/passkey/authenticate` 追加
5. UI: アカウント画面に「パスキーを追加」ボタン
6. UI: ログイン画面に「パスキーでログイン」ボタン
7. unit テスト 4 本、playwright e2e 1 本

## Risks
- WebAuthn の RP ID 設定ミス → 開発環境で動かない可能性
- sign_count 検証漏れ → リプレイ攻撃の温床
- 既存セッション機構との二重実装による不整合
