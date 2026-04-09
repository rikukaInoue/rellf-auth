# rellf-auth

Cognito を内部に隠した独自 OIDC Provider。複数プロダクトで共通のアカウントを使うための認証基盤。

## 技術スタック

| レイヤー | 技術 |
|---------|------|
| 言語 | Go (Gin) |
| 実行環境 | AWS Lambda (arm64, provided.al2023) |
| API | API Gateway v2 (HTTP API) |
| 認証 | Cognito User Pool + Google OAuth |
| メール | SES (DEVELOPER モード) + CustomMessage Lambda |
| シークレット | SSM Parameter Store |
| IaC | Terraform |
| ドメイン | auth.rikuka.dev |

## アーキテクチャ

- [インフラ構成](architecture-infra.md)
- [エンドポイント・ミドルウェア](architecture-flow.md)
