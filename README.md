# rellf-auth

AWS Cognito ベースの認証 API。OIDC Provider として機能し、メール/パスワード認証、Google OAuth、OpenID 2.0 外部 IdP 連携をサポート。

## 技術スタック

- **Go** (Gin) — API サーバー
- **AWS Cognito** — ユーザー管理・認証
- **AWS Lambda** (arm64, `provided.al2023`) — デプロイ先
- **API Gateway** (HTTP API v2) — エンドポイント公開
- **Amazon SES** — メール送信（確認コード・パスワードリセット）
- **SSM Parameter Store** — 機密情報管理
- **Terraform** — IaC
- **floci** — ローカル開発用 AWS エミュレータ

## アーキテクチャ

```
                    ┌──────────────────────────────────────┐
                    │            クライアントアプリ           │
                    └──────────────────┬───────────────────┘
                                      │ OIDC (Authorization Code + PKCE)
                                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         rellf-auth                                  │
│                                                                     │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │  Router   │→│  Handler   │→│ UseCase  │→│  Domain Model     │  │
│  │          │  │  (OIDC/    │  │          │  │  (User Lifecycle) │  │
│  │          │  │   Admin)   │  │          │  │                   │  │
│  └──────────┘  └───────────┘  └────┬─────┘  └──────────────────┘  │
│                                     │                               │
│                                     ▼                               │
│                              ┌─────────────┐                       │
│                              │  Cognito     │                       │
│                              │  Client      │                       │
│                              └──────┬──────┘                       │
└─────────────────────────────────────┼───────────────────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                  ▼
            ┌──────────┐     ┌──────────────┐    ┌───────────┐
            │ Cognito   │     │ SSM Parameter│    │ Google    │
            │ User Pool │     │ Store        │    │ OAuth     │
            └─────┬────┘     └──────────────┘    └───────────┘
                  │
        ┌─────────┼──────────┐
        ▼         ▼          ▼
 ┌──────────┐ ┌────────┐ ┌─────────────┐
 │ PreSignup│ │CustomMsg│ │ SES         │
 │ Trigger  │ │Trigger  │ │ (DKIM)      │
 │          │ │(HTML)   │ │ no-reply@   │
 └──────────┘ └────────┘ │ rikuka.dev  │
                          └─────────────┘
```

### 連携サービス

```
rellf-auth ◄──JWT検証──► rellf-authz (認可サービス / AVP)
                          https://authz.rikuka.dev

rellf-auth ◄──OIDC────► クライアントアプリ
                          例: harmony-etml, 管理ツール等
```

## ディレクトリ構成

```
cmd/
  lambda/main.go              # Lambda エントリポイント
  server/main.go              # ローカル開発用サーバー
  trigger/presignup/          # Pre Sign-up Lambda トリガー
  trigger/custommessage/      # CustomMessage Lambda トリガー（メール文面カスタマイズ）
internal/
  domain/                     # ドメインモデル（User Lifecycle）
    user.go                   #   User interface + 状態別 struct
    credential.go             #   認証情報（パスワード/MFA）
    role.go                   #   ロール管理（RoleSet）
    session.go                #   セッション・ログイン履歴
    audit.go                  #   監査イベント
  usecase/                    # ユースケース層
    user.go                   #   ユーザー操作（状態遷移 + Cognito 連携）
  handler/                    # 認証 API ハンドラー
  admin/                      # 管理画面ハンドラー
  oidc/                       # OIDC Provider エンドポイント
  cognito/                    # Cognito SDK ラッパー
    client.go                 #   認証操作（Service interface）
    admin.go                  #   管理操作（AdminService interface）
  middleware/                 # JWT 検証・CORS・Basic Auth
  config/                     # 環境変数 + SSM 解決
  router/                     # ルーティング定義
terraform/                    # Terraform 構成
docs/                         # アーキテクチャ図・手順書
```

## ユースケースと Cognito API の対応

### ユーザーライフサイクル

| ユースケース | ドメイン遷移 | Cognito API |
|-------------|-------------|-------------|
| ユーザー取得 | → `User` interface | `AdminGetUser` |
| ユーザー一覧 | → `[]User` | `ListUsers` |
| アカウント確認 | `PendingUser` → `ActiveUser` | `AdminConfirmSignUp` |
| 一時停止 | `ActiveUser` → `SuspendedUser` | `AdminDisableUser` |
| 復帰 | `SuspendedUser` → `ActiveUser` | `AdminEnableUser` |
| 削除 | `ActiveUser/SuspendedUser` → `DeletedUser` | `AdminDeleteUser` |
| ログイン検証 | `ActiveUser` のみ許可 | `InitiateAuth` (USER_PASSWORD_AUTH) |
| ログイン記録 | `ActiveUser.RecordLogin()` | — (ドメインのみ) |

### ロール管理

| ユースケース | ドメイン操作 | Cognito API |
|-------------|-------------|-------------|
| ロール追加 | `RoleSet.Add()` | `AdminAddUserToGroup` |
| ロール削除 | `RoleSet.Remove()` | `AdminRemoveUserFromGroup` |
| ロール確認 | `RoleSet.HasRole()` | `AdminListGroupsForUser` |

### 認証情報

| ユースケース | ドメイン操作 | Cognito API |
|-------------|-------------|-------------|
| パスワードリセット | `Credential.PasswordReset()` | `AdminResetUserPassword` |
| メール登録 | `ActiveUser.Email` 更新 | `AdminUpdateUserAttributes` |
| ユーザー作成 | → `PendingUser` | `AdminCreateUser` |

### OIDC フロー

| ユースケース | ドメイン操作 | Cognito API |
|-------------|-------------|-------------|
| 認証 (パスワード) | `ValidateLoginState()` | `InitiateAuth` |
| 認証 (Google OAuth) | `ValidateLoginState()` | OAuth 2.0 フロー |
| 認証 (OpenID 2.0) | `ValidateLoginState()` | — (外部 OP) + `AdminLinkProviderForUser` |
| メール登録促進 | `RegisterEmail()` | `AdminUpdateUserAttributes` |
| トークン発行 | — | — (rellf-auth 自前署名) |

### 外部 IdP 連携

| ユースケース | Cognito API |
|-------------|-------------|
| 外部 ID リンク | `AdminLinkProviderForUser` |
| 外部 ID リンク解除 | `AdminDisableProviderForUser` |
| リンク済みプロバイダ一覧 | `AdminGetUser` → `identities` 属性 |
| アカウント統合 | `AdminDisableProviderForUser` + `AdminLinkProviderForUser` + `AdminDeleteUser` |

### 監査イベント

| イベント種別 | タイミング |
|-------------|-----------|
| `signup` | ユーザー登録時 |
| `confirm` | アカウント確認時 |
| `login` | ログイン成功時 |
| `suspend` | 一時停止時 |
| `reactivate` | 復帰時 |
| `delete` | 削除時 |
| `role_add` | ロール追加時 |
| `role_remove` | ロール削除時 |
| `password_reset` | パスワードリセット時 |

## API エンドポイント

### OIDC Provider

| メソッド | パス | 説明 |
|---------|------|------|
| GET | `/.well-known/openid-configuration` | OIDC Discovery |
| GET | `/oidc/jwks.json` | JWKS (公開鍵) |
| GET | `/oidc/authorize` | 認可エンドポイント (ログイン画面) |
| POST | `/oidc/authorize` | ログイン処理 |
| POST | `/oidc/register-email` | メールアドレス登録 |
| POST | `/oidc/register-email-skip` | メール登録スキップ |
| POST | `/oidc/token` | トークン交換 |
| GET | `/oidc/userinfo` | ユーザー情報 |

### 認証 API

| メソッド | パス | 説明 |
|---------|------|------|
| POST | `/auth/signup` | ユーザー登録 |
| POST | `/auth/confirm-signup` | メール確認 |
| POST | `/auth/login` | ログイン |
| POST | `/auth/forgot-password` | パスワードリセット要求 |
| POST | `/auth/confirm-forgot-password` | パスワードリセット確認 |
| GET | `/auth/oauth/google` | Google OAuth リダイレクト |
| GET | `/auth/oauth/callback` | OAuth コールバック |

### 保護 API (`Authorization: Bearer <token>`)

| メソッド | パス | 説明 |
|---------|------|------|
| GET | `/api/me` | ユーザー情報取得 |
| GET | `/api/providers` | リンク済みプロバイダ一覧 |
| GET | `/api/link/google` | Google アカウントリンク |
| DELETE | `/api/link/:provider` | プロバイダリンク解除 |

### 管理画面 (`/admin`)

| パス | 説明 |
|------|------|
| `/admin/login` | 管理者ログイン |
| `/admin/users` | ユーザー一覧・検索 |
| `/admin/users/new` | ユーザー作成 |
| `/admin/users/:username` | ユーザー詳細・操作 |

## ローカル開発

### 前提条件

- Go 1.21+
- Docker
- AWS CLI

### floci を使ったローカル開発（推奨）

```bash
make floci-setup    # floci 起動 + Cognito リソース作成 + .env.local 生成
make dev-local      # ローカルサーバー起動
```

### AWS 直接接続での開発

```bash
cp .env.example .env
# .env を編集
make dev
```

## テスト

```bash
make test           # floci 起動 + 結合テスト実行
```

## ビルド・デプロイ

```bash
make build          # Lambda 用バイナリビルド
make zip            # デプロイ用 zip 作成

cd terraform
terraform init
terraform apply
```
