# rellf-auth

AWS Cognito ベースの認証 API。メール/パスワード認証と Google OAuth をサポート。

## 技術スタック

- **Go** (Gin) — API サーバー
- **AWS Cognito** — ユーザー管理・認証
- **AWS Lambda** (arm64, `provided.al2023`) — デプロイ先
- **API Gateway** (HTTP API v2) — エンドポイント公開
- **SSM Parameter Store** — 機密情報管理
- **Terraform** — IaC
- **floci** — ローカル開発用 AWS エミュレータ

## ディレクトリ構成

```
cmd/
  lambda/main.go          # Lambda エントリポイント
  server/main.go          # ローカル開発用サーバー
  trigger/presignup/      # Pre Sign-up Lambda トリガー（アカウント自動リンク）
internal/
  handler/                # HTTP ハンドラー
  middleware/jwt.go       # JWT 検証ミドルウェア
  cognito/client.go       # Cognito SDK ラッパー
  config/config.go        # 環境変数 + SSM 解決
  router/router.go        # ルーティング定義
terraform/                # Terraform 構成
scripts/setup-local.sh    # floci ローカル環境セットアップ
docs/                     # Swagger 自動生成ドキュメント
```

## API エンドポイント

### 公開

| メソッド | パス | 説明 |
|---------|------|------|
| GET | `/health` | ヘルスチェック |
| POST | `/auth/signup` | ユーザー登録 |
| POST | `/auth/confirm-signup` | メール確認 |
| POST | `/auth/login` | ログイン |
| POST | `/auth/forgot-password` | パスワードリセット要求 |
| POST | `/auth/confirm-forgot-password` | パスワードリセット確認 |
| GET | `/auth/oauth/google` | Google OAuth リダイレクト |
| GET | `/auth/oauth/callback` | OAuth コールバック |

### 認証必須 (`Authorization: Bearer <token>`)

| メソッド | パス | 説明 |
|---------|------|------|
| GET | `/api/me` | ユーザー情報取得 |
| GET | `/api/providers` | リンク済みプロバイダ一覧 |
| GET | `/api/link/google` | Google アカウントリンク |
| DELETE | `/api/link/:provider` | プロバイダリンク解除 |

API ドキュメント: https://rikukaInoue.github.io/rellf-auth/

ローカル: `http://localhost:8080/swagger/index.html`

## ローカル開発

### 前提条件

- Go 1.21+
- Docker
- AWS CLI

### floci を使ったローカル開発（推奨）

実際の AWS アカウント不要で開発できます。

```bash
# 1. floci 起動 + Cognito リソース作成 + .env.local 生成
make floci-setup

# 2. ローカルサーバー起動
make dev-local
```

### AWS 直接接続での開発

```bash
# .env を作成して AWS リソースの情報を設定
cp .env.example .env
# .env を編集

# サーバー起動
make dev
```

### 環境変数

| 変数 | 必須 | 説明 |
|------|------|------|
| `AWS_REGION` | Yes | AWS リージョン |
| `AWS_ENDPOINT_URL` | No | カスタムエンドポイント（floci 用） |
| `COGNITO_POOL_ID` | Yes | Cognito User Pool ID |
| `COGNITO_CLIENT_ID` | Yes | Cognito Client ID |
| `COGNITO_CLIENT_SECRET` | Yes | Cognito Client Secret（`ssm:` プレフィックスで SSM 参照可） |
| `COGNITO_DOMAIN` | Yes | Cognito ドメイン |
| `OAUTH_CALLBACK_URL` | Yes | OAuth コールバック URL |

`COGNITO_CLIENT_SECRET=ssm:/rellf-auth/cognito-client-secret` のように設定すると、起動時に SSM Parameter Store から値を取得します。

## テスト

floci に対する結合テストです。モックは使用しません。

```bash
# floci 起動 + テスト実行（一発）
make test

# floci が既に起動済みの場合
source .env.local && go test -tags integration -v -count=1 ./...
```

## ビルド・デプロイ

```bash
# Lambda 用バイナリビルド
make build

# デプロイ用 zip 作成
make zip

# Terraform デプロイ
cd terraform
cp terraform.tfvars.example terraform.tfvars
# terraform.tfvars を編集
terraform init
terraform apply
```

### Terraform に必要な変数

| 変数 | 説明 |
|------|------|
| `cognito_domain_prefix` | Cognito ドメインのプレフィックス |
| `google_client_id` | Google OAuth クライアント ID |
| `google_client_secret` | Google OAuth クライアントシークレット |

## その他

```bash
make fmt        # コードフォーマット
make vet        # 静的解析
make swagger    # Swagger ドキュメント再生成
make tidy       # go mod tidy
```

lefthook が設定済みで、コミット時に Swagger ドキュメントが自動再生成されます。
