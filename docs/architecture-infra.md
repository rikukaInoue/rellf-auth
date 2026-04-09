# インフラ構成

## 全体構成図

```mermaid
graph TB
    subgraph "Client"
        Browser["Browser"]
        ReactApp["React App<br/>(vigorment.rikuka.dev)"]
    end

    subgraph "DNS / TLS"
        Route53["Route53<br/>rikuka.dev"]
        ACM["ACM Certificate<br/>auth.rikuka.dev<br/>TLS 1.2+"]
    end

    subgraph "API Layer"
        APIGW["API Gateway v2<br/>HTTP API<br/>Custom Domain: auth.rikuka.dev"]
    end

    subgraph "Compute"
        Lambda["Lambda (arm64)<br/>Go / Gin<br/>128MB / 30s timeout"]
        PreSignup["Lambda (arm64)<br/>PreSignup Trigger<br/>Auto-link accounts"]
    end

    subgraph "Auth / Identity"
        Cognito["Cognito User Pool<br/>Email + Password<br/>Google OAuth"]
        Google["Google OAuth 2.0<br/>Identity Provider"]
        CustomMsg["Lambda (arm64)<br/>CustomMessage Trigger<br/>HTML メールテンプレート"]
    end

    subgraph "Email"
        SES["SES<br/>rikuka.dev (DKIM)<br/>送信元: no-reply@rikuka.dev"]
    end

    subgraph "Secrets"
        SSM["SSM Parameter Store<br/>- Cognito Client Secret<br/>- OIDC Signing Key (RSA)<br/>- Auth Code Key (AES-256)"]
    end

    subgraph "State Management"
        S3["S3<br/>rellf-auth-tfstate<br/>Versioning + Encryption"]
        DynamoDB["DynamoDB<br/>rellf-auth-tflock<br/>State Locking"]
    end

    Browser -->|"HTTPS"| Route53
    ReactApp -->|"HTTPS (CORS)"| Route53
    Route53 -->|"A Record (Alias)"| APIGW
    ACM -.->|"Certificate"| APIGW
    APIGW -->|"AWS_PROXY"| Lambda
    Lambda -->|"SDK"| Cognito
    Lambda -->|"GetParameters"| SSM
    Cognito -->|"PreSignUp Trigger"| PreSignup
    Cognito <-->|"OAuth 2.0"| Google
    PreSignup -->|"AdminLinkProviderForUser"| Cognito
    Cognito -->|"CustomMessage Trigger"| CustomMsg
    Cognito -->|"SendEmail"| SES

    style Lambda fill:#f90,color:#fff
    style PreSignup fill:#f90,color:#fff
    style Cognito fill:#527fff,color:#fff
    style APIGW fill:#a855f7,color:#fff
    style Route53 fill:#146eb4,color:#fff
    style S3 fill:#3b8739,color:#fff
    style DynamoDB fill:#4053d6,color:#fff
    style SSM fill:#dd344c,color:#fff
    style CustomMsg fill:#f90,color:#fff
    style SES fill:#dd344c,color:#fff
```

## Terraform リソース一覧

| リソース | 用途 |
|---------|------|
| `aws_cognito_user_pool.main` | ユーザープール |
| `aws_cognito_user_pool_client.main` | アプリクライアント |
| `aws_cognito_identity_provider.google` | Google OAuth 連携 |
| `aws_lambda_function.main` | API Lambda |
| `aws_lambda_function.presignup` | PreSignUp トリガー |
| `aws_lambda_function.custommessage` | CustomMessage トリガー |
| `aws_apigatewayv2_api.main` | HTTP API |
| `aws_apigatewayv2_domain_name.main` | カスタムドメイン |
| `aws_sesv2_email_identity.main` | SES ドメイン認証 |
| `aws_route53_record.ses_dkim` | DKIM レコード (x3) |
| `aws_acm_certificate.main` | TLS 証明書 |
| `aws_ssm_parameter.*` | シークレット管理 |
| `aws_s3_bucket` / `aws_dynamodb_table` | Terraform state |
