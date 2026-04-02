# Cognito API リファレンス

rellf-auth が使用する全 Cognito API の詳細。各 API について、ユースケース・リクエスト・レスポンス・エラーケースを記載。

## Service interface（ユーザー向け操作）

### SignUp

新規ユーザー登録。

```
Cognito API: SignUp
```

```go
Input: &cip.SignUpInput{
    ClientId:   "client-id",
    Username:   "user@example.com",
    Password:   "Password123!",
    SecretHash: HMAC-SHA256(username + clientId, clientSecret),
    UserAttributes: [
        {Name: "email", Value: "user@example.com"},
    ],
}

Output: &cip.SignUpOutput{
    UserConfirmed: false,     // メール確認前は false
    UserSub:       "uuid",    // 払い出された Cognito UUID
}
```

**エラー:**
- `UsernameExistsException` — メールアドレスが既に登録済み
- `InvalidPasswordException` — パスワードポリシー違反

**ドメイン遷移:** → `PendingUser` 作成

---

### ConfirmSignUp

メール確認コードによるアカウント確認。

```
Cognito API: ConfirmSignUp
```

```go
Input: &cip.ConfirmSignUpInput{
    ClientId:         "client-id",
    Username:         "user@example.com",
    ConfirmationCode: "123456",
    SecretHash:       HMAC-SHA256(...),
}
```

**エラー:**
- `CodeMismatchException` — 確認コードが不正
- `ExpiredCodeException` — 確認コードの有効期限切れ

**ドメイン遷移:** `PendingUser` → `ActiveUser`

---

### InitiateAuth (Login)

パスワード認証。JWT トークンセットを返す。

```
Cognito API: InitiateAuth
AuthFlow: USER_PASSWORD_AUTH
```

```go
Input: &cip.InitiateAuthInput{
    AuthFlow: "USER_PASSWORD_AUTH",
    ClientId: "client-id",
    AuthParameters: {
        "USERNAME":    "user@example.com",
        "PASSWORD":    "Password123!",
        "SECRET_HASH": HMAC-SHA256(...),
    },
}

Output: &cip.InitiateAuthOutput{
    AuthenticationResult: {
        AccessToken:  "eyJhbG...",     // API アクセス用
        IdToken:      "eyJhbG...",     // ユーザー情報 (sub, email, groups)
        RefreshToken: "eyJjdH...",     // トークン更新用
        ExpiresIn:    3600,            // 秒
        TokenType:    "Bearer",
    },
}
```

**IdToken の中身（JWT デコード後）:**
```json
{
  "sub": "cognito-uuid",
  "email": "user@example.com",
  "email_verified": true,
  "cognito:groups": ["admin", "lawyer"],
  "token_use": "id",
  "aud": "client-id",
  "iss": "https://cognito-idp.ap-northeast-1.amazonaws.com/pool-id"
}
```

**エラー:**
- `NotAuthorizedException` — パスワードが不正
- `UserNotFoundException` — ユーザーが存在しない
- `UserNotConfirmedException` — メール未確認

**ドメイン操作:** `ValidateLoginState()` で `ActiveUser` のみ許可 → `RecordLogin()`

---

### ForgotPassword

パスワードリセットコードの送信。

```
Cognito API: ForgotPassword
```

```go
Input: &cip.ForgotPasswordInput{
    ClientId:   "client-id",
    Username:   "user@example.com",
    SecretHash: HMAC-SHA256(...),
}
```

確認コードがメールで送信される。

**ドメイン操作:** `Credential.PasswordReset()`

---

### ConfirmForgotPassword

確認コードと新パスワードでリセット完了。

```
Cognito API: ConfirmForgotPassword
```

```go
Input: &cip.ConfirmForgotPasswordInput{
    ClientId:         "client-id",
    Username:         "user@example.com",
    ConfirmationCode: "123456",
    Password:         "NewPassword123!",
    SecretHash:       HMAC-SHA256(...),
}
```

**ドメイン操作:** `Credential.PasswordConfirmed()`

---

## AdminService interface（管理操作）

### AdminGetUser

ユーザー詳細の取得。

```
Cognito API: AdminGetUser
```

```go
Input: &cip.AdminGetUserInput{
    UserPoolId: "pool-id",
    Username:   "cognito-uuid or email",
}

Output: &cip.AdminGetUserOutput{
    Username:             "cognito-uuid",
    UserStatus:           "CONFIRMED",     // UNCONFIRMED | CONFIRMED | FORCE_CHANGE_PASSWORD
    Enabled:              true,
    UserCreateDate:       time.Time,
    UserLastModifiedDate: time.Time,
    UserAttributes: [
        {Name: "email",          Value: "user@example.com"},
        {Name: "email_verified", Value: "true"},
        {Name: "sub",            Value: "cognito-uuid"},
        {Name: "identities",     Value: "[{\"providerName\":\"Google\",\"userId\":\"12345\",...}]"},
    ],
}
```

**ドメインマッピング:**
- `UserStatus == "UNCONFIRMED"` → `PendingUser`
- `UserStatus == "CONFIRMED" && Enabled == true` → `ActiveUser`
- `Enabled == false` → `SuspendedUser`

---

### ListUsers

ユーザー一覧の取得（フィルタ・ページネーション対応）。

```
Cognito API: ListUsers
```

```go
Input: &cip.ListUsersInput{
    UserPoolId:      "pool-id",
    Limit:           20,
    Filter:          "email ^= \"search\"",    // プレフィックス検索
    PaginationToken: "token-from-previous",    // 次ページ
}

Output: &cip.ListUsersOutput{
    Users: [{
        Username:   "cognito-uuid",
        Attributes: [{Name: "email", Value: "..."}],
        UserStatus: "CONFIRMED",
        Enabled:    true,
        UserCreateDate:       time.Time,
        UserLastModifiedDate: time.Time,
    }, ...],
    PaginationToken: "next-page-token",
}
```

**フィルタ構文:**
- `email ^= "prefix"` — メールアドレス前方一致
- `status = "CONFIRMED"` — ステータスで絞り込み

---

### AdminCreateUser

管理者によるユーザー作成。仮パスワード付き。

```
Cognito API: AdminCreateUser
```

```go
Input: &cip.AdminCreateUserInput{
    UserPoolId:        "pool-id",
    Username:          "user@example.com",
    TemporaryPassword: "TempPass123!",
    UserAttributes: [
        {Name: "email",          Value: "user@example.com"},
        {Name: "email_verified", Value: "true"},
    ],
}

Output: &cip.AdminCreateUserOutput{
    User: {
        Username:   "cognito-uuid",
        UserStatus: "FORCE_CHANGE_PASSWORD",
        Enabled:    true,
        ...
    },
}
```

作成されたユーザーは初回ログイン時にパスワード変更が必要。

**ドメイン遷移:** → `PendingUser` 作成

---

### AdminConfirmSignUp

管理者によるアカウント強制確認。確認コード不要。

```
Cognito API: AdminConfirmSignUp
```

```go
Input: &cip.AdminConfirmSignUpInput{
    UserPoolId: "pool-id",
    Username:   "cognito-uuid",
}
```

**ドメイン遷移:** `PendingUser` → `ActiveUser`

---

### AdminDisableUser

ユーザーの一時停止。ログイン不可になる。

```
Cognito API: AdminDisableUser
```

```go
Input: &cip.AdminDisableUserInput{
    UserPoolId: "pool-id",
    Username:   "cognito-uuid",
}
```

停止後、`AdminGetUser` で `Enabled: false` になる。既存のトークンは有効期限まで使える（即時無効化にはトークン取り消しが別途必要）。

**ドメイン遷移:** `ActiveUser` → `SuspendedUser`

---

### AdminEnableUser

一時停止の解除。

```
Cognito API: AdminEnableUser
```

```go
Input: &cip.AdminEnableUserInput{
    UserPoolId: "pool-id",
    Username:   "cognito-uuid",
}
```

**ドメイン遷移:** `SuspendedUser` → `ActiveUser`

---

### AdminDeleteUser

ユーザーの永久削除。復元不可。

```
Cognito API: AdminDeleteUser
```

```go
Input: &cip.AdminDeleteUserInput{
    UserPoolId: "pool-id",
    Username:   "cognito-uuid",
}
```

**ドメイン遷移:** `ActiveUser/SuspendedUser` → `DeletedUser`

---

### AdminResetUserPassword

パスワードリセットの管理者実行。確認コードがメールで送信される。

```
Cognito API: AdminResetUserPassword
```

```go
Input: &cip.AdminResetUserPasswordInput{
    UserPoolId: "pool-id",
    Username:   "cognito-uuid",
}
```

**ドメイン操作:** `Credential.PasswordReset()`

---

### AdminLinkProviderForUser

外部 IdP のアカウントを Cognito ユーザーにリンク。

```
Cognito API: AdminLinkProviderForUser
```

```go
Input: &cip.AdminLinkProviderForUserInput{
    UserPoolId: "pool-id",
    DestinationUser: {
        ProviderName:           "Cognito",
        ProviderAttributeValue: "cognito-uuid",    // リンク先
    },
    SourceUser: {
        ProviderName:           "Google",           // or "openid2-auid"
        ProviderAttributeName:  "Cognito_Subject",
        ProviderAttributeValue: "external-user-id", // 外部IDのユーザーID
    },
}
```

リンク後、`AdminGetUser` の `identities` 属性に外部プロバイダー情報が追加される:
```json
[{
  "providerName": "Google",
  "userId": "12345",
  "providerType": "Google",
  "dateCreated": "1774971408761",
  "primary": "false"
}]
```

---

### AdminDisableProviderForUser

外部 IdP のリンクを解除。

```
Cognito API: AdminDisableProviderForUser
```

```go
Input: &cip.AdminDisableProviderForUserInput{
    UserPoolId: "pool-id",
    User: {
        ProviderName:           "Google",
        ProviderAttributeName:  "Cognito_Subject",
        ProviderAttributeValue: "external-user-id",
    },
}
```

---

## SecretHash の計算

Cognito のクライアントシークレットが設定されている場合、全 API リクエストに `SecretHash` が必要。

```go
func computeSecretHash(username, clientID, clientSecret string) string {
    mac := hmac.New(sha256.New, []byte(clientSecret))
    mac.Write([]byte(username + clientID))
    return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
```

`USERNAME + CLIENT_ID` を `CLIENT_SECRET` で HMAC-SHA256 し、Base64 エンコード。

## Cognito のステータスとドメインモデルの対応

```
Cognito                              Domain
──────────────────                   ──────────────
UserStatus: UNCONFIRMED              PendingUser
UserStatus: CONFIRMED, Enabled: true ActiveUser
UserStatus: CONFIRMED, Enabled: false SuspendedUser
(削除済み — 存在しない)                DeletedUser
UserStatus: FORCE_CHANGE_PASSWORD    PendingUser (初回パスワード変更待ち)
```
