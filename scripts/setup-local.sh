#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
EP="http://localhost:9229"

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=ap-northeast-1

echo "==> Creating Cognito User Pool..."
POOL_ID=$(aws cognito-idp create-user-pool \
  --pool-name rellf-auth-local \
  --alias-attributes email \
  --auto-verified-attributes email \
  --policies 'PasswordPolicy={MinimumLength=8,RequireUppercase=true,RequireLowercase=true,RequireNumbers=true,RequireSymbols=true}' \
  --endpoint-url "$EP" \
  --query 'UserPool.Id' --output text)
echo "    Pool ID: $POOL_ID"

echo "==> Creating User Pool Client..."
CLIENT_ID=$(aws cognito-idp create-user-pool-client \
  --user-pool-id "$POOL_ID" \
  --client-name rellf-auth-local-client \
  --explicit-auth-flows ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH \
  --endpoint-url "$EP" \
  --query 'UserPoolClient.ClientId' --output text)
echo "    Client ID: $CLIENT_ID"

echo "==> Writing .env.local..."
cat > "$PROJECT_DIR/.env.local" <<ENVEOF
AWS_REGION=ap-northeast-1
AWS_ENDPOINT_URL=$EP
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
COGNITO_POOL_ID=$POOL_ID
COGNITO_CLIENT_ID=$CLIENT_ID
COGNITO_CLIENT_SECRET=
COGNITO_DOMAIN=localhost
OAUTH_CALLBACK_URL=http://localhost:8080/auth/oauth/callback
OIDC_ISSUER=http://localhost:8080
OIDC_SIGNING_KEY=auto
OIDC_KEY_ID=local-key-1
OIDC_AUTH_CODE_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
OIDC_CLIENTS=test-client::public:http://localhost:3000/callback,meeting-companion::public:http://localhost:3456/callback
ENVEOF

echo "==> Creating groups..."
for g in admin lawyer zeirishi site:editor site:viewer; do
  aws cognito-idp create-group --user-pool-id "$POOL_ID" --group-name "$g" --endpoint-url "$EP" > /dev/null 2>&1 || true
  echo "    Group: $g"
done

echo "==> Creating users..."

create_user() {
  local email="$1" password="$2" groups="$3"

  aws cognito-idp admin-create-user \
    --user-pool-id "$POOL_ID" --username "$email" \
    --temporary-password 'TempPass1!' \
    --user-attributes Name=email,Value="$email" Name=email_verified,Value=true \
    --message-action SUPPRESS \
    --endpoint-url "$EP" > /dev/null 2>&1

  aws cognito-idp admin-set-user-password \
    --user-pool-id "$POOL_ID" --username "$email" \
    --password "$password" --permanent \
    --endpoint-url "$EP" > /dev/null 2>&1

  for g in $groups; do
    aws cognito-idp admin-add-user-to-group \
      --user-pool-id "$POOL_ID" --username "$email" \
      --group-name "$g" --endpoint-url "$EP" > /dev/null 2>&1 || true
  done

  echo "    User: $email (groups: ${groups:-none})"
}

create_user "admin@example.com"    'Admin1234!'    "admin"
create_user "lawyer@example.com"   'Lawyer1234!'   "lawyer"
create_user "zeirishi@example.com" 'Zeirishi1234!' "zeirishi"
create_user "editor@example.com"   'Editor1234!'   "site:editor"
create_user "viewer@example.com"   'Viewer1234!'   "site:viewer"
create_user "multi@example.com"    'Multi1234!'    "lawyer site:editor"

echo ""
echo "==> Setup complete!"
echo "    Run: make dev-local"
echo "    Admin: http://localhost:8080/admin/login (admin@example.com / Admin1234!)"
