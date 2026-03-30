#!/bin/bash
set -euo pipefail

ENDPOINT="http://localhost:4566"
REGION="ap-northeast-1"

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=$REGION

echo "==> Creating Cognito User Pool..."
POOL_ID=$(aws cognito-idp create-user-pool \
  --pool-name rellf-auth-local \
  --username-attributes email \
  --auto-verified-attributes email \
  --policies 'PasswordPolicy={MinimumLength=8,RequireUppercase=true,RequireLowercase=true,RequireNumbers=true,RequireSymbols=true}' \
  --endpoint-url "$ENDPOINT" \
  --query 'UserPool.Id' \
  --output text)
echo "    Pool ID: $POOL_ID"

echo "==> Creating User Pool Client..."
CLIENT_OUTPUT=$(aws cognito-idp create-user-pool-client \
  --user-pool-id "$POOL_ID" \
  --client-name rellf-auth-local-client \
  --explicit-auth-flows ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH \
  --endpoint-url "$ENDPOINT" \
  --output json)
CLIENT_ID=$(echo "$CLIENT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['UserPoolClient']['ClientId'])")
CLIENT_SECRET="local-dummy-secret"
echo "    Client ID: $CLIENT_ID"

echo "==> Writing .env.local..."
cat > "$(dirname "$0")/../.env.local" <<EOF
AWS_REGION=$REGION
AWS_ENDPOINT_URL=$ENDPOINT
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
COGNITO_POOL_ID=$POOL_ID
COGNITO_CLIENT_ID=$CLIENT_ID
COGNITO_CLIENT_SECRET=$CLIENT_SECRET
COGNITO_DOMAIN=localhost
OAUTH_CALLBACK_URL=http://localhost:8080/auth/oauth/callback
OIDC_ISSUER=http://localhost:8080
OIDC_SIGNING_KEY=auto
OIDC_KEY_ID=local-key-1
OIDC_AUTH_CODE_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
OIDC_CLIENTS=test-client::public:http://localhost:3000/callback
EOF

echo "==> Creating admin group..."
aws cognito-idp create-group \
  --user-pool-id "$POOL_ID" \
  --group-name admin \
  --endpoint-url "$ENDPOINT" > /dev/null 2>&1 || true

echo "==> Creating admin user..."
aws cognito-idp sign-up \
  --client-id "$CLIENT_ID" \
  --username admin@example.com \
  --password "Admin1234!" \
  --user-attributes Name=email,Value=admin@example.com \
  --endpoint-url "$ENDPOINT" > /dev/null 2>&1 || true

aws cognito-idp admin-confirm-sign-up \
  --user-pool-id "$POOL_ID" \
  --username admin@example.com \
  --endpoint-url "$ENDPOINT" > /dev/null 2>&1 || \
aws cognito-idp confirm-sign-up \
  --client-id "$CLIENT_ID" \
  --username admin@example.com \
  --confirmation-code 000000 \
  --endpoint-url "$ENDPOINT" > /dev/null 2>&1 || true

aws cognito-idp admin-add-user-to-group \
  --user-pool-id "$POOL_ID" \
  --username admin@example.com \
  --group-name admin \
  --endpoint-url "$ENDPOINT" > /dev/null 2>&1 || true
echo "    Admin: admin@example.com / Admin1234!"

echo ""
echo "==> Setup complete!"
echo "    Run: make dev-local"
echo "    Admin: http://localhost:8080/admin/login"
