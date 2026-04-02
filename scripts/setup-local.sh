#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENDPOINT="http://localhost:4566"
REGION="ap-northeast-1"

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=$REGION

echo "==> Creating Cognito User Pool..."
POOL_ID=$(aws cognito-idp create-user-pool \
  --pool-name rellf-auth-local \
  --alias-attributes email \
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
cat > "$PROJECT_DIR/.env.local" <<EOF
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

# --- Load fixtures ---

GROUPS_FILE="$PROJECT_DIR/fixtures/groups.json"
USERS_FILE="$PROJECT_DIR/fixtures/users.json"

echo "==> Creating groups from fixtures..."
for group in $(python3 -c "import json; [print(g) for g in json.load(open('$GROUPS_FILE'))]"); do
  aws cognito-idp create-group \
    --user-pool-id "$POOL_ID" \
    --group-name "$group" \
    --endpoint-url "$ENDPOINT" > /dev/null 2>&1 || true
  echo "    Group: $group"
done

echo "==> Creating users from fixtures..."
USER_COUNT=$(python3 -c "import json; print(len(json.load(open('$USERS_FILE'))))")
for i in $(seq 0 $((USER_COUNT - 1))); do
  EMAIL=$(python3 -c "import json; u=json.load(open('$USERS_FILE'))[$i]; print(u.get('email', ''))")
  USERNAME=$(python3 -c "import json; u=json.load(open('$USERS_FILE'))[$i]; print(u.get('username', u.get('email', '')))")
  PASSWORD=$(python3 -c "import json; print(json.load(open('$USERS_FILE'))[$i]['password'])")
  CONFIRMED=$(python3 -c "import json; print(json.load(open('$USERS_FILE'))[$i]['confirmed'])")
  GROUPS=$(python3 -c "import json; print(' '.join(json.load(open('$USERS_FILE'))[$i]['groups']))")

  # Sign up
  if [ -n "$EMAIL" ]; then
    aws cognito-idp sign-up \
      --client-id "$CLIENT_ID" \
      --username "$USERNAME" \
      --password "$PASSWORD" \
      --user-attributes Name=email,Value="$EMAIL" \
      --endpoint-url "$ENDPOINT" > /dev/null 2>&1 || true
  else
    aws cognito-idp sign-up \
      --client-id "$CLIENT_ID" \
      --username "$USERNAME" \
      --password "$PASSWORD" \
      --endpoint-url "$ENDPOINT" > /dev/null 2>&1 || true
  fi

  # Confirm if needed
  if [ "$CONFIRMED" = "True" ]; then
    aws cognito-idp admin-confirm-sign-up \
      --user-pool-id "$POOL_ID" \
      --username "$USERNAME" \
      --endpoint-url "$ENDPOINT" > /dev/null 2>&1 || \
    aws cognito-idp confirm-sign-up \
      --client-id "$CLIENT_ID" \
      --username "$USERNAME" \
      --confirmation-code 000000 \
      --endpoint-url "$ENDPOINT" > /dev/null 2>&1 || true
  fi

  # Add to groups
  for group in $GROUPS; do
    aws cognito-idp admin-add-user-to-group \
      --user-pool-id "$POOL_ID" \
      --username "$USERNAME" \
      --group-name "$group" \
      --endpoint-url "$ENDPOINT" > /dev/null 2>&1 || true
  done

  echo "    User: $USERNAME (groups: $GROUPS) $([ "$CONFIRMED" = "True" ] && echo "[confirmed]" || echo "[pending]")"
done

echo ""
echo "==> Setup complete!"
echo "    Run: make dev-local"
echo "    Admin: http://localhost:8080/admin/login (admin@example.com / Admin1234!)"
