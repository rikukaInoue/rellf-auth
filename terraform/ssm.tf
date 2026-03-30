resource "aws_ssm_parameter" "cognito_client_secret" {
  name  = "/${var.project_name}/cognito-client-secret"
  type  = "SecureString"
  value = aws_cognito_user_pool_client.main.client_secret

  tags = {
    Project = var.project_name
  }
}

resource "aws_ssm_parameter" "google_client_secret" {
  name  = "/${var.project_name}/google-client-secret"
  type  = "SecureString"
  value = var.google_client_secret

  tags = {
    Project = var.project_name
  }
}

resource "aws_ssm_parameter" "oidc_signing_key" {
  name  = "/${var.project_name}/oidc-signing-key"
  type  = "SecureString"
  value = var.oidc_signing_key

  tags = {
    Project = var.project_name
  }
}

resource "aws_ssm_parameter" "oidc_auth_code_key" {
  name  = "/${var.project_name}/oidc-auth-code-key"
  type  = "SecureString"
  value = var.oidc_auth_code_key

  tags = {
    Project = var.project_name
  }
}
