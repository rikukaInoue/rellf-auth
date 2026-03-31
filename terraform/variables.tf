variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-northeast-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "rellf-auth"
}

variable "cognito_domain_prefix" {
  description = "Cognito User Pool domain prefix"
  type        = string
}

variable "google_client_id" {
  description = "Google OAuth client ID"
  type        = string
}

variable "google_client_secret" {
  description = "Google OAuth client secret"
  type        = string
  sensitive   = true
}

variable "oauth_callback_urls" {
  description = "Allowed OAuth callback URLs"
  type        = list(string)
  default     = [
    "http://localhost:3000/auth/oauth/callback",
    "https://auth.rikuka.dev/auth/oauth/callback",
  ]
}

variable "oauth_logout_urls" {
  description = "Allowed logout URLs"
  type        = list(string)
  default     = [
    "http://localhost:3000",
    "https://auth.rikuka.dev",
  ]
}

variable "lambda_zip_path" {
  description = "Path to the API Lambda deployment zip file"
  type        = string
  default     = "../function.zip"
}

variable "presignup_zip_path" {
  description = "Path to the Pre Sign-up trigger Lambda deployment zip file"
  type        = string
  default     = "../presignup.zip"
}

# OIDC Provider

variable "oidc_signing_key" {
  description = "RSA private key (PEM) for signing OIDC tokens"
  type        = string
  sensitive   = true
}

variable "oidc_key_id" {
  description = "Key ID (kid) for the OIDC signing key"
  type        = string
}

variable "oidc_auth_code_key" {
  description = "AES-256 key (hex) for encrypting authorization codes"
  type        = string
  sensitive   = true
}

variable "oidc_clients" {
  description = "OIDC client definitions (format: client_id:secret:type:redirect_uris)"
  type        = string
}

# Domain

variable "domain_name" {
  description = "Custom domain name for the API (e.g. auth.rikuka.dev)"
  type        = string
  default     = "auth.rikuka.dev"
}

variable "domain_zone" {
  description = "Route53 hosted zone name"
  type        = string
  default     = "rikuka.dev"
}
