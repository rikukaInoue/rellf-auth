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
  default     = ["http://localhost:3000/auth/oauth/callback"]
}

variable "oauth_logout_urls" {
  description = "Allowed logout URLs"
  type        = list(string)
  default     = ["http://localhost:3000"]
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
