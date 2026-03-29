resource "aws_lambda_function" "main" {
  function_name = var.project_name
  role          = aws_iam_role.lambda.arn
  handler       = "bootstrap"
  runtime       = "provided.al2023"
  architectures = ["arm64"]
  timeout       = 30
  memory_size   = 128

  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)

  environment {
    variables = {
      AWS_REGION_NAME        = var.aws_region
      COGNITO_POOL_ID        = aws_cognito_user_pool.main.id
      COGNITO_CLIENT_ID      = aws_cognito_user_pool_client.main.id
      COGNITO_CLIENT_SECRET  = aws_cognito_user_pool_client.main.client_secret
      COGNITO_DOMAIN         = "${var.cognito_domain_prefix}.auth.${var.aws_region}.amazoncognito.com"
      OAUTH_CALLBACK_URL     = "${aws_apigatewayv2_stage.main.invoke_url}/auth/oauth/callback"
    }
  }

  tags = {
    Project = var.project_name
  }
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.main.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

# Pre Sign-up trigger Lambda
resource "aws_lambda_function" "presignup" {
  function_name = "${var.project_name}-presignup"
  role          = aws_iam_role.presignup.arn
  handler       = "bootstrap"
  runtime       = "provided.al2023"
  architectures = ["arm64"]
  timeout       = 5
  memory_size   = 128

  filename         = var.presignup_zip_path
  source_code_hash = filebase64sha256(var.presignup_zip_path)

  tags = {
    Project = var.project_name
  }
}

resource "aws_lambda_permission" "cognito_presignup" {
  statement_id  = "AllowCognitoInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.presignup.function_name
  principal     = "cognito-idp.amazonaws.com"
  source_arn    = aws_cognito_user_pool.main.arn
}
