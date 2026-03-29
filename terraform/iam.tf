data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.project_name}-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Project = var.project_name
  }
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "cognito_access" {
  statement {
    actions = [
      "cognito-idp:ListUsers",
      "cognito-idp:AdminGetUser",
      "cognito-idp:AdminLinkProviderForUser",
      "cognito-idp:AdminDisableProviderForUser",
    ]
    resources = [aws_cognito_user_pool.main.arn]
  }
}

resource "aws_iam_policy" "cognito_access" {
  name   = "${var.project_name}-cognito-access"
  policy = data.aws_iam_policy_document.cognito_access.json
}

resource "aws_iam_role_policy_attachment" "cognito_access" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.cognito_access.arn
}

# Pre Sign-up trigger Lambda role
resource "aws_iam_role" "presignup" {
  name               = "${var.project_name}-presignup-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Project = var.project_name
  }
}

resource "aws_iam_role_policy_attachment" "presignup_basic" {
  role       = aws_iam_role.presignup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "presignup_cognito" {
  statement {
    actions = [
      "cognito-idp:ListUsers",
      "cognito-idp:AdminLinkProviderForUser",
    ]
    resources = [aws_cognito_user_pool.main.arn]
  }
}

resource "aws_iam_policy" "presignup_cognito" {
  name   = "${var.project_name}-presignup-cognito"
  policy = data.aws_iam_policy_document.presignup_cognito.json
}

resource "aws_iam_role_policy_attachment" "presignup_cognito" {
  role       = aws_iam_role.presignup.name
  policy_arn = aws_iam_policy.presignup_cognito.arn
}
