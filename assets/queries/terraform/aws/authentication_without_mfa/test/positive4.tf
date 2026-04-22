provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_user_policy" "jsonencoded" {
  name = "jsonencoded-policy"
  user = aws_iam_user.positive4.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_user.positive4.arn
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}
