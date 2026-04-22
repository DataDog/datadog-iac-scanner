resource "aws_iam_policy" "multi_statement" {
  name = "multi_statement"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Safe"
        Effect = "Allow"
        Action = "lambda:InvokeFunction"
        Resource = [
          "arn:aws:lambda:*:*:function:safe-function",
          "arn:aws:lambda:*:*:function:safe-function:*"
        ]
      },
      {
        Sid      = "Vulnerable"
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = "arn:aws:lambda:*:*:function:vulnerable-function"
      }
    ]
  })
}
