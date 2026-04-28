resource "aws_iam_policy" "jsonencoded" {
  name = "jsonencoded"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "JsonEncodedVulnerable"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
