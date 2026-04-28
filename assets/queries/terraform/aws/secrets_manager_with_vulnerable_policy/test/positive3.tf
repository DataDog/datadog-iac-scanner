resource "aws_secretsmanager_secret_policy" "jsonencoded" {
  secret_arn = aws_secretsmanager_secret.example.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "JsonEncodedVulnerable"
        Effect    = "Allow"
        Principal = "*"
        Action    = "secretsmanager:*"
      }
    ]
  })
}
