resource "aws_ssoadmin_permission_set_inline_policy" "jsonencoded" {
  instance_arn       = aws_ssoadmin_permission_set.example.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.example.arn

  inline_policy = jsonencode({
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
