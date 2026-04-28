resource "aws_iam_role_policy" "multi_statement" {
  name = "multi_statement"
  role = aws_iam_role.test_role.id

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "Safe",
        "Effect": "Allow",
        "Action": "iam:passrole",
        "Resource": "arn:aws:iam::123456789012:role/example-role"
      },
      {
        "Sid": "Vulnerable",
        "Effect": "Allow",
        "Action": "iam:passrole",
        "Resource": "*"
      }
    ]
  }
  EOF
}

resource "aws_iam_role_policy" "jsonencoded" {
  name = "jsonencoded"
  role = aws_iam_role.test_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "JsonEncodedVulnerable"
        Effect   = "Allow"
        Action   = "iam:passrole"
        Resource = "*"
      }
    ]
  })
}
