resource "aws_iam_role_policy" "jsonencoded" {
  name = "jsonencoded"
  role = aws_iam_role.example.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

data "aws_iam_policy_document" "multi_statement" {
  statement {
    sid    = "Safe"
    effect = "Allow"
    actions = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example-bucket/*"]
  }
  statement {
    sid    = "Vulnerable"
    effect = "Allow"
    actions = ["*"]
    resources = ["*"]
  }
}
