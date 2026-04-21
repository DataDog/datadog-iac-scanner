resource "aws_iam_role" "jsonencoded" {
  name = "jsonencoded-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"
        }
        Effect = "Allow"
      }
    ]
  })
}
