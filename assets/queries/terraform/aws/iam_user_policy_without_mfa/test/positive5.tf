resource "aws_iam_user_policy" "jsonencoded" {
  name = "test-jsonencoded"
  user = aws_iam_user.lb.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::111122223333:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}
