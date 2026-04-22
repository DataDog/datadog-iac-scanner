resource "aws_ecr_repository" "aws_wildcard" {
  name = "aws-wildcard-repo"
}

resource "aws_ecr_repository_policy" "aws_wildcard" {
  repository = aws_ecr_repository.aws_wildcard.name

  policy = <<EOF
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Sid": "AllowAnyAccount",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage"
      ]
    }
  ]
}
EOF
}
