resource "aws_iam_role" "multi_statement" {
  name = "test_multi"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Safe",
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole",
      "Resource": "*"
    },
    {
      "Sid": "Vulnerable",
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role" "jsonencoded" {
  name = "test_jsonencoded"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "JsonEncodedVulnerable"
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "*"
        Resource  = "*"
      }
    ]
  })
}
