resource "aws_iam_role" "multi_statement" {
  name = "multi_statement"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SafeWithMFA",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": {"aws:MultiFactorAuthPresent": "true"}
      }
    },
    {
      "Sid": "VulnerableCrossAccountWithoutMFA",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role" "jsonencoded" {
  name = "jsonencoded"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "JsonEncodedVulnerable"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::333333333333:root" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}
