resource "aws_sns_topic_policy" "multi_statement" {
  arn = aws_sns_topic.example.arn

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Safe",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": "SNS:Publish",
      "Resource": "arn:aws:sns:us-east-1:123456789012:example"
    },
    {
      "Sid": "Vulnerable",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "NotAction": "SNS:DeleteTopic",
      "Resource": "arn:aws:sns:us-east-1:123456789012:example"
    }
  ]
}
POLICY
}

resource "aws_sns_topic_policy" "jsonencoded" {
  arn = aws_sns_topic.example.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "JsonEncodedVulnerable"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:root" }
        NotAction = "SNS:DeleteTopic"
        Resource  = "arn:aws:sns:us-east-1:123456789012:example"
      }
    ]
  })
}
