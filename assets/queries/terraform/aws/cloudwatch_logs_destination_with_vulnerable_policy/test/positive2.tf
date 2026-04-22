resource "aws_cloudwatch_log_destination_policy" "multi_statement" {
  destination_name = aws_cloudwatch_log_destination.example.name

  access_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Safe",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": ["logs:PutSubscriptionFilter"]
    },
    {
      "Sid": "Vulnerable",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["logs:*"]
    }
  ]
}
POLICY
}
