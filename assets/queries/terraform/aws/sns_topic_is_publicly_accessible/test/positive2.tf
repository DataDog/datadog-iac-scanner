resource "aws_sns_topic_policy" "positive2" {
  arn = aws_sns_topic.example.arn

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPublicAccess",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "SNS:Publish",
      "Resource": "arn:aws:sns:us-east-1:123456789012:example"
    }
  ]
}
EOF
}
