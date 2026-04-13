resource "aws_sns_topic" "multi" {
  name = "multi-statement-topic"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSpecific",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": "SNS:Publish",
      "Resource": "arn:aws:sns:us-east-1:123456789012:multi-statement-topic"
    },
    {
      "Sid": "AllowAnyone",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "SNS:Publish",
      "Resource": "arn:aws:sns:us-east-1:123456789012:multi-statement-topic"
    }
  ]
}
EOF
}
