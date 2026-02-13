module "sqs_queue_policy" {
  source  = "terraform-aws-modules/sqs/aws"
  version = "~> 2.0"

  name = "example"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "sqspolicy",
  "Statement": [
    {
      "Sid": "First",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:eu-west-1:135367859851:queue1",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "arn:aws:events:eu-west-1:135367859851:rule/RunDailyTask"
        }
      }
    }
  ]
}
POLICY

  # ... other configuration ...
}