resource "aws_sqs_queue" "multi" {
  name = "multi-statement-queue"
}

resource "aws_sqs_queue_policy" "multi" {
  queue_url = aws_sqs_queue.multi.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Id": "MultiStatementPolicy",
  "Statement": [
    {
      "Sid": "AllowSpecific",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:us-east-1:123456789012:multi-statement-queue"
    },
    {
      "Sid": "AllowAnyone",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:us-east-1:123456789012:multi-statement-queue"
    }
  ]
}
EOF
}
