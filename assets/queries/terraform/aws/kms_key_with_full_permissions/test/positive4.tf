resource "aws_kms_key" "multi_statement" {
  description             = "KMS multi-statement"
  deletion_window_in_days = 7

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Safe",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": ["kms:Encrypt"],
      "Resource": "*"
    },
    {
      "Sid": "Vulnerable",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["kms:*"],
      "Resource": "*"
    }
  ]
}
POLICY
}
