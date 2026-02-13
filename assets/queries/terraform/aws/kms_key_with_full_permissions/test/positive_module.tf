module "kms_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "1.3.0"

  description             = "KMS key 1"
  deletion_window_in_days = 7

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Id": "key-default-1",
  "Statement": [
    {
      "Sid": "Allow administration of the key",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::646842065146:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}
EOF
}