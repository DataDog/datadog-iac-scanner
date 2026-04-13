resource "aws_iam_role" "multi" {
  name = "multi-statement-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": "AllowSpecific"
    },
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com",
        "AWS": "*"
      },
      "Effect": "Allow",
      "Sid": "AllowAll"
    }
  ]
}
EOF
}
