//  Role whose assume-role policy grants trust to every AWS service.
resource "aws_iam_role" "service_wildcard" {
  name = "service-wildcard-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "*"
      },
      "Effect": "Allow",
      "Sid": "AllowAnyService"
    }
  ]
}
EOF
}
