provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_user_policy" "multi_statement" {
  name = "multi-statement-policy"
  user = aws_iam_user.positive3.name

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "${aws_iam_user.positive3.arn}",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "${aws_iam_user.positive3.arn}"
    }
  ]
}
EOF
}
