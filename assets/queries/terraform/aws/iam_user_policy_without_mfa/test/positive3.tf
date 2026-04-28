resource "aws_iam_user_policy" "wildcard_principal" {
  name = "test-wildcard"
  user = aws_iam_user.lb.name

  policy = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
     {
       "Effect": "Allow",
       "Principal": "*",
       "Action": "sts:AssumeRole"
     }
   ]
}
EOF
}
