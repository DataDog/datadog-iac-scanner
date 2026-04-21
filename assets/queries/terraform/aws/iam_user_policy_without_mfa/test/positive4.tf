resource "aws_iam_user_policy" "multi_statement" {
  name = "test-multi"
  user = aws_iam_user.lb.name

  policy = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
     {
       "Effect": "Allow",
       "Principal": {
         "AWS": "arn:aws:iam::mfa/111122223333:user"
       },
       "Action": "sts:AssumeRole"
     },
     {
       "Effect": "Allow",
       "Principal": {
         "AWS": "arn:aws:iam::111122223333:root"
       },
       "Action": "sts:AssumeRole"
     }
   ]
}
EOF
}
