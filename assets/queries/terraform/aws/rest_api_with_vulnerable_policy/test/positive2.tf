resource "aws_api_gateway_rest_api_policy" "multi_statement" {
  rest_api_id = aws_api_gateway_rest_api.example.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Safe",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": ["execute-api:Invoke"],
      "Resource": "${aws_api_gateway_rest_api.example.arn}"
    },
    {
      "Sid": "Vulnerable",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "execute-api:*",
      "Resource": "${aws_api_gateway_rest_api.example.arn}"
    }
  ]
}
EOF
}
