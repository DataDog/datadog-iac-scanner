resource "aws_elasticsearch_domain_policy" "multi_statement" {
  domain_name = aws_elasticsearch_domain.example.domain_name

  access_policies = <<POLICIES
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Safe",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": ["es:DescribeDomain"]
    },
    {
      "Sid": "Vulnerable",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["es:*"]
    }
  ]
}
POLICIES
}
