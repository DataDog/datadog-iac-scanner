resource "aws_elasticsearch_domain_policy" "jsonencoded" {
  domain_name = aws_elasticsearch_domain.example.domain_name

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "JsonEncodedVulnerable"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["es:*"]
      }
    ]
  })
}
