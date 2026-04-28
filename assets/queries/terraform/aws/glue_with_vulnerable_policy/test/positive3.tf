resource "aws_glue_resource_policy" "jsonencoded" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "JsonEncodedVulnerable"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["glue:*"]
      }
    ]
  })
}
