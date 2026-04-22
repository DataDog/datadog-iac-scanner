resource "aws_cloudwatch_log_destination_policy" "jsonencoded" {
  destination_name = aws_cloudwatch_log_destination.example.name

  access_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "JsonEncodedVulnerable"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["logs:*"]
      }
    ]
  })
}
