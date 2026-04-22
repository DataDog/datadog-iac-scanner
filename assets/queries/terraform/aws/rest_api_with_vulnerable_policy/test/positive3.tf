resource "aws_api_gateway_rest_api_policy" "jsonencoded" {
  rest_api_id = aws_api_gateway_rest_api.example.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "JsonEncodedVulnerable"
        Effect    = "Allow"
        Principal = "*"
        Action    = "execute-api:*"
        Resource  = aws_api_gateway_rest_api.example.arn
      }
    ]
  })
}
